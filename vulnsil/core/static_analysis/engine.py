# vulnsil/core/static_analysis/engine.py
import importlib.util
import json
import logging
import os
import subprocess
import tempfile
from typing import Dict, List, Tuple

from config import settings
from vulnsil.core.static_analysis.compressor import SemanticCompressor

# 动态加载 AST 模块
ast_spec = importlib.util.find_spec("vulnsil.core.static_analysis.ast_analyzer")
if ast_spec and ast_spec.loader:
    ast_module = importlib.util.module_from_spec(ast_spec)
    ast_spec.loader.exec_module(ast_module)
    ASTHeuristicAnalyzer = getattr(ast_module, "ASTHeuristicAnalyzer", None)
else:
    ASTHeuristicAnalyzer = None

logger = logging.getLogger(__name__)


class DualEngineAnalyzer:
    """
    Static Analysis Engine v7.2 (With Smart Fuse & Fallback & Semantic Tags)
    """

    SOURCE_NONE = 0
    SOURCE_AST_FALLBACK = 1
    SOURCE_JOERN_FUSION = 2

    def __init__(self):
        try:
            self.compressor = SemanticCompressor()
        except Exception as e:
            logger.warning(f"Compressor Init Failed: {e}")
            self.compressor = None

        self.ast_engine = ASTHeuristicAnalyzer() if ASTHeuristicAnalyzer else None

        self.script_template = ""
        if os.path.exists(settings.JOERN_SCRIPT_PATH):
            with open(settings.JOERN_SCRIPT_PATH, 'r', encoding='utf-8') as f:
                self.script_template = f.read()
        else:
            logger.critical(f"CRITICAL: Joern script not found at {settings.JOERN_SCRIPT_PATH}")

        self.joern_env = os.environ.copy()
        if settings.JOERN_JAVA_OPTS:
            self.joern_env["JAVA_OPTS"] = settings.JOERN_JAVA_OPTS
            self.joern_env["_JAVA_OPTIONS"] = settings.JOERN_JAVA_OPTIONS

        self.shim_header = """
                        #include <stdio.h>
                        #include <stdlib.h>
                        #include <string.h>
                        #include <stddef.h>
                        #include <stdint.h>
                        #include <limits.h>
                        #include <stdbool.h>
                        #include <sys/types.h>
                        #include <unistd.h>
                        #include <linux/kernel.h>
                        #include <linux/slab.h>

                        typedef unsigned char u8;
                        typedef unsigned short u16;
                        typedef unsigned int u32;
                        typedef unsigned long long u64;
                        typedef signed char s8;
                        typedef signed short s16;
                        typedef signed int s32;
                        typedef signed long long s64;
                        typedef unsigned int __u32;
                        typedef unsigned int __be32;
                        typedef unsigned long long __u64;
                        typedef long long atomic64_t;
                        typedef int atomic_t;

                        #define __user
                        #define __kernel
                        #define __iomem
                        #define __init
                        #define __exit
                        #define __force
                        #define __must_check
                        #define likely(x) (x)
                        #define unlikely(x) (x)
                        #define asmlinkage
                        #define __attribute__(x) 

                        #ifndef NULL
                        #define NULL ((void*)0)
                        #endif
                        \n"""

    def _wrap_code_batch(self, code: str, task_id: int) -> str:
        try:
            code = code.encode('utf-8', 'ignore').decode('utf-8')
        except:
            pass
        if "{" in code and "}" in code:
            return self.shim_header + "\n" + code
        return f"{self.shim_header}\nint task_{task_id}(int argc, char** argv) {{\n{code}\nreturn 0;\n}}"

    def _calculate_python_complexity(self, code: str) -> int:
        if not code: return 1
        keywords = ['if', 'else', 'for', 'while', 'switch', 'case', '&&', '||', '?', 'catch']
        score = 1
        for kw in keywords:
            score += code.count(kw)
        return min(score, 1000)

    def analyze_batch(self, tasks: List[dict]) -> Dict[int, Dict]:
        """
        带【智能熔断】的批量分析接口。
        如果批次分析全军覆没(通常是Parser崩溃)，自动拆解为单任务重试。
        """
        # 1. 尝试作为一个整体批次运行
        results_map = self._analyze_batch_core(tasks)

        # 2. [核心逻辑]：检查是否发生“批次级雪崩”
        # 如果是多文件批次，且 Joern 成功率为 0 (全失败)，说明 C2CPG 可能直接崩溃了
        joern_success_count = sum(1 for r in results_map.values() if r.get('success'))

        if len(tasks) > 1 and joern_success_count == 0:
            logger.warning(
                f"⚠️ Batch crash detected (Size {len(tasks)}). Fuse tripped! Activating Fallback: Retry sequentially.")

            # 3. [降级模式]：拆分为单任务逐个重试
            new_results = {}
            for single_task in tasks:
                # 递归调用：这次列表里只有 1 个任务
                sub_res = self.analyze_batch([single_task])
                new_results.update(sub_res)

            return new_results

        # 4. 执行 AST/Regex 兜底 (对 Joern 失败的任务进行补位)
        self._run_fallback_batch(tasks, results_map, fusion=True)
        return results_map

    def _analyze_batch_core(self, tasks: List[dict]) -> Dict[int, Dict]:
        """
        执行一次具体的 Joern 调用
        """
        results_map = {}
        # 初始化默认失败状态
        for t in tasks:
            results_map[t['id']] = {
                "success": False,
                "has_data_flow": False,
                "complexity": 0,
                "apis": [],
                "source_type": self.SOURCE_NONE
            }

        if not os.path.exists(settings.JOERN_CLI_PATH):
            return results_map

        try:
            with tempfile.TemporaryDirectory(prefix="vuln_batch_", dir=settings.STATIC_TMP_DIR) as work_dir:
                src_dir = os.path.join(work_dir, "src")
                os.makedirs(src_dir, exist_ok=True)

                # 写文件
                self._dump_batch_files(tasks, src_dir)

                cpg_path = os.path.join(work_dir, "cpg.bin")
                res_path = os.path.join(work_dir, "result.json")
                run_sc_path = os.path.join(work_dir, "query.sc")

                # 生成 CPG
                cpg_generated = self._run_cpg_generation(src_dir, cpg_path)

                if cpg_generated:
                    # 运行分析脚本
                    self._prepare_and_run_query(cpg_path, res_path, run_sc_path, work_dir)
                    # 读取结果
                    self._map_results(res_path, results_map)

                    # [Fix 2] Explicit Semantic Tagging for Pipeline Consumption
                    for tid, res in results_map.items():
                        if res.get('success', False):
                            res['analysis_mode'] = 'joern'  # Proven provenance
                        else:
                            res['analysis_mode'] = 'none'  # Placeholder before fallback
                else:
                    # CPG 生成失败，保持 success=False，等待外层熔断
                    pass

        except Exception as e:
            logger.error(f"Static Engine Core Error: {e}")

        return results_map

    def _run_fallback_batch(self, tasks, results_map, fusion=False):
        for t in tasks:
            tid = t['id']
            code = t['code']
            res = results_map[tid]

            if self.ast_engine:
                regex_risk, regex_apis = self.ast_engine.scan(code)

                if fusion:
                    # [Safety] Null Guard
                    existing = set(res.get('apis', []) or [])
                    existing.update(regex_apis)
                    res['apis'] = list(existing)

                    if res['success']:
                        res['source_type'] = self.SOURCE_JOERN_FUSION
                        res['analysis_mode'] = 'hybrid'  # [Fix 2] Semantic Tag
                    else:
                        # [Fix 2] Strict Semantics: Regex != DataFlow
                        res['has_data_flow'] = False
                        if regex_risk: res['_ast_regex_hit'] = True

                        res['source_type'] = self.SOURCE_AST_FALLBACK
                        res['analysis_mode'] = 'ast_fallback'
                else:
                    res['apis'] = regex_apis
                    # [Fix 2] Strict Semantics
                    res['has_data_flow'] = False
                    if regex_risk: res['_ast_regex_hit'] = True

                    res['source_type'] = self.SOURCE_AST_FALLBACK
                    res['analysis_mode'] = 'ast_fallback'

            # [Fix 8] Type Safety Check after Fallback Logic
            if res.get('has_data_flow') is None:
                res['has_data_flow'] = False

            if res.get('complexity', 0) <= 0:
                res['complexity'] = self._calculate_python_complexity(code)

        return results_map

    def _dump_batch_files(self, tasks: List[dict], src_dir: str) -> None:
        for t in tasks:
            tid = t['id']
            code = t['code']
            if self.compressor and len(code) > settings.COMPRESSION_TRIGGER_LEN:
                code = self.compressor.compress(code, settings.MAX_CODE_TOKENS_INPUT)

            fname = f"{tid}.c"
            final = self._wrap_code_batch(code, tid)
            with open(os.path.join(src_dir, fname), "w", encoding="utf-8") as f:
                f.write(final)

    def _run_cpg_generation(self, src_dir: str, cpg_path: str) -> bool:
        cmd = [settings.JOERN_PARSE_PATH, src_dir, "--output", cpg_path]
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                timeout=settings.STATIC_PARSE_TIMEOUT,
                env=self.joern_env,
                check=False
            )
            if os.path.exists(cpg_path) and os.path.getsize(cpg_path) > 100:
                return True
            else:
                return False
        except subprocess.TimeoutExpired:
            logger.error("C2CPG Timeout!")
            return False
        except Exception as e:
            logger.error(f"C2CPG Subprocess Error: {e}")
            return False

    def _prepare_and_run_query(self, cpg_path: str, res_path: str, run_sc_path: str, work_dir: str) -> None:
        abs_cpg = os.path.abspath(cpg_path).replace("\\", "/")
        abs_out = os.path.abspath(res_path).replace("\\", "/")

        script_content = self.script_template.replace("{{CPG_FILE}}", abs_cpg) \
            .replace("{{OUT_FILE}}", abs_out)

        with open(run_sc_path, "w", encoding='utf-8') as f:
            f.write(script_content)

        cmd = [settings.JOERN_CLI_PATH, "--script", run_sc_path]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                timeout=settings.STATIC_QUERY_TIMEOUT,
                cwd=work_dir,
                env=self.joern_env,
                check=False
            )
        except subprocess.TimeoutExpired:
            logger.error("Joern Query Timeout!")
        except Exception as e:
            logger.error(f"Joern Query Error: {e}")

    def _map_results(self, res_path: str, results_map: Dict[int, Dict]) -> None:
        if not os.path.exists(res_path): return
        try:
            with open(res_path, 'r', encoding='utf-8') as f:
                raw_content = f.read().strip()
            if not raw_content: return
            data = json.loads(raw_content)
            if not isinstance(data, list): return

            for item in data:
                if "error" in item: continue
                path_str = item.get("filename", "")
                fname = os.path.basename(path_str)
                if not fname.endswith(".c"): continue

                try:
                    tid = int(fname[:-2])
                    if tid in results_map:
                        r = results_map[tid]
                        r['success'] = True

                        # [Fix 8] Robust Type Conversion & Null Handling
                        # Check none for keys before casting to int/bool
                        c_raw = item.get('complexity')
                        r['complexity'] = int(c_raw) if c_raw is not None else 0

                        f_raw = item.get('has_data_flow')
                        r['has_data_flow'] = bool(f_raw) if f_raw is not None else False

                        apis = item.get('apis')
                        # Force list if None or single element edge case
                        if apis is None:
                            apis = []
                        elif not isinstance(apis, list):
                            apis = [str(apis)]  # Should theoretically not happen with updated script

                        r['apis'] = list(set(apis))
                except ValueError:
                    continue
        except Exception as e:
            logger.error(f"Mapping Results Failed: {e}")

    def analyze(self, code: str) -> Tuple[Dict, str]:
        res_map = self.analyze_batch([{'id': 0, 'code': code}])
        return res_map[0], code