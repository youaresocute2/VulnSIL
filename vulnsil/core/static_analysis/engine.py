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
    Static Analysis Engine v7.2 (With Smart Fuse & Fallback)
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
                        r['complexity'] = int(item.get('complexity', 0))
                        r['has_data_flow'] = bool(item.get('has_data_flow', False))
                        apis = item.get('apis', [])
                        if apis: r['apis'] = list(set(apis))
                except ValueError:
                    continue
        except Exception as e:
            logger.error(f"Mapping Results Failed: {e}")

    def analyze(self, code: str) -> Tuple[Dict, str]:
        res_map = self.analyze_batch([{'id': 0, 'code': code}])
        return res_map[0], code