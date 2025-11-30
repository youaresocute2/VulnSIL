# VulnSIL/run_pipeline.py
import argparse
import joblib
import os
import gc
import json
import threading
import time
import numpy as np
import pandas as pd
import queue
import signal
import sys
import re

try:
    import pynvml

    pynvml.nvmlInit()
except:
    pass

from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# 项目模块导入
from vulnsil.database import SessionLocal
from vulnsil.models import Vulnerability, AnalysisResultRecord, StaticAnalysisCache
from vulnsil.core.retrieval.hybrid_search import HybridRetriever
from vulnsil.core.llm.vllm_client import VLLMClient
from vulnsil.core.llm.prompts import PromptManager
from vulnsil.schemas import DecisionEnum
from vulnsil.utils_log import setup_logging
from vulnsil.core.static_analysis.compressor import SemanticCompressor
# [New] AST 图特征分析器
from vulnsil.core.static_analysis.ast_analyzer import ASTGraphAnalyzer
from config import settings, ML_FEATURE_NAMES  # [Fix I] Shared definitions

# 初始化日志
logger = setup_logging("pipeline")

# ==============================================================================
# [AUDIT] FEATURE LIST ALIGNMENT (Now synchronized with config.ML_FEATURE_NAMES)
# ==============================================================================
FEATURE_NAMES = ML_FEATURE_NAMES

# 全局信号控制
STOP_EVENT = threading.Event()
INTERRUPT_COUNT = 0


def signal_handler(signum, frame):
    global INTERRUPT_COUNT
    INTERRUPT_COUNT += 1
    if INTERRUPT_COUNT >= 2:
        print("\n💀 Force killing process (User request)...")
        os._exit(1)
    else:
        logger.warning("\n🛑 Received Stop Signal. Finishing pending tasks... (Ctrl+C again to FORCE KILL)")
        STOP_EVENT.set()


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ==============================================================================
# Global Resources
# ==============================================================================
RETRIEVER = None
LLM_CLIENT = None
CALIBRATOR = None
DB_WRITER = None
COMPRESSOR = None
GRAPH_ANALYZER = None

STATS = {
    "total_processed": 0,
    "llm_success": 0,
    "llm_failed": 0,
    "agent_corrected": 0,
    "agent_maintained_vuln": 0,
    "static_source_joern": 0,
    "static_source_fallback": 0,
    "static_source_none": 0
}


# ==============================================================================
# Helper Classes & Functions
# ==============================================================================

class DBWriter:
    """
    异步数据库写入器 (含背压机制 + 故障转移)
    使用有界队列 (Max=200) 防止推理过快导致内存溢出
    [Enhanced] Retry Logic & Backup Strategy
    """

    def __init__(self, batch_size=50, interval_seconds=3.0, max_queue_size=200):
        self.queue = queue.Queue(maxsize=max_queue_size)
        self.batch_size = batch_size
        self.interval_seconds = interval_seconds
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        logger.info(f"💾 Async DB Writer started (Max Queue: {max_queue_size}).")

    def put(self, item):
        # [Fix 5] Backpressure with Retry and Logging
        attempts = 0
        while self.running:
            try:
                # Use shorter timeout to allow log intervention
                self.queue.put(item, block=True, timeout=5)
                return
            except queue.Full:
                attempts += 1
                if attempts % 6 == 0:  # Log every 30s aprox
                    logger.error("❌ DB Writer Queue Full (Timeout)! Pipeline stalled (Backpressure active).")

                # Check emergency stop condition
                if STOP_EVENT.is_set():
                    logger.warning("Pipeline stopping, attempting one last non-blocking push...")
                    try:
                        self.queue.put_nowait(item)
                    except queue.Full:
                        logger.error("Data drop: Writer Queue Full at exit.")
                    return

    def _loop(self):
        batch = []
        last_flush = time.time()
        while self.running or not self.queue.empty():
            try:
                try:
                    item = self.queue.get(timeout=0.5)
                    batch.append(item)
                except queue.Empty:
                    pass

                is_stopping = (not self.running or STOP_EVENT.is_set())
                time_trigger = (time.time() - last_flush > self.interval_seconds)
                size_trigger = (len(batch) >= self.batch_size)

                if batch and (time_trigger or size_trigger or is_stopping):
                    self._flush(batch)
                    batch = []
                    last_flush = time.time()

                    # 标记任务完成
                    for _ in range(len(batch)):
                        try:
                            self.queue.task_done()
                        except:
                            pass

            except Exception as e:
                logger.error(f"Writer Loop Error: {e}")
                time.sleep(1)  # Prevent CPU spin on hard errors

    def _flush(self, batch):
        if not batch: return
        sess = SessionLocal()
        try:
            ids = [x['vuln_id'] for x in batch]
            if ids:
                # 幂等写入: 先删后插
                sess.query(AnalysisResultRecord).filter(AnalysisResultRecord.vuln_id.in_(ids)).delete(
                    synchronize_session=False)

            recs = [AnalysisResultRecord(**x['record_data']) for x in batch if x['type'] == 'success']
            if recs:
                sess.bulk_save_objects(recs)

            for x in batch:
                sess.query(Vulnerability).filter(Vulnerability.id == x['vuln_id']).update({"status": x['status']},
                                                                                          synchronize_session=False)

            # [Fix 5] Transaction Retry Mechanism (Handling SQLite locks)
            committed = False
            for attempt in range(3):
                try:
                    sess.commit()
                    committed = True
                    break
                except Exception as commit_err:
                    if attempt < 2:
                        time.sleep(0.5 + attempt * 0.5)

            if not committed:
                raise RuntimeError("DB Commit failed after 3 attempts.")

        except Exception as e:
            sess.rollback()
            logger.error(f"DB Flush Error: {e}. Attempting Backup.")

            # [Fix 5] Emergency File Backup
            try:
                backup_path = os.path.join(settings.LOG_DIR, f"db_fail_backup_{int(time.time())}.jsonl")
                with open(backup_path, "a", encoding="utf-8") as f:
                    for item in batch:
                        if item.get('type') == 'success':
                            # Simplify dict
                            record = item['record_data'].copy()
                            json.dump(record, f, default=str)
                            f.write("\n")
            except Exception as backup_e:
                logger.error(f"FATAL: Backup Failed: {backup_e}")
        finally:
            sess.close()

    def stop(self):
        logger.info("Stopping DB Writer...")
        self.running = False
        self.thread.join(timeout=10)
        final_batch = []
        while not self.queue.empty():
            try:
                final_batch.append(self.queue.get_nowait())
            except:
                break
        if final_batch:
            self._flush(final_batch)


def ensure_resources(user_device_str=None):
    """
    单例模式加载全局资源
    """
    global RETRIEVER, LLM_CLIENT, CALIBRATOR, DB_WRITER, COMPRESSOR, GRAPH_ANALYZER

    if user_device_str:
        settings.EMBEDDING_DEVICE = user_device_str

    if not LLM_CLIENT:
        logger.info("Init VLLM Client...")
        LLM_CLIENT = VLLMClient()

    # [New] 初始化 AST 图特征计算器
    if not GRAPH_ANALYZER:
        logger.info("Init AST Graph Analyzer (Density Logic)...")
        GRAPH_ANALYZER = ASTGraphAnalyzer()

    if not COMPRESSOR:
        try:
            logger.info("Init Semantic Compressor...")
            COMPRESSOR = SemanticCompressor()
        except Exception as e:
            logger.warning(f"Compressor failed: {e}")
            COMPRESSOR = None

    if not RETRIEVER:
        logger.info("Init Hybrid Retriever (With MD5 Deduplication)...")
        RETRIEVER = HybridRetriever()

    if not CALIBRATOR and os.path.exists(settings.CONFIDENCE_MODEL_PATH):
        try:
            CALIBRATOR = joblib.load(settings.CONFIDENCE_MODEL_PATH)
            logger.info(f"Calibrator Loaded (Pipeline Mode).")
        except Exception:
            logger.warning("Calibrator load failed. Using native confidence.")

    if not DB_WRITER:
        DB_WRITER = DBWriter(max_queue_size=200)


def _calc_calibrated_score_realtime(feature_vec: dict) -> float:
    """
    运行时计算校准分数，用于 Agent 反馈闭环
    """
    if not CALIBRATOR:
        return feature_vec.get("llm_native_conf", 0.5)

    try:
        # [Fix 1] Ensure float conversion for all boolean features strictly
        row_vals = []
        for name in FEATURE_NAMES:
            v = feature_vec.get(name, 0.0)
            try:
                row_vals.append(float(v))
            except:
                row_vals.append(0.0)

        # [Fix IV] Safety NaN check
        row_vals = np.nan_to_num(row_vals, nan=0.0)

        df_vec = pd.DataFrame([row_vals], columns=FEATURE_NAMES)
        # 预测属于 "VULNERABLE" (Class 1) 的概率
        return float(CALIBRATOR.predict_proba(df_vec)[0][1])
    except Exception as e:
        # 出错回退
        return feature_vec.get("llm_native_conf", 0.5)


# ==============================================================================
# Core Inference Logic
# ==============================================================================

def process_inference(task: dict, cached_data: dict):
    """
    核心推理逻辑：
    1. 恢复静态特征与图特征计算
    2. 自适应检索与Prompt构建
    3. LLM 第一轮推理 (Entropy计算)
    4. 校准前置反馈 (Agent Loop Trigger)
    5. Agentic 反思 (Loop Logic)
    6. 最终特征封装与落库
    """
    if STOP_EVENT.is_set(): return False
    try:
        vid = task['id']
        code = task['code']

        # --- 1. Static Feature Extraction ---
        s_type = cached_data.get('source_type', 0)
        j_str = cached_data.get('feature_json')
        feat_dict = json.loads(j_str) if j_str else {}

        # [Fix 2] Semantic Analysis Mode Consistency
        analysis_mode = feat_dict.get('analysis_mode', 'unknown')

        has_flow = feat_dict.get('has_flow', False)

        # Enforce consistency: If mode is AST Fallback, data flow must be False to match Prompt
        if s_type == 1:
            if has_flow:
                logger.debug(f"Task {vid}: Fallback active but has_flow=True. Override to False for prompt safety.")
            has_flow = False

        if has_flow is None: has_flow = False

        complexity = feat_dict.get('complexity', 0) or 0
        apis = feat_dict.get('apis', [])
        if apis is None: apis = []

        # [New] Compute Realtime AST Graph Metrics
        graph_metrics = GRAPH_ANALYZER.analyze_graph_metrics(code)
        graph_density = graph_metrics.get("ast_graph_density", 0.0)

        # Human Readable Description for Prompt
        if s_type == 2:
            desc = "CONFIRMED RISK (Traced by Joern)" if has_flow else "CLEARED (No Flow Detected by Joern)"
        elif s_type == 1:
            desc = "POTENTIAL HINT (Regex Only)"
        else:
            desc = "UNKNOWN"

        # --- 2. RAG & Compression ---
        query_code = code
        compressed = False
        if COMPRESSOR and len(code) > settings.COMPRESSION_TRIGGER_LEN:
            try:
                query_code = COMPRESSOR.compress(code, settings.MAX_CODE_TOKENS_INPUT)
                compressed = True
            except:
                pass

        # Retriever has MD5 Deduplication & MaxSim Gate inside
        rag_hits = RETRIEVER.search(query_code, top_k=settings.RAG_TOP_K)
        final_rag = rag_hits

        # --- 3. First Round Inference ---
        prompt_feats = {
            "complexity": complexity,
            "apis": apis,
            "graph_density": graph_density
        }

        prompt_v1 = PromptManager.build_prompt(code, final_rag, prompt_feats, desc)
        full_msg = f"System: {PromptManager.SYSTEM_PROMPT}\nUser: {prompt_v1}"

        # res_pack = (VulnerabilityResponse, native_conf, entropy_score)
        res_pack = LLM_CLIENT.generate(full_msg)

        if not res_pack or not res_pack[0]:
            if DB_WRITER: DB_WRITER.put({"type": "fail", "vuln_id": vid, "status": "Failed"})
            return False

        res_obj, native_conf, entropy = res_pack

        # --- 4. Pre-Calibration & Agent Loop Logic ---

        # 计算基础统计量
        sims = [x.similarity_score for x in final_rag]
        sim_avg = float(np.mean(sims)) if sims else 0.0
        sim_max = float(np.max(sims)) if sims else 0.0
        # [Fix VI] Safety checks for variance
        sim_var = float(np.var(sims)) if sims and len(sims) > 1 else 0.0

        # 当前轮次的决策
        llm_decision_raw = 1 if res_obj.final_decision.value == "VULNERABLE" else 0

        # 计算特征变量 (用于校准模型输入)
        code_len = float(len(code))
        risk_density = float(len(apis)) / (code_len + 1e-9)
        conflict_val_weighted = float(s_type) * abs(int(has_flow) - llm_decision_raw)
        conflict_spec = 1 if (has_flow and not llm_decision_raw) else 0

        # [Fix 1] Type-safe Feature Dictionary Construction
        raw_feat_map = {
            "llm_native_conf": float(native_conf or 0.0),
            "static_has_flow": float(1.0 if has_flow else 0.0),
            "static_complexity": float(complexity),
            "static_apis_count": float(len(apis)),
            "static_risk_density": float(risk_density if not np.isnan(risk_density) else 0.0),
            "static_graph_density": float(graph_density or 0.0),
            "source_type": float(s_type),
            "code_len_log": np.log1p(code_len),
            "is_compressed": 1.0 if compressed else 0.0,
            "rag_sim_avg": float(sim_avg),
            "rag_top1_sim": float(sim_max),
            "rag_var": float(sim_var),
            "conflict_disagree_weighted": float(conflict_val_weighted),
            "conflict_special": float(conflict_spec),
            "llm_entropy": float(entropy or 0.0)
        }

        # [Fix 9] Length & Alignment Assertion
        # We guarantee order by using loop over FEATURE_NAMES to build final dict/list
        feature_vector_map = {}
        for fname in FEATURE_NAMES:
            # Safe default 0.0 for any key miss
            feature_vector_map[fname] = raw_feat_map.get(fname, 0.0)

        # 前置校准 (Feedback)
        pre_cal_score = _calc_calibrated_score_realtime(feature_vector_map)

        # Agent Trigger Conditions:
        # 1. Conflict: Strong Static (Clean) vs LLM (Vuln)
        cond_conflict = (s_type == 2 and not has_flow and llm_decision_raw == 1)
        # 2. Weak Positive: LLM says Vuln but Model says Prob < 0.5
        cond_weak = (llm_decision_raw == 1 and pre_cal_score < 0.5)

        if cond_conflict or cond_weak:
            trigger_reason = "Conflict" if cond_conflict else "WeakCalibration"
            logger.info(
                f"🔄 [Agent Loop] ID {vid}: Trigger={trigger_reason} (PreScore={pre_cal_score:.3f}). Re-prompting...")

            # Construct Rebuttal Prompt
            rebuttal_msg = (
                f"{prompt_v1}\n\n"
                "**[SYSTEM AUDIT INTERVENTION]**\n"
                "Your analysis predicted VULNERABLE, but detected conflicting evidence:\n"
                f"- Static Analysis: {desc}\n"
                f"- Calibrated Probability: {pre_cal_score:.2f} (Low Confidence)\n\n"
                "**REFLECTION REQUIRED**:\n"
                "1. If you cannot identify a decisive LOGIC/RACE/INTEGER flaw -> **CORRECT to BENIGN**.\n"
                "2. If flaw is strictly independent of data flow -> **MAINTAIN VULNERABLE**.\n\n"
                "Wait: If you are uncertain (< 30% confidence), strictly Default to Safe."
            )

            full_msg_2 = f"System: {PromptManager.SYSTEM_PROMPT}\nUser: {rebuttal_msg}"
            res_pack_2 = LLM_CLIENT.generate(full_msg_2)

            if res_pack_2 and res_pack_2[0]:
                obj_2, conf_2, ent_2 = res_pack_2

                threshold = settings.AGENT_MIN_CONFIDENCE_THRESHOLD  # <--- 修改点

                if obj_2.final_decision.value == "VULNERABLE" and conf_2 < threshold:
                    logger.warning(
                        f"🚫 [Loop Break] ID {vid}: Maintained Vuln but Conf {conf_2:.2f} < {threshold}. Dropping as unreliable."
                    )
                    res_obj = obj_2
                    native_conf = conf_2
                    entropy = ent_2
                    STATS['agent_maintained_vuln'] += 1
                else:
                    # Normal Accept
                    res_obj = obj_2
                    native_conf = conf_2
                    entropy = ent_2

                    if res_obj.final_decision.value == "BENIGN":
                        STATS['agent_corrected'] += 1
                        logger.info(f"✅ [Agent Loop] ID {vid}: Self-corrected to BENIGN.")
                    else:
                        STATS['agent_maintained_vuln'] += 1

        # --- 5. Finalize Feature Vector & Persistence ---

        # Re-calc final dynamic features
        final_decision_raw = 1 if res_obj.final_decision.value == "VULNERABLE" else 0
        final_conflict_w = float(s_type) * abs(int(has_flow) - final_decision_raw)
        final_conflict_spec = 1 if (has_flow and not final_decision_raw) else 0

        # Update Vector Map
        feature_vector_map['llm_native_conf'] = native_conf
        feature_vector_map['llm_entropy'] = entropy
        feature_vector_map['conflict_disagree_weighted'] = final_conflict_w
        feature_vector_map['conflict_special'] = final_conflict_spec

        # Final Calibrated Score
        final_cal_score = _calc_calibrated_score_realtime(feature_vector_map)

        # Prepare DB Record
        record = {
            "vuln_id": vid,
            "raw_json": res_obj.model_dump_json(),
            "final_decision": res_obj.final_decision.value,
            "cwe_id": res_obj.cwe_id,  # [Unified cwe_id]
            "native_confidence": native_conf,
            "calibrated_confidence": final_cal_score,

            # Feature Columns
            "static_has_flow": has_flow,
            "static_complexity": complexity,
            "feat_static_apis_count": len(apis),
            "feat_static_risk_density": risk_density,
            "feat_static_graph_density": graph_density,
            "feat_static_source_type": s_type,

            "feat_code_len": len(code),
            "feat_is_compressed": compressed,

            "feature_rag_similarity": sim_avg,
            "feat_rag_top1_sim": sim_max,
            "feat_rag_sim_variance": sim_var,

            "feat_conflict_disagreement": final_conflict_w,  # Weighted
            "feat_conflict_static_yes_llm_no": final_conflict_spec,
            "feat_llm_uncertainty": entropy  # [Map to DB: entropy stored in uncertainty col]
        }

        if DB_WRITER: DB_WRITER.put({"type": "success", "vuln_id": vid, "record_data": record, "status": "Success"})
        return True

    except Exception as e:
        logger.error(f"Task Error (ID {task.get('id', 'unk')}): {e}", exc_info=True)
        return False


# ==============================================================================
# Batch & Stats Logic
# ==============================================================================

def run_batched_pipeline(tids):
    BATCH = settings.STATIC_ANALYSIS_BATCH_SIZE
    LLM_THREADS = 8

    total = len(tids)
    batches = [tids[i:i + BATCH] for i in range(0, total, BATCH)]
    logger.info(f"🚀 Pipeline Started. Total: {total} tasks. Batches: {len(batches)}.")

    with tqdm(total=total, unit="task", desc="Analyzing") as pbar:
        for b_ids in batches:
            if STOP_EVENT.is_set(): break

            # 1. Fetch Vulnerabilities
            sess = SessionLocal()
            task_rows = sess.query(Vulnerability).filter(Vulnerability.id.in_(b_ids)).all()
            if not task_rows: sess.close(); continue

            task_objs = [{"id": t.id, "name": t.name, "code": t.code} for t in task_rows]
            target_names = [t['name'] for t in task_objs]
            sess.close()

            # 2. Fetch Cached Features
            sess = SessionLocal()
            caches = sess.query(StaticAnalysisCache.task_name, StaticAnalysisCache.source_type,
                                StaticAnalysisCache.feature_json) \
                .filter(StaticAnalysisCache.task_name.in_(target_names)).all()
            sess.close()
            c_map = {r[0]: {"source_type": r[1], "feature_json": r[2]} for r in caches}

            # 3. Concurrent Execution
            with ThreadPoolExecutor(max_workers=LLM_THREADS) as exe:
                futures = []
                for t in task_objs:
                    if STOP_EVENT.is_set(): break
                    c_data = c_map.get(t['name'], {"source_type": 0})

                    # Simple stats
                    st = c_data.get('source_type', 0)
                    if st == 2:
                        STATS['static_source_joern'] += 1
                    elif st == 1:
                        STATS['static_source_fallback'] += 1
                    else:
                        STATS['static_source_none'] += 1

                    f = exe.submit(process_inference, t, c_data)
                    futures.append(f)

                for f in as_completed(futures):
                    if STOP_EVENT.is_set():
                        # [Fix V] Concurrency Cancel Safety
                        for rem in futures: rem.cancel()
                        break
                    try:
                        if f.result():
                            STATS['llm_success'] += 1
                        else:
                            STATS['llm_failed'] += 1
                    except Exception as e:
                        logger.error(f"Thread execution fail: {e}")
                        STATS['llm_failed'] += 1

                    STATS['total_processed'] += 1
                    pbar.set_postfix({"OK": STATS['llm_success'], "Reflect": STATS['agent_corrected']})
                    pbar.update(1)

            # Manual GC to keep memory clean
            manual_gc()

    if DB_WRITER: DB_WRITER.stop()
    print_final_stats()


def manual_gc():
    gc.collect()
    import torch
    if torch.cuda.is_available():
        torch.cuda.empty_cache()


def print_final_stats():
    print(f"\n===== VULNSIL REPORT =====")
    print(f"Total Processed : {STATS['total_processed']}")
    print(f"Success/Failed  : {STATS['llm_success']} / {STATS['llm_failed']}")
    print(f"Stats by Source : Joern={STATS['static_source_joern']} | Fallback={STATS['static_source_fallback']}")
    print(
        f"Agent Logic     : Corrected Safe={STATS['agent_corrected']} | Confirmed Vuln={STATS['agent_maintained_vuln']}")
    print("=========================\n")


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="VulnSIL Inference Pipeline")

    parser.add_argument("--split_name", type=str, required=True,
                        help="Target dataset split name (e.g. diversevul_test)")
    parser.add_argument("--limit", type=int, default=-1, help="Max tasks to run (-1 for all)")
    parser.add_argument("--offset", type=int, default=0, help="Offset task start index")
    parser.add_argument("--device", type=str, default=None, help="Device string override for embedding")

    args = parser.parse_args()

    split_name = args.split_name
    limit = args.limit
    offset = args.offset
    device = args.device

    ensure_resources(device)

    tasks = []
    with SessionLocal() as db:
        q = db.query(Vulnerability.id).filter(
            Vulnerability.name.like(f"{split_name}%"),
            Vulnerability.status.in_(["Pending", "Failed"])
        )
        if offset > 0: q = q.offset(offset)
        if limit > 0: q = q.limit(limit)

        tasks = [r[0] for r in q.all()]

    if not tasks:
        logger.warning(f"No tasks found for split '{split_name}' (Status: Pending/Failed).")
        if DB_WRITER: DB_WRITER.stop()
        return

    try:
        run_batched_pipeline(tasks)
    except KeyboardInterrupt:
        logger.warning("Pipeline interrupted by user.")
    finally:
        if DB_WRITER: DB_WRITER.stop()


if __name__ == "__main__":
    main()