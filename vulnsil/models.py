# --- START OF FILE vulnsil/models.py ---

from sqlalchemy import Column, Integer, String, Text, Float, Boolean, ForeignKey, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from vulnsil.database import Base


class KnowledgeBase(Base):
    """
    RAG 知识库: 存储用于检索的历史漏洞案例
    """
    __tablename__ = "knowledge_base"
    id = Column(Integer, primary_key=True, index=True)
    original_id = Column(String, unique=True, index=True)
    code = Column(Text)
    label = Column(Integer)  # 统一使用 int 类型
    cwe_id = Column(String, nullable=True)
    source_dataset = Column(String)


class Vulnerability(Base):
    """
    待分析任务表 (Eval/Test Dataset)
    """
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True, index=True)

    # 任务唯一标识 (split_commit_idx)
    name = Column(String, unique=True, index=True)

    # [扩展] 数据集来源字段
    dataset = Column(String, index=True, nullable=True, default="unknown")

    commit_id = Column(String, index=True, nullable=True)
    code = Column(Text)
    ground_truth_label = Column(Integer)
    cwe_id = Column(String, default="N/A")
    status = Column(String, default="Pending")

    # 关联到统一 Prediction 表
    prediction = relationship("Prediction", back_populates="vuln", uselist=False)


class StaticAnalysisCache(Base):
    """
    离线静态分析缓存表
    """
    __tablename__ = "static_analysis_cache"
    id = Column(Integer, primary_key=True, index=True)

    task_name = Column(String, unique=True, index=True)
    source_type = Column(Integer, default=0, index=True)
    feature_json = Column(Text)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Prediction(Base):
    """
    统一的预测结果表，兼容旧版 AnalysisResultRecord 与新版 Prediction 字段
    """
    __tablename__ = "predictions"

    id = Column(Integer, primary_key=True)
    vuln_id = Column(Integer, ForeignKey("vulnerabilities.id"), unique=True, index=True)

    # 冗余存储方便查询
    name = Column(String, index=True)
    dataset = Column(String, index=True)

    # --- 统一核心字段 ---
    is_vulnerable = Column(Boolean)
    confidence = Column(Float)
    calibrated_confidence = Column(Float)
    final_pred = Column(Integer)
    decision = Column(String)
    cwe = Column(String, nullable=True)
    reasoning = Column(Text)
    kb_evidence = Column(Text)

    # --- LLM / 中间特征字段 ---
    llm_pred = Column(Integer)  # 0 or 1
    llm_native_confidence = Column(Float)
    llm_reasoning = Column(Text)
    feature_json = Column(Text)  # 特征字典
    rag_result_json = Column(Text)  # Top-K 检索结果

    # --- 兼容旧表字段 ---
    raw_json = Column(Text)
    static_has_flow = Column(Boolean)
    static_complexity = Column(Integer)
    feat_static_apis_count = Column(Integer)
    feat_static_risk_density = Column(Float, default=0.0)
    feat_static_source_type = Column(Integer, default=0)
    feat_code_len = Column(Integer)
    feat_is_compressed = Column(Boolean)
    feat_rag_agreement = Column(Float)
    feat_rag_similarity = Column(Float)
    feat_rag_top1_sim = Column(Float)
    feat_rag_sim_variance = Column(Float)
    feat_conflict_disagreement = Column(Integer)
    feat_conflict_static_yes_llm_no = Column(Integer)
    feat_llm_uncertainty = Column(Float, default=0.0)
    feat_graph_density = Column(Float, default=0.0)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    vuln = relationship("Vulnerability", back_populates="prediction")