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
    label = Column(String)  # "0" or "1"
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

    # 旧的关系，保留以兼容现有代码查询
    result = relationship("AnalysisResultRecord", back_populates="vuln", uselist=False)
    # [新增] 关联到 Prediction 表
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
    [新增] 最终预测结果表
    存储完整流程数据，包括 LLM 原始输出、RAG 结果、构造后的特征以及最终决策。
    """
    __tablename__ = "predictions"

    id = Column(Integer, primary_key=True)
    vuln_id = Column(Integer, ForeignKey("vulnerabilities.id"), unique=True)

    # 冗余存储方便查询
    name = Column(String, index=True)
    dataset = Column(String, index=True)

    # --- LLM 原始结果 ---
    llm_pred = Column(Integer)  # 0 or 1
    llm_native_confidence = Column(Float)
    llm_reasoning = Column(Text)

    # --- 中间数据 (JSON) ---
    feature_json = Column(Text)  # 15维特征字典
    rag_result_json = Column(Text)  # Top-K 检索结果

    # --- 最终决策 ---
    calibrated_confidence = Column(Float)  # Model 输出 (0.0 - 1.0)
    final_pred = Column(Integer)  # 阈值切分结果 (0 or 1)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    vuln = relationship("Vulnerability", back_populates="prediction")


class AnalysisResultRecord(Base):
    """
    旧的分析结果表
    保留此表定义，避免在原有脚本或逻辑中删除有用功能报错。
    """
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True)
    vuln_id = Column(Integer, ForeignKey("vulnerabilities.id"), unique=True)

    raw_json = Column(Text)
    final_decision = Column(String)
    cwe_id = Column(String, nullable=True)

    native_confidence = Column(Float)
    calibrated_confidence = Column(Float)

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

    vuln = relationship("Vulnerability", back_populates="result")
    created_at = Column(DateTime(timezone=True), server_default=func.now())