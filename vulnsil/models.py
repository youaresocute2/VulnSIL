# vulnsil/models.py
from sqlalchemy import Column, Integer, String, Text, Float, Boolean, ForeignKey, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from vulnsil.database import Base


class KnowledgeBase(Base):
    """
    RAG 知识库
    映射风险点：依靠 original_id 去重；依靠 id 与 FAISS 进行位置对齐
    """
    __tablename__ = "knowledge_base"
    id = Column(Integer, primary_key=True, index=True)

    # 业务唯一键，格式: {filename}_{row_idx}_{commit_prefix}
    original_id = Column(String(255), unique=True, index=True)

    code = Column(Text)
    label = Column(String)
    cwe_id = Column(String, nullable=True)  # Unified: cwe_id
    source_dataset = Column(String)


class Vulnerability(Base):
    """
    任务表 (Test/Eval Dataset)
    """
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True, index=True)

    # 唯一映射键，用于关联 StaticAnalysisCache
    name = Column(String(255), unique=True, index=True)

    commit_id = Column(String, index=True, nullable=True)
    code = Column(Text)
    ground_truth_label = Column(Integer)
    cwe_id = Column(String, default="N/A")  # Unified: cwe_id
    status = Column(String, default="Pending")  # Pending, Success, Failed

    # 级联删除: 删任务自动删结果
    result = relationship("AnalysisResultRecord", back_populates="vuln", uselist=False, cascade="all, delete-orphan")


class StaticAnalysisCache(Base):
    """
    离线静态分析结果缓存
    """
    __tablename__ = "static_analysis_cache"
    id = Column(Integer, primary_key=True, index=True)

    # 必须与 Vulnerability.name 一致
    task_name = Column(String(255), unique=True, index=True)

    # 0=Unknown, 1=Regex, 2=Joern
    source_type = Column(Integer, default=0, index=True)
    feature_json = Column(Text)  # JSON: has_flow, complexity, apis...
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AnalysisResultRecord(Base):
    """
    推理结果与15维特征记录表
    """
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True)

    # 强外键关联
    vuln_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), unique=True)

    raw_json = Column(Text)
    final_decision = Column(String)
    cwe_id = Column(String, nullable=True)  # Unified: cwe_id

    # Metrics
    native_confidence = Column(Float)
    calibrated_confidence = Column(Float)

    # --- Static Features ---
    static_has_flow = Column(Boolean)
    static_complexity = Column(Integer)
    feat_static_apis_count = Column(Integer)
    feat_static_risk_density = Column(Float)
    feat_static_graph_density = Column(Float, default=0.0)  # [New] AST Topology Density
    feat_static_source_type = Column(Integer)

    # --- Code Features ---
    feat_code_len = Column(Integer)
    feat_is_compressed = Column(Boolean)

    # --- RAG Features ---
    feat_rag_agreement = Column(Float, nullable=True)
    feature_rag_similarity = Column(Float)  # Avg Sim
    feat_rag_top1_sim = Column(Float)  # Max Sim
    feat_rag_sim_variance = Column(Float)

    # --- Interaction Features ---
    feat_conflict_disagreement = Column(Float)  # Weighted Conflict
    feat_conflict_static_yes_llm_no = Column(Integer)
    feat_llm_uncertainty = Column(Float, default=0.0)  # Entropy Score

    vuln = relationship("Vulnerability", back_populates="result")
    created_at = Column(DateTime(timezone=True), server_default=func.now())