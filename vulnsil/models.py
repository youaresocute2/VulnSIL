# vulnsil/models.py
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
    label = Column(String)
    cwe_id = Column(String, nullable=True)
    source_dataset = Column(String)


class Vulnerability(Base):
    """
    待分析任务表 (Eval/Test Dataset)
    """
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True, index=True)

    # [Key Link] 用于与 Cache 关联的唯一标识 (split_commit_idx)
    name = Column(String, unique=True, index=True)

    # [Metadata] 保留 Commit ID 供展示或分组
    commit_id = Column(String, index=True, nullable=True)

    code = Column(Text)
    ground_truth_label = Column(Integer)
    cwe_id = Column(String, default="N/A")
    status = Column(String, default="Pending")

    result = relationship("AnalysisResultRecord", back_populates="vuln", uselist=False)


class StaticAnalysisCache(Base):
    """
    [新增] 离线静态分析缓存表
    用于存储耗时的分析结果，供 Pipeline 毫秒级读取
    """
    __tablename__ = "static_analysis_cache"
    id = Column(Integer, primary_key=True, index=True)

    # 必须与 Vulnerability.name 一致
    task_name = Column(String, unique=True, index=True)

    # [核心独立字段]：来源可信度 (2=Joern, 1=Regex, 0=None)
    # 用于 Prompt 和 特征向量
    source_type = Column(Integer, default=0, index=True)

    # 其他复杂结构 (apis list, complexity etc) 存为 JSON
    feature_json = Column(Text)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AnalysisResultRecord(Base):
    """
    最终推理结果表
    """
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True)
    vuln_id = Column(Integer, ForeignKey("vulnerabilities.id"), unique=True)

    raw_json = Column(Text)
    final_decision = Column(String)
    cwe_id = Column(String, nullable=True)

    native_confidence = Column(Float)
    calibrated_confidence = Column(Float)

    # --- 特征维度 ---
    static_has_flow = Column(Boolean)
    static_complexity = Column(Integer)
    feat_static_apis_count = Column(Integer)

    # [新增] 静态风险密度 = apis_count / code_len
    feat_static_risk_density = Column(Float, default=0.0)

    # [核心特征] 静态分析来源权重
    feat_static_source_type = Column(Integer, default=0)

    # Code Metadata
    feat_code_len = Column(Integer)
    feat_is_compressed = Column(Boolean)

    # RAG Metrics
    feat_rag_agreement = Column(Float)
    feat_rag_similarity = Column(Float)
    feat_rag_top1_sim = Column(Float)
    feat_rag_sim_variance = Column(Float)

    # Conflict Features
    feat_conflict_disagreement = Column(Integer)
    feat_conflict_static_yes_llm_no = Column(Integer)

    # [新增] LLM 犹豫指数 (根据 thought_process 关键词统计)
    feat_llm_uncertainty = Column(Float, default=0.0)

    # [新增] 图密度特征
    feat_graph_density = Column(Float, default=0.0)

    vuln = relationship("Vulnerability", back_populates="result")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


if __name__ == "__main__":
    from vulnsil.database import engine

    Base.metadata.create_all(bind=engine)