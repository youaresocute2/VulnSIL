# vulnsil/models.py

from sqlalchemy import Column, Integer, String, Text, Float, JSON, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

# 定义所有模型的基础类 (Base)
Base = declarative_base()


class Vulnerability(Base):
    """
    存储从数据集中加载的原始漏洞/代码样本。
    这代表“Ground Truth”（真实标签）。
    """
    __tablename__ = 'vulnerabilities'

    id = Column(Integer, primary_key=True)

    # 基础字段 (来自上一轮)
    name = Column(String(255), index=True, unique=True)  # "name"
    code = Column(Text, nullable=False)  # "func"
    ground_truth_label = Column(String(10))  # "label" ("1" or "0")
    ground_truth_cwe = Column(String(50))  # "cwe_id"

    # -----------------------------------------------------------------
    # [新增] 存储 VCLData 中的丰富语义标签
    ground_truth_source = Column(Text, nullable=True)  # "source"
    ground_truth_sink = Column(Text, nullable=True)  # "sink"
    ground_truth_reason = Column(Text, nullable=True)  # "reason"
    # -----------------------------------------------------------------

    cve_id = Column(String(50), index=True, nullable=True)

    # 关联到 VulnSIL 的分析结果
    analysis_results = relationship(
        "VulnSILAnalysis",
        back_populates="vulnerability",
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Vulnerability(name='{self.name}', label='{self.ground_truth_label}')>"


class VulnSILAnalysis(Base):
    """
    存储 VulnSIL 流水线针对每个 Vulnerability 的 *所有* 输出结果。
    这代表“Prediction”（模型预测）。
    """
    __tablename__ = 'vulnsil_analysis'

    id = Column(Integer, primary_key=True)

    vulnerability_id = Column(Integer, ForeignKey('vulnerabilities.id'), nullable=False, index=True, unique=True)

    vulnerability = relationship("Vulnerability", back_populates="analysis_results")

    # [字段保持不变]
    final_sil_json = Column(Text, nullable=True)
    vapa_iterations = Column(Text, nullable=True)  # 存储 JSON 字符串
    final_sil_confidence = Column(Float, nullable=True)
    reasoning_raw = Column(Text, nullable=True)
    reasoning_confidence = Column(Float, nullable=True)
    final_decision = Column(String(100), nullable=True)
    detected_cwe = Column(String(100), nullable=True)
    status = Column(String(50), default="Pending", index=True)

    def __repr__(self):
        return f"<VulnSILAnalysis(vuln_id={self.vulnerability_id}, decision='{self.final_decision}')>"