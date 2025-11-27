import textwrap
from typing import Any, Dict, Iterable, List

from vulnsil.schemas import KnowledgeBaseEntry


def _summarize_rag_entries(rag_entries: Iterable[KnowledgeBaseEntry]) -> str:
    lines: List[str] = []
    for idx, entry in enumerate(rag_entries, start=1):
        similarity = getattr(entry, "similarity_score", None)
        label = getattr(entry, "label", None)
        cwe = getattr(entry, "cwe", None) or "Unknown"
        project = getattr(entry, "project", None) or "Unknown"
        commit_id = getattr(entry, "commit_id", None) or "Unknown"
        source = getattr(entry, "source", None) or "kb"
        sim_str = f"{similarity:.3f}" if similarity is not None else "0.000"
        label_str = "vulnerable" if label == 1 else "benign" if label == 0 else "unknown"
        lines.append(
            f"[Ref {idx}] sim={sim_str} label={label_str} cwe={cwe} project={project} commit={commit_id} source={source}"
        )
    return "\n".join(lines) if lines else "(no retrieved references)"


def build_vuln_prompt(
    code: str,
    static_features: Dict[str, Any],
    rag_entries: List[KnowledgeBaseEntry],
    meta: Dict[str, Any] | None = None,
) -> str:
    """Assemble the vulnerability analysis prompt without embedding raw template text in the orchestrator."""
    meta = meta or {}
    complexity = static_features.get("complexity", 0)
    api_count = static_features.get("api_count", 0)
    has_flow = bool(static_features.get("has_flow", False))
    ast_has_dangerous = bool(static_features.get("ast_has_dangerous", False))
    graph_density = static_features.get("graph_density", 0.0)
    rag_summary = _summarize_rag_entries(rag_entries)

    static_block = textwrap.dedent(
        f"""
        Static features:
        - complexity={complexity}
        - api_count={api_count}
        - has_flow={has_flow}
        - ast_has_dangerous={ast_has_dangerous}
        - graph_density={graph_density}
        """
    ).strip()

    code_excerpt = code[:12000]
    prompt = textwrap.dedent(
        f"""
        You are an expert security auditor. Review the provided C/C++ function for security vulnerabilities. Use the static indicators and retrieved references as signals but make an independent judgment.

        {static_block}

        Retrieved references:
        {rag_summary}

        Target code:
        {code_excerpt}

        Respond with a single JSON object following the schema defined by the system instructions. Do not include any extra text.
        """
    ).strip()
    return prompt
