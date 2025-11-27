import logging

from vulnsil.core.llm.vllm_client import VLLMClient
from vulnsil.schemas import AnalysisResult

logger = logging.getLogger(__name__)


class LLMService:
    """Facade over vLLM client to keep pipeline orchestration decoupled from provider details."""

    def __init__(self) -> None:
        self._client = VLLMClient()

    def analyze(self, prompt: str) -> AnalysisResult:
        try:
            result, _ = self._client.generate(prompt)
            return result
        except Exception as exc:  # pragma: no cover - defensive fallback
            logger.error("LLM analysis failed: %s", exc)
            return AnalysisResult(
                is_vulnerable=False,
                confidence=0.0,
                reasoning=f"LLM failure: {exc}",
                decision="unknown",  # type: ignore[arg-type]
                cwe=None,
                kb_evidence=[],
            )
