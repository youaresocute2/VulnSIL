# vulnsil/core/llm/vllm_client.py
from __future__ import annotations

import json
import logging
from typing import Tuple

from openai import OpenAI

from config import settings
from vulnsil.schemas import AnalysisResult, DecisionEnum

logger = logging.getLogger("VLLMClient")


class VLLMClient:
    """
    与本地 vLLM(OpenAI-compatible) 服务交互的客户端。

    约定：
    - 输入：已经构造好的 prompt（包含代码、静态分析结果、RAG 证据等）
    - 输出：AnalysisResult 对象 + native_confidence（直接取 result.confidence）
    """

    def __init__(self) -> None:
        # 如果你在 config.Settings 里有 LLM_API_BASE / LLM_API_KEY / LLM_MODEL_NAME，
        # 这里会直接使用；否则需要在 config.py 里补充这些字段。
        base_url = settings.LLM_API_BASE
        api_key = getattr(settings, "LLM_API_KEY", None) or "EMPTY"

        self._client = OpenAI(
            base_url=base_url,
            api_key=api_key,
        )
        self._model_name = settings.LLM_MODEL_NAME
        self._max_tokens = settings.LLM_MAX_TOKENS

        logger.info(
            f"[VLLMClient] Initialized with base_url={base_url}, model={self._model_name}, "
            f"max_tokens={self._max_tokens}"
        )

    @staticmethod
    def _build_system_prompt() -> str:
        """
        统一的系统提示，用于约束 LLM 输出为 JSON 对象。
        """
        return (
            "You are an expert security auditor specialized in static analysis and "
            "vulnerability detection. You MUST respond with a single valid JSON object "
            "that conforms to the following schema:\n\n"
            "{\n"
            '  "is_vulnerable": bool,\n'
            '  "confidence": float (0.0 - 1.0),\n'
            '  "reasoning": string,\n'
            '  "decision": "vulnerable" | "safe" | "unknown",\n'
            '  "cwe": string or null,\n'
            '  "kb_evidence": [\n'
            "    {\n"
            '      "code": string,\n'
            '      "cwe": string or null,\n'
            '      "project": string or null,\n'
            '      "commit_id": string or null,\n'
            '      "label": 0 or 1 or null,\n'
            '      "similarity_score": float or null\n'
            "    }, ...\n"
            "  ]\n"
            "}\n\n"
            "Do not wrap the JSON in markdown. Do not output any text before or after the JSON."
        )

    @staticmethod
    def _extract_json_from_text(text: str) -> dict:
        """
        尝试从 LLM 输出中提取 JSON 对象。
        - 优先直接 json.loads
        - 如果失败，再从中间截取第一个 '{' 到最后一个 '}' 子串尝试解析
        """
        text = text.strip()
        try:
            return json.loads(text)
        except Exception:
            pass

        # 尝试从 text 中找到 JSON 子串
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidate = text[start : end + 1]
            try:
                return json.loads(candidate)
            except Exception:
                logger.warning("[VLLMClient] Failed to parse candidate JSON substring.")
                raise

        raise ValueError("No valid JSON object found in LLM response.")

    def generate(
        self,
        prompt: str,
        temperature: float = 0.1,
        max_tokens: int | None = None,
    ) -> Tuple[AnalysisResult, float]:
        """
        调用本地 vLLM 服务进行推理。

        参数：
        - prompt: 已经构造好的完整 prompt（包含代码/RAG/静态分析等）
        - temperature: 采样温度（默认 0.1）
        - max_tokens: 输出最大 token 数；若为 None 则使用 settings.LLM_MAX_TOKENS

        返回：
        - AnalysisResult 对象
        - native_confidence: 直接取 result.confidence 字段（供置信度特征使用）
        """
        if max_tokens is None:
            max_tokens = self._max_tokens

        messages = [
            {
                "role": "system",
                "content": self._build_system_prompt(),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ]

        try:
            # 使用 OpenAI SDK 调用你本地的 vLLM(OpenAI-compatible) 接口。
            # response_format={"type": "json_object"} 会在官方 OpenAI 下约束输出为 JSON。
            # 对于 vLLM，如果不支持该参数，也不会出错（会被忽略），但我们仍然在本地做 JSON 解析。
            response = self._client.chat.completions.create(
                model=self._model_name,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                response_format={"type": "json_object"},
            )
        except Exception as e:
            logger.error(f"[VLLMClient] LLM call failed: {e}")
            # 出错时返回一个“安全、低置信度”的结果，避免整个 pipeline 崩溃
            fallback = AnalysisResult(
                is_vulnerable=False,
                confidence=0.0,
                reasoning=f"LLM call failed: {e}",
                decision=DecisionEnum.unknown,
                cwe=None,
                kb_evidence=[],
            )
            return fallback, fallback.confidence

        if not response.choices:
            logger.error("[VLLMClient] Empty choices in response.")
            fallback = AnalysisResult(
                is_vulnerable=False,
                confidence=0.0,
                reasoning="Empty response from LLM.",
                decision=DecisionEnum.unknown,
                cwe=None,
                kb_evidence=[],
            )
            return fallback, fallback.confidence

        content = response.choices[0].message.content or ""
        try:
            raw_obj = self._extract_json_from_text(content)
        except Exception as e:
            logger.error(f"[VLLMClient] Failed to parse JSON from LLM output: {e}")
            fallback = AnalysisResult(
                is_vulnerable=False,
                confidence=0.0,
                reasoning=f"Failed to parse JSON from LLM output: {e}",
                decision=DecisionEnum.unknown,
                cwe=None,
                kb_evidence=[],
            )
            return fallback, fallback.confidence

        try:
            result = AnalysisResult.model_validate(raw_obj)
        except Exception as e:
            logger.error(f"[VLLMClient] Pydantic validation failed: {e}")
            # 尝试做一个温和的 fallback，将部分字段填入
            is_vul = bool(raw_obj.get("is_vulnerable", False)) if isinstance(raw_obj, dict) else False
            conf = float(raw_obj.get("confidence", 0.0)) if isinstance(raw_obj, dict) else 0.0
            reasoning = str(raw_obj.get("reasoning", "")) if isinstance(raw_obj, dict) else ""
            decision_str = str(raw_obj.get("decision", "unknown")) if isinstance(raw_obj, dict) else "unknown"
            try:
                decision = DecisionEnum(decision_str)
            except Exception:
                decision = DecisionEnum.unknown

            result = AnalysisResult(
                is_vulnerable=is_vul,
                confidence=conf,
                reasoning=reasoning or f"Pydantic validation failed: {e}",
                decision=decision,
                cwe=raw_obj.get("cwe") if isinstance(raw_obj, dict) else None,
                kb_evidence=[],
            )

        native_conf = float(result.confidence)
        return result, native_conf
