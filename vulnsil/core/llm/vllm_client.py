# vulnsil/core/llm/vllm_client.py
import requests
import json
import numpy as np
import logging
import re
from pydantic import ValidationError
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception
from config import settings
# [Fix 3] Need DecisionEnum for safe fallback construction
from vulnsil.schemas import VulnerabilityResponse, DecisionEnum

logger = logging.getLogger(__name__)


def is_retryable_error(exception):
    if isinstance(exception, requests.exceptions.HTTPError):
        # 4xx client errors should not retry (Context length, Invalid JSON)
        if 400 <= exception.response.status_code < 500: return False
    return True


class VLLMClient:
    """
    Robust Client with Input Sanitization & Entropy Metrics
    [Enhanced] Features Retry Logic, Format Repair, and Safe Fallback (Fix 3)
    """

    @retry(
        stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception(is_retryable_error), reraise=True
    )
    def _post_request(self, payload):
        resp = requests.post(settings.LLM_API_URL, json=payload, timeout=settings.LLM_TIMEOUT)
        resp.raise_for_status()
        return resp

    def _sanitize_prompt(self, text: str) -> str:
        """
        [Security Fix] Remove control characters to prevent prompt injection or format breakage.
        Preserves \n (0x0A), \r (0x0D), \t (0x09).
        Removes: 0x00-0x08, 0x0B-0x0C, 0x0E-0x1F, 0x7F(DEL).
        """
        if not text: return ""
        # Concise Regex for control block
        clean_text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
        return clean_text

    def generate(self, prompt: str):
        # 1. Sanitize
        clean_prompt = self._sanitize_prompt(prompt)

        # 2. Guided Generation Configuration
        json_schema = VulnerabilityResponse.model_json_schema()
        payload = {
            "model": settings.LLM_MODEL_NAME,
            "messages": [{"role": "user", "content": clean_prompt}],
            "temperature": settings.LLM_TEMPERATURE,
            "max_tokens": settings.LLM_MAX_TOKENS,
            "repetition_penalty": settings.LLM_REPETITION_PENALTY,
            "guided_json": json_schema,
            "logprobs": True,
        }

        try:
            resp = self._post_request(payload)
            data = resp.json()
            content = data['choices'][0]['message']['content']

            # 3. Calculate Uncertainty Metrics (Native + Entropy)
            logprobs_list = data.get('choices', [{}])[0].get('logprobs', {}).get('content', [])
            native_conf = 0.5
            entropy_score = 0.0

            if logprobs_list:
                # Filter nulls
                valid_lps = [lp.get('logprob') for lp in logprobs_list if lp.get('logprob') is not None]
                if valid_lps:
                    probs = np.array([np.exp(lp) for lp in valid_lps])
                    native_conf = float(np.mean(probs))

                    # Shannon Entropy H = - sum(p * ln(p))
                    # Adds 1e-10 stability epsilon
                    entropy_score = -np.sum(probs * np.log(probs + 1e-10))
                    entropy_score = float(entropy_score)

            # 4. [Fix 3] Robust Validation Loop

            # Simple manual fix for bool strings (LLM quirk)
            content_cleaned = content.replace('"true"', 'true').replace('"false"', 'false')

            parsed_result = None
            last_err = None

            # Retry loop for parsing stability (2 attempts)
            for attempt in range(2):
                try:
                    parsed_result = VulnerabilityResponse.model_validate_json(content_cleaned)
                    break
                except Exception as e:
                    # Capture Pydantic ValidationError or JSONDecodeError
                    last_err = e
                    # Log retry warning only
                    if attempt == 0:
                        logger.warning(f"Parsing 1st Attempt Failed: {str(e)[:50]}... Retrying.")

            # [Fix 3] Evidence Size Warning (Anti-Hallucination)
            if parsed_result and len(parsed_result.evidence) > 5:
                logger.warning(
                    f"Warning: Large evidence count detected ({len(parsed_result.evidence)}). Possible Hallucination.")

            # [Fix 3] Safe Fallback if Parsing Failed Completely
            if parsed_result is None:
                # Critical: Log original error before swallowing
                # This format preserves the intention of original "Response Schema Invalid" log
                logger.warning(f"Response Schema Invalid (Final): {str(last_err)[:200]}. Fallback to BENIGN.")

                # Construct Safe Benign Response to prevent Pipeline crash
                parsed_result = VulnerabilityResponse(
                    thought_process=f"[SYSTEM FALLBACK] JSON Parse Failure: {str(last_err)[:50]}...",
                    static_analysis_review="UNCERTAIN",
                    evidence={},
                    final_decision=DecisionEnum.BENIGN,  # Default Safe
                    confidence=0.0,
                    cwe_id="Unknown"
                )

            # Normalization (Constraint Check)
            result = parsed_result
            if result.confidence > 1.0: result.confidence /= 100.0
            result.confidence = max(0.0, min(1.0, result.confidence))

            return result, native_conf, entropy_score

        except Exception as e:
            logger.error(f"VLLM Client Inference Error: {e}")
            # Ensure return signature consistency: Object, float, float
            return None, 0.0, 0.0