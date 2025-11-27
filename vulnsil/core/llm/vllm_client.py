# VulnSIL/vulnsil/core/llm/vllm_client.py
import requests
import json
import numpy as np
import logging
from pydantic import ValidationError
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception
from config import settings
from vulnsil.schemas import AnalysisResult

logger = logging.getLogger(__name__)


# 自定义异常判断：如果是 4xx 错误（如 Token 超出），不要重试，直接失败，避免浪费时间
def is_retryable_error(exception):
    if isinstance(exception, requests.exceptions.HTTPError):
        status_code = exception.response.status_code
        # 400-499 客户端错误（参数错误、长度溢出等）不重试
        if 400 <= status_code < 500:
            return False
    # 其他网络错误、超时、500 服务端错误都重试
    return True


class VLLMClient:

    @retry(
        stop=stop_after_attempt(3),  # 最多重试 3 次
        wait=wait_exponential(multiplier=1, min=2, max=10),  # 指数退避 2s, 4s, 8s
        retry=retry_if_exception(is_retryable_error),  # 智能判断是否重试
        reraise=True  # 抛出最后一次异常供上层捕获
    )
    def _post_request(self, payload):
        """带重试机制的底层请求"""
        resp = requests.post(
            settings.LLM_API_URL,
            json=payload,
            timeout=settings.LLM_TIMEOUT
        )
        resp.raise_for_status()  # 将 HTTP 状态码转换为异常，触发 tenacity
        return resp

    def generate(self, prompt: str):
        """
        生成LLM响应
        [改进] 添加Agentic Loop迭代验证；加权native_conf（早期token高权）
        """
        payload = {
            "model": settings.LLM_MODEL_NAME,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": settings.LLM_TEMPERATURE,
            "max_tokens": settings.LLM_MAX_TOKENS,
            "repetition_penalty": settings.LLM_REPETITION_PENALTY,
            "guided_json": AnalysisResult.model_json_schema(),
            "logprobs": True,
        }

        try:
            # 初步响应
            resp = self._post_request(payload)
            data = resp.json()

            content = data['choices'][0]['message']['content']
            logprobs = data.get('choices', [{}])[0].get('logprobs', {}).get('content', None)

            # 新增：加权conf（早期高权）
            if logprobs:
                probs = [np.exp(lp['logprob']) * (1 - i / len(logprobs)) for i, lp in enumerate(logprobs)]  # 线性衰减
                native_conf = float(np.mean(probs))
            else:
                native_conf = 0.5

            try:
                result = AnalysisResult.model_validate_json(content)

                # 归一化逻辑
                if result.confidence > 1.0:
                    result.confidence = result.confidence / 100.0
                result.confidence = max(0.0, min(1.0, result.confidence))

                # 新增：Agentic Loop验证
                for _ in range(settings.AGENTIC_MAX_ITER - 1):
                    verify_prompt = f"Verify: {result.thought_process}. Any conflicts with evidence?"
                    verify_payload = payload.copy()
                    verify_payload["messages"] = [{"role": "user", "content": verify_prompt}]
                    verify_resp = self._post_request(verify_payload)
                    verify_data = verify_resp.json()
                    verify_content = verify_data['choices'][0]['message']['content']
                    verify_result = AnalysisResult.model_validate_json(verify_content)
                    if verify_result.confidence < 0.5:  # 冲突，重推理
                        payload["messages"].append({"role": "assistant", "content": verify_content})
                        resp = self._post_request(payload)
                        data = resp.json()
                        content = data['choices'][0]['message']['content']
                        result = AnalysisResult.model_validate_json(content)
                    else:
                        break

                return result, native_conf

            except ValidationError as e:
                logger.error(f"JSON Parse Fail: {str(e)[:100]}")
                return None, 0.0

        except requests.exceptions.HTTPError as e:
            # 专门捕获 400 错误，打印具体原因，不重试，直接返回失败
            if e.response.status_code == 400:
                logger.error(f"❌ LLM Input Too Long (HTTP 400): {e.response.text[:200]}")
            else:
                logger.error(f"LLM HTTP Error: {e}")
            return None, 0.0
        except Exception as e:
            logger.error(f"LLM Unknown Error: {e}")
            return None, 0.0