# -*- coding: utf-8 -*-
"""LLM 客户端。

统一 generate(system, user) 接口，两种后端：
- api：DeepSeek / OpenAI 兼容 Chat Completions（httpx，超时+重试）
- fallback：返回空结构化对象，由 detector/attribution 内部规则兜底
（保证无 Key 时全流程可演示）
"""
import json
import logging
from abc import ABC, abstractmethod
from typing import Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class BaseLLM(ABC):
    @abstractmethod
    def generate(self, system: str, user: str) -> str:
        """发送请求，返回模型输出文本。"""
        raise NotImplementedError


class ApiLLM(BaseLLM):
    """OpenAI 兼容 Chat Completions 调用。"""

    def __init__(self, api_key: str, base_url: str, model: str, timeout: int = 60):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def generate(self, system: str, user: str) -> str:
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        last_err: Optional[Exception] = None
        for attempt in range(2):  # 失败重试 1 次
            try:
                resp = httpx.post(url, json=payload, headers=headers, timeout=self.timeout)
                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]["content"]
            except Exception as e:  # noqa: BLE001
                last_err = e
                logger.warning("LLM 调用失败(第%s次): %s", attempt + 1, e)
        raise RuntimeError(f"LLM API 调用失败: {last_err}")


class FallbackLLM(BaseLLM):
    """规则兜底：返回空对象，由上层服务用本地规则产出结构化结果。"""

    def generate(self, system: str, user: str) -> str:
        return "{}"


class LLMClient:
    """统一 LLM 客户端：按配置选择后端，支持密钥热更新后 reload。"""

    def __init__(self) -> None:
        self._backend: BaseLLM = FallbackLLM()
        self.reload()

    def reload(self) -> None:
        """按当前 settings 重新选择后端（密钥保存后调用）。"""
        if settings.llm_api_key and settings.llm_provider in ("deepseek", "openai_compatible"):
            logger.info("LLM 后端: API (%s)", settings.llm_model)
            self._backend = ApiLLM(
                settings.llm_api_key, settings.llm_api_base, settings.llm_model, settings.llm_timeout
            )
        else:
            logger.info("LLM 后端: 规则兜底（未配置 API Key）")
            self._backend = FallbackLLM()

    @property
    def available(self) -> bool:
        return isinstance(self._backend, ApiLLM) and bool(settings.llm_api_key)

    def generate(self, system: str, user: str) -> str:
        try:
            return self._backend.generate(system, user)
        except Exception as e:  # noqa: BLE001
            logger.warning("LLM 调用失败，降级为兜底: %s", e)
            return "{}"

    def generate_text(self, system: str, user: str) -> str:
        """自由文本生成（用于大模型分析页问答），失败时返回空串。"""
        try:
            return self._backend.generate(system, user)
        except Exception as e:  # noqa: BLE001
            logger.warning("LLM 文本生成失败: %s", e)
            return ""

    def generate_json(self, system: str, user: str) -> dict:
        """生成并容错解析 JSON（取首个 { 到末尾 }）。"""
        text = self.generate(system, user)
        try:
            start, end = text.index("{"), text.rindex("}")
            obj = json.loads(text[start:end + 1])
            return obj if isinstance(obj, dict) else {}
        except (ValueError, json.JSONDecodeError):
            logger.warning("LLM 输出 JSON 解析失败: %s...", text[:80])
            return {}


llm_client = LLMClient()
