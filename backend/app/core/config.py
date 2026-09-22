# -*- coding: utf-8 -*-
"""配置中心。

加载 config.yaml + .env（python-dotenv）+ 运行时密钥 data/settings.json（加密）。
提供全局 settings；密钥可通过 /api/settings/keys 热更新并持久化。
"""
import json
import os
from pathlib import Path

import yaml
from dotenv import load_dotenv

from app.core.crypto_util import decrypt_text, encrypt_text

BASE_DIR = Path(__file__).resolve().parent.parent.parent  # backend/
load_dotenv(BASE_DIR / ".env")

# 运行时密钥文件（敏感值 Fernet 加密存储）
RUNTIME_SETTINGS_FILE = BASE_DIR / "data" / "settings.json"


class Settings:
    """集中配置对象。"""

    def __init__(self) -> None:
        raw = self._load_yaml(BASE_DIR / "config.yaml")

        # 路径
        self.data_dir = str(BASE_DIR / raw.get("paths", {}).get("data_dir", "data"))
        self.output_dir = str(BASE_DIR / raw.get("paths", {}).get("output_dir", "data/output"))

        # 数据库
        self.db_path = str(BASE_DIR / raw.get("database", {}).get("path", "data/apt.db"))

        # LLM
        llm = raw.get("llm", {})
        self.llm_provider = os.getenv("LLM_PROVIDER", llm.get("provider", "deepseek"))
        self.llm_model = os.getenv("DEEPSEEK_MODEL", llm.get("model", "deepseek-chat"))
        self.llm_api_base = os.getenv("LLM_API_BASE", "https://api.deepseek.com/v1")
        self.llm_api_key = os.getenv("DEEPSEEK_API_KEY", "")
        self.llm_timeout = llm.get("timeout_sec", 60)
        self.llm_fallback = os.getenv("LLM_FALLBACK_ENABLED", str(llm.get("fallback_enabled", True))).lower() == "true"

        # 预筛 / 画像
        pre = raw.get("prefilter", {})
        self.features_file = str(BASE_DIR / pre.get("features_file", "data/features.json"))
        self.window_minutes = pre.get("window_minutes", 60)
        self.score_threshold = pre.get("score_threshold", 3)
        prof = raw.get("profiles", {})
        self.profiles_file = str(BASE_DIR / prof.get("file", "data/apt_profiles.json"))
        self.rag_topk = prof.get("rag_topk", 3)

        # 过滤
        flt = raw.get("filter", {})
        self.min_evidence = flt.get("min_evidence", 2)
        self.confirm_threshold = flt.get("confirm_threshold", 0.8)
        self.review_threshold = flt.get("review_threshold", 0.6)

        # 安全
        sec = raw.get("security", {})
        self.api_token = os.getenv("API_TOKEN", sec.get("api_token", "dev-token"))
        self.encrypt_keyfile = str(BASE_DIR / os.getenv("ENCRYPT_KEYFILE", sec.get("encrypt_keyfile", "keyfile")))

        # 情报平台
        itl = raw.get("intel", {})
        self.intel_cache_ttl_hours = itl.get("cache_ttl_hours", 24)
        self.intel_concurrency = itl.get("concurrency", 3)
        self.intel_rate_per_sec = itl.get("rate_per_sec", 1)
        self.vt_api_key = os.getenv("VT_API_KEY", "")
        self.threatbook_api_key = os.getenv("THREATBOOK_API_KEY", "")
        self.fofa_api_key = os.getenv("FOFA_API_KEY", "")

        # 运行时密钥覆盖（settings.json 优先于 .env）
        self._load_runtime_settings()

    # ---------- 运行时密钥持久化 ----------

    KEY_FIELDS = ("llm_api_key", "vt_api_key", "threatbook_api_key", "fofa_api_key", "api_token")

    def _load_runtime_settings(self) -> None:
        if not RUNTIME_SETTINGS_FILE.exists():
            return
        try:
            raw = json.loads(RUNTIME_SETTINGS_FILE.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return
        for field in self.KEY_FIELDS:
            token = raw.get(field)
            if token:
                try:
                    setattr(self, field, decrypt_text(token))
                except Exception:  # noqa: BLE001
                    continue  # 密钥文件变化时静默跳过

    def save_keys(self, keys: dict) -> None:
        """加密保存运行时密钥并立即生效。

        None = 不修改；空字符串 = 清除该密钥。
        """
        RUNTIME_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        raw: dict = {}
        if RUNTIME_SETTINGS_FILE.exists():
            try:
                raw = json.loads(RUNTIME_SETTINGS_FILE.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                raw = {}
        for field in self.KEY_FIELDS:
            v = keys.get(field)
            if v is None:
                continue
            if v == "":
                setattr(self, field, "")
                raw.pop(field, None)
                continue
            setattr(self, field, str(v))
            raw[field] = encrypt_text(str(v))
        RUNTIME_SETTINGS_FILE.write_text(
            json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")

    def key_status(self) -> dict:
        """各密钥是否已配置（不含明文）。"""
        return {
            "llm_api_key": bool(self.llm_api_key),
            "vt_api_key": bool(self.vt_api_key),
            "threatbook_api_key": bool(self.threatbook_api_key),
            "fofa_api_key": bool(self.fofa_api_key),
            "api_token": bool(self.api_token),
        }

    @staticmethod
    def _load_yaml(path: Path) -> dict:
        if not path.exists():
            return {}
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}


settings = Settings()

