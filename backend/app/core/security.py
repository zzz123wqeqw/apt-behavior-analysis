# -*- coding: utf-8 -*-
"""安全模块。

- Fernet（AES-128-CBC + HMAC）加密敏感字段：IP/域名/样本 Hash 落库加密、展示解密。
- HMAC-SHA256 完整性校验：报告/图谱签名与校验。
- API Token 校验（课设级）。
"""
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet

from app.core.config import settings
from app.core.crypto_util import get_fernet

# 落库前需加密的字段
SENSITIVE_FIELDS = ("src_ip", "dst_ip", "domain", "file_hash", "ioc", "source_url")


def _get_fernet() -> Fernet:
    """加载或生成加密密钥（首次运行自动生成 keyfile）。"""
    return get_fernet(Path(settings.encrypt_keyfile))


def _hmac_key() -> bytes:
    """从 Fernet 密钥派生 HMAC 密钥（课设级，避免额外密钥管理）。"""
    return hashlib.sha256(_get_fernet()._encryption_key).digest()


def encrypt_text(plain: str) -> str:
    """加密单字段，返回可入库字符串。"""
    return _get_fernet().encrypt(plain.encode("utf-8")).decode("utf-8")


def decrypt_text(token: str) -> str:
    """解密单字段。"""
    return _get_fernet().decrypt(token.encode("utf-8")).decode("utf-8")


def encrypt_json(payload: Any) -> str:
    """加密任意 JSON 可序列化对象。"""
    return encrypt_text(json.dumps(payload, ensure_ascii=False))


def decrypt_json(token: str) -> Any:
    """解密并反序列化。"""
    return json.loads(decrypt_text(token))


def sign(payload: str) -> str:
    """HMAC-SHA256 签名。"""
    return hmac.new(_hmac_key(), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def sign_report(report_id: str, canonical: str) -> str:
    """对报告规范化内容签名。"""
    return sign(f"{report_id}|{canonical}")


def verify(payload: str, signature: str) -> bool:
    """校验签名。"""
    return hmac.compare_digest(sign(payload), signature)


def check_token(token: Optional[str]) -> bool:
    """API Token 校验（课设级）。"""
    if not token:
        return False
    return hmac.compare_digest(token, settings.api_token)
