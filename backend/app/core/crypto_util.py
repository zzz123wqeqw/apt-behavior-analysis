# -*- coding: utf-8 -*-
"""通用加解密工具（独立于 settings，避免 config<->security 循环依赖）。

- 密钥文件：默认 backend/keyfile（与 config 默认 ENCRYPT_KEYFILE 一致），首次运行自动生成。
- 供 security（字段加密）与 config（运行时密钥 settings.json）复用。
"""
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet

DEFAULT_KEYFILE = Path(__file__).resolve().parent.parent.parent / "keyfile"  # backend/keyfile


def get_fernet(keyfile: Optional[Path] = None) -> Fernet:
    """加载或生成 Fernet 密钥。"""
    kf = Path(keyfile) if keyfile else DEFAULT_KEYFILE
    if kf.exists():
        key = kf.read_bytes()
    else:
        key = Fernet.generate_key()
        kf.parent.mkdir(parents=True, exist_ok=True)
        kf.write_bytes(key)
    return Fernet(key)


def encrypt_text(plain: str, keyfile: Optional[Path] = None) -> str:
    return get_fernet(keyfile).encrypt(plain.encode("utf-8")).decode("utf-8")


def decrypt_text(token: str, keyfile: Optional[Path] = None) -> str:
    return get_fernet(keyfile).decrypt(token.encode("utf-8")).decode("utf-8")
