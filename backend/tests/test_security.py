# -*- coding: utf-8 -*-
"""安全模块测试。"""
from app.core import security


def test_encrypt_decrypt_roundtrip():
    enc = security.encrypt_text("45.77.10.20")
    assert enc != "45.77.10.20"
    assert security.decrypt_text(enc) == "45.77.10.20"


def test_sign_verify():
    s = security.sign("payload")
    assert security.verify("payload", s)
    assert not security.verify("tampered", s)


def test_check_token():
    assert security.check_token("dev-token")  # 与 config 默认一致
    assert not security.check_token("wrong")
