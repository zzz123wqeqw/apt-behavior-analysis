# -*- coding: utf-8 -*-
"""API 冒烟测试（骨架）。"""
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health():
    """健康检查（骨架）。"""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["code"] == 0
