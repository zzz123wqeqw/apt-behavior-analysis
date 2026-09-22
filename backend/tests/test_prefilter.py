# -*- coding: utf-8 -*-
"""预筛模块测试。"""
from app.models.event import Event
from app.services.prefilter import domain_entropy, prefilter


def test_features_loaded():
    assert "behaviors" in prefilter.features
    assert "lateral_movement" in prefilter.features["behaviors"]


def test_domain_entropy_high_for_tunnel_subdomain():
    assert domain_entropy("3f9a2c1d8b5e.secure-update.net") >= 3.2
    assert domain_entropy("mail.corp.local") < 3.2


def test_aggregate_produces_case_for_445():
    events = [
        Event(event_id=f"e{i}", ts=f"2026-09-20T09:0{i}:00", type="flow",
              host="web", dst_ip=f"10.10.2.{30 + i}", dst_port=445, action="connect")
        for i in range(8)
    ]
    cases = prefilter.aggregate(events, window_minutes=120)
    assert cases and "lateral_movement" in cases[0].hit_rules
