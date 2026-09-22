# -*- coding: utf-8 -*-
"""解析模块测试。"""
from pathlib import Path

from app.services.parser import parser

SAMPLE = [
    {"event_id": "evt_001", "ts": "2026-09-20T10:00:00", "type": "flow",
     "src_ip": "10.0.0.1", "dst_ip": "45.77.1.1", "dst_port": 443, "action": "connect", "label": "attack"},
    {"event_id": "evt_002", "ts": "2026-09-20T10:00:01", "type": "dns", "domain": "evil.com", "label": "attack"},
    {"event_id": "evt_003", "ts": "bad_ts", "type": "flow"},  # 非法时间戳应被过滤
]


def test_parse_dicts_orders_by_time():
    events = parser.parse_dicts(SAMPLE)
    assert len(events) == 2  # 非法时间戳被过滤
    assert events[0].event_id == "evt_001"
    assert events[1].event_id == "evt_002"
    assert events[1].ts >= events[0].ts


def test_parse_ndjson_real_format(tmp_path):
    """OTRF NDJSON（每行一个 Windows 事件）可解析。"""
    line = ('{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational",'
            '"@timestamp":"2020-09-20T16:16:06.363Z","Image":"C:\\\\Windows\\\\system32\\\\cmd.exe",'
            '"ParentImage":"C:\\\\Windows\\\\explorer.exe","Hostname":"PC01"}')
    f = tmp_path / "real.ndjson"
    f.write_text(line + "\n", encoding="utf-8")
    events = parser.parse_file(f)
    assert len(events) == 1
    assert events[0].type.value == "process"
    assert events[0].process == "cmd.exe"
    assert events[0].label == "attack"
