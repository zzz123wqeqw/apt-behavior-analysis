# -*- coding: utf-8 -*-
"""事件模型（统一 schema，见设计方案 4.1）。"""
from enum import Enum
from typing import Optional

from pydantic import BaseModel


class EventType(str, Enum):
    flow = "flow"
    process = "process"
    file = "file"
    dns = "dns"
    auth = "auth"


class Event(BaseModel):
    event_id: str
    ts: str  # ISO 时间戳
    type: EventType
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    domain: Optional[str] = None
    process: Optional[str] = None
    parent_process: Optional[str] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    action: Optional[str] = None  # login/exec/delete/write/connect...
    user: Optional[str] = None
    host: Optional[str] = None
    scene: Optional[str] = None  # 评测用
    label: Optional[str] = None  # normal/attack（标准答案，评测用）
