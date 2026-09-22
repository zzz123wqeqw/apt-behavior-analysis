# -*- coding: utf-8 -*-
"""研判报告模型（见设计方案 4.3）。"""
from typing import Any, List, Optional

from pydantic import BaseModel


class Behavior(BaseModel):
    type: str                # lateral_movement / hidden_channel / long_term_latency / trace_cleaning
    name: str = ""           # 中文名
    confidence: float = 0.0  # 0-1
    evidence: List[str] = []  # 证据事件 ID
    description: str = ""


class Attribution(BaseModel):
    org: str = ""
    org_confidence: float = 0.0
    path: List[str] = []
    entry: str = ""
    intent: str = ""
    reasoning: str = ""


class Recommendation(BaseModel):
    block: List[str] = []     # 阻断
    clean: List[str] = []     # 清除
    trace: List[str] = []     # 溯源


class Report(BaseModel):
    report_id: str
    created_at: str = ""
    case_id: str = ""
    behaviors: List[Behavior] = []
    attribution: Optional[Attribution] = None
    risk_level: str = "低"    # 低/中/高/严重
    scope: List[Any] = []     # 影响主机/IP/域名
    timeline: List[Any] = []  # 攻击链时间线
    recommendations: Optional[Recommendation] = None
    status: str = "待复核"    # 确认 / 待复核 / 误报
    signature: str = ""


class AnalyzeRequest(BaseModel):
    """POST /api/analyze 请求体（骨架）。"""
    scene: Optional[str] = None   # 指定场景；空 = 全量
    data_file: Optional[str] = None  # 可指定外部事件文件
    use_intel: bool = True        # 是否启用情报平台增强
