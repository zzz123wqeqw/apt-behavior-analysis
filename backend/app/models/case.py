# -*- coding: utf-8 -*-
"""可疑案例模型（见设计方案 4.2）。"""
from typing import Any, List, Optional

from pydantic import BaseModel


class Case(BaseModel):
    case_id: str
    host: str
    window_start: str
    window_end: str
    events: List[str] = []          # 窗口内事件 ID（截断上限）
    suspicious_score: float = 0.0   # 预筛得分
    hit_rules: List[str] = []       # 命中规则名
    # 后续流水线填充
    behaviors: Optional[Any] = None
    attribution: Optional[Any] = None
    final_status: Optional[str] = None  # 确认 / 待复核 / 误报
