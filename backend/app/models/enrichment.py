# -*- coding: utf-8 -*-
"""情报增强结果模型（B13 / §15）。"""
from typing import Optional

from pydantic import BaseModel


class Enrichment(BaseModel):
    enrichment_id: str
    report_id: Optional[str] = None
    ioc: str
    ioc_type: str            # ip / domain
    platform: str            # threatbook / virustotal / fofa
    verdict: str = "未知"    # 恶意/可疑/正常/未知
    score: float = 0.0
    family: Optional[str] = None
    tags: str = ""
    detail: str = ""
    source_url: str = ""
    queried_at: str = ""
    cited: bool = False      # 是否被 LLM 引用
