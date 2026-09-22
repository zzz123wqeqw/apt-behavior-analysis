# -*- coding: utf-8 -*-
"""GET /api/stats 仪表盘统计。"""
import json
from collections import Counter
from typing import List

from fastapi import APIRouter, Depends

from app.api.deps import get_current_token
from app.core.database import fetch_all

router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("")
async def get_stats(_: str = Depends(get_current_token)) -> dict:
    report_rows = fetch_all("SELECT * FROM reports")
    event_rows = fetch_all("SELECT label, scene FROM events")

    behavior_dist: Counter = Counter()
    risk_dist: Counter = Counter()
    top_orgs: Counter = Counter()
    for r in report_rows:
        risk_dist[r["risk_level"]] += 1
        org = (json.loads(r["attribution_json"]) or {}).get("org", "未知")
        top_orgs[org] += 1
        for b in json.loads(r["behaviors_json"]):
            behavior_dist[b.get("type", "unknown")] += 1

    # 时间趋势（按日期聚合 events）
    trend: Counter = Counter()
    for r in fetch_all("SELECT substr(ts,1,10) AS d, COUNT(*) c FROM events GROUP BY d ORDER BY d"):
        trend[r["d"]] = r["c"]

    attack = sum(1 for e in event_rows if e["label"] == "attack")
    normal = sum(1 for e in event_rows if e["label"] == "normal")
    high_count = sum(1 for r in report_rows if r["risk_level"] == "高" or r["status"] == "确认")
    return {
        "code": 0, "message": "ok",
        "data": {
            "total_events": len(event_rows),
            "attack_events": attack,
            "normal_events": normal,
            "case_count": len(fetch_all("SELECT case_id FROM cases")),
            "report_count": len(report_rows),
            "high_count": high_count,
            "behavior_dist": dict(behavior_dist),
            "risk_dist": dict(risk_dist),
            "trend": [{"date": k, "count": v} for k, v in trend.items()],
            "top_orgs": [{"org": k, "count": v} for k, v in top_orgs.most_common(8)],
        },
    }
