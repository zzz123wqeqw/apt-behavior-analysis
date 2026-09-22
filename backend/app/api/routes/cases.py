# -*- coding: utf-8 -*-
"""GET /api/cases 可疑案例查询。"""
import json
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.api.deps import get_current_token
from app.core.database import fetch_all, fetch_one

router = APIRouter(prefix="/api/cases", tags=["cases"])


@router.get("")
async def list_cases(
    status: Optional[str] = None,
    score_min: float = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _: str = Depends(get_current_token),
) -> dict:
    where, params = " WHERE 1=1", []
    if status:
        where += " AND status=?"
        params.append(status)
    if score_min > 0:
        where += " AND suspicious_score>=?"
        params.append(score_min)
    rows = fetch_all(f"SELECT * FROM cases{where} ORDER BY suspicious_score DESC LIMIT ? OFFSET ?",
                     tuple(params + [limit, offset]))
    items = []
    for r in rows:
        d = dict(r)
        d["hit_rules"] = json.loads(d["hit_rules"]) if d.get("hit_rules") else []
        items.append(d)
    return {"code": 0, "message": "ok", "data": {"items": items, "total": len(items) + offset}}


@router.get("/{case_id}")
async def get_case(case_id: str, _: str = Depends(get_current_token)) -> dict:
    row = fetch_one("SELECT * FROM cases WHERE case_id=?", (case_id,))
    if not row:
        return {"code": 1, "message": "not_found", "data": None}
    d = dict(row)
    d["hit_rules"] = json.loads(d["hit_rules"]) if d.get("hit_rules") else []
    return {"code": 0, "message": "ok", "data": d}
