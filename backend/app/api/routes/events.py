# -*- coding: utf-8 -*-
"""GET /api/events 事件查询（分页/过滤/解密展示）+ POST /api/events/batch 按 ID 批量查询。"""
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.api.deps import get_current_token
from app.core import security
from app.core.database import fetch_all

router = APIRouter(prefix="/api/events", tags=["events"])


class BatchRequest(BaseModel):
    ids: List[str] = []


def _decrypt_event(r: dict) -> dict:
    for f in ("src_ip", "dst_ip", "domain", "file_hash"):
        v = r.get(f)
        if v:
            try:
                r[f] = security.decrypt_text(v)
            except Exception:  # noqa: BLE001
                pass
    return r


@router.get("")
async def list_events(
    host: Optional[str] = None,
    type: Optional[str] = None,
    scene: Optional[str] = None,
    label: Optional[str] = None,
    limit: int = Query(50, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    _: str = Depends(get_current_token),
) -> dict:
    where_sql = " WHERE 1=1"
    conds: list = []
    params: list = []
    if host:
        conds.append("host=?"); params.append(host)
    if type:
        conds.append("type=?"); params.append(type)
    if scene:
        conds.append("scene=?"); params.append(scene)
    if label:
        conds.append("label=?"); params.append(label)
    if conds:
        where_sql += " AND " + " AND ".join(conds)
    total = fetch_all(f"SELECT COUNT(*) AS c FROM events{where_sql}", tuple(params))[0]["c"]
    rows = fetch_all(f"SELECT * FROM events{where_sql} ORDER BY ts LIMIT ? OFFSET ?",
                     tuple(params + [limit, offset]))
    return {
        "code": 0, "message": "ok",
        "data": {
            "items": [_decrypt_event(dict(r)) for r in rows],
            "total": total,
        },
    }


@router.post("/batch")
async def batch_events(req: BatchRequest, _: str = Depends(get_current_token)) -> dict:
    """按事件 ID 批量查询（证据列表按需拉取，替代全表扫描）。"""
    ids = list(dict.fromkeys(req.ids[:500]))  # 去重 + 上限
    if not ids:
        return {"code": 0, "message": "ok", "data": {"items": []}}
    placeholders = ",".join("?" * len(ids))
    rows = fetch_all(f"SELECT * FROM events WHERE event_id IN ({placeholders})", tuple(ids))
    return {"code": 0, "message": "ok", "data": {"items": [_decrypt_event(dict(r)) for r in rows]}}
