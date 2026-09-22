# -*- coding: utf-8 -*-
"""POST /api/search 组合检索。"""
from typing import Optional

from pydantic import BaseModel
from fastapi import APIRouter, Depends

from app.api.deps import get_current_token
from app.api.routes.events import _decrypt_event
from app.core.database import fetch_all

router = APIRouter(prefix="/api/search", tags=["search"])


class SearchRequest(BaseModel):
    keyword: str
    search_type: Optional[str] = "all"  # event/case/report/all
    limit: int = 20


@router.post("")
async def search(req: SearchRequest, _: str = Depends(get_current_token)) -> dict:
    kw = req.keyword.strip().lower()
    result: dict = {}

    if req.search_type in ("event", "all"):
        # 敏感字段加密存储：先全量取出，解密后内存匹配
        hits = []
        for r in fetch_all("SELECT * FROM events ORDER BY ts DESC LIMIT 2000"):
            d = _decrypt_event(dict(r))
            blob = " ".join(str(v).lower() for v in d.values() if v is not None)
            if kw in blob:
                hits.append(d)
                if len(hits) >= req.limit:
                    break
        result["events"] = hits

    if req.search_type in ("case", "all"):
        result["cases"] = [dict(r) for r in fetch_all(
            "SELECT * FROM cases WHERE host LIKE ? ORDER BY suspicious_score DESC LIMIT ?",
            (f"%{kw}%", req.limit))]

    if req.search_type in ("report", "all"):
        result["reports"] = [dict(r) for r in fetch_all(
            "SELECT * FROM reports WHERE attribution_json LIKE ? OR report_id LIKE ? "
            "ORDER BY created_at DESC LIMIT ?",
            (f"%{kw}%", f"%{kw}%", req.limit))]

    return {"code": 0, "message": "ok", "data": result}
