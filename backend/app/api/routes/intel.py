# -*- coding: utf-8 -*-
"""情报平台路由（§15）。

GET  /api/intel        单点情报查询（聚合 VT/微步）
POST /api/enrich       对指定案例 IOC 批量情报增强
POST /api/expand       对指定 IOC 进行 FOFA 资产扩线
GET  /api/enrichments  查询增强结果
"""
from typing import Optional

from pydantic import BaseModel
from fastapi import APIRouter, Depends

from app.api.deps import get_current_token
from app.core import security
from app.core.database import fetch_all, fetch_one
from app.services.enricher import enricher
from app.services.expander import expander
from app.services.intel.fofa_client import fofa_client
from app.services.intel.threatbook_client import threatbook_client
from app.services.intel.vt_client import vt_client

router = APIRouter(prefix="/api", tags=["intel"])


class EnrichRequest(BaseModel):
    report_id: str
    force: bool = False


class ExpandRequest(BaseModel):
    ioc: str
    ioc_type: str  # ip / domain
    limit: int = 10


@router.get("/intel")
async def query_intel(
    ioc: str,
    ioc_type: str = "ip",
    _: str = Depends(get_current_token),
) -> dict:
    """单点情报查询（聚合 VT/微步/FOFA 参考）。"""
    results = []
    for client in (vt_client, threatbook_client):
        try:
            r = client.query(ioc, ioc_type)
        except Exception as e:  # noqa: BLE001
            r = {"available": False, "reason": str(e), "platform": getattr(client, "platform", "?")}
        results.append(r)
    fofa_ref = fofa_client.query(ioc, ioc_type)
    return {
        "code": 0, "message": "ok",
        "data": {"ioc": ioc, "ioc_type": ioc_type, "platforms": results, "fofa": fofa_ref,
                 "disclaimer": "平台判定仅供参考，请人工复核"},
    }


@router.post("/enrich")
async def enrich(req: EnrichRequest, _: str = Depends(get_current_token)) -> dict:
    """对指定案例 IOC 批量增强。"""
    import json
    row = fetch_one("SELECT events FROM cases WHERE case_id=?", (req.report_id,))
    if not row:
        return {"code": 1, "message": "案例不存在", "data": None}
    eids = json.loads(row["events"] or "[]")
    ev_rows = fetch_all("SELECT * FROM events WHERE event_id IN (%s)" % ",".join("?" * len(eids)), tuple(eids))
    events = []
    for r in ev_rows:
        d = dict(r)
        for f in ("src_ip", "dst_ip", "domain", "file_hash"):
            v = d.get(f)
            if v:
                try:
                    d[f] = security.decrypt_text(v)
                except Exception:  # noqa: BLE001
                    pass
        events.append(d)
    return {"code": 0, "message": "ok", "data": {"items": [e.model_dump() for e in enricher.enrich_report(None, events)]}}


@router.post("/expand")
async def expand(req: ExpandRequest, _: str = Depends(get_current_token)) -> dict:
    """FOFA 资产扩线。"""
    items = expander.expand(req.ioc, req.ioc_type, limit=req.limit)
    return {"code": 0, "message": "ok", "data": {"items": items}}


@router.get("/enrichments")
async def list_enrichments(
    report_id: Optional[str] = None,
    ioc: Optional[str] = None,
    platform: Optional[str] = None,
    _: str = Depends(get_current_token),
) -> dict:
    where, params = " WHERE 1=1", []
    if report_id:
        where += " AND report_id=?"
        params.append(report_id)
    if ioc:
        where += " AND ioc LIKE ?"
        params.append(f"%{ioc}%")
    if platform:
        where += " AND platform=?"
        params.append(platform)
    rows = fetch_all(f"SELECT * FROM enrichments{where} ORDER BY score DESC LIMIT 100", tuple(params))
    items = []
    for r in rows:
        d = dict(r)
        try:
            d["ioc"] = security.decrypt_text(d["ioc"])
        except Exception:  # noqa: BLE001
            pass
        try:
            d["source_url"] = security.decrypt_text(d["source_url"])
        except Exception:  # noqa: BLE001
            pass
        items.append(d)
    return {"code": 0, "message": "ok", "data": {"items": items}}
