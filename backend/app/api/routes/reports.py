# -*- coding: utf-8 -*-
"""GET /api/reports 报告查询。"""
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.api.deps import get_current_token
from app.services.report import report_service

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("")
async def list_reports(
    risk_level: Optional[str] = None,
    status: Optional[str] = None,
    org: Optional[str] = None,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _: str = Depends(get_current_token),
) -> dict:
    items = report_service.list(risk_level, status, org, limit, offset)
    return {"code": 0, "message": "ok", "data": {"items": items, "total": len(items) + offset}}


@router.get("/{report_id}")
async def get_report(report_id: str, _: str = Depends(get_current_token)) -> dict:
    report = report_service.get(report_id)
    if not report:
        return {"code": 1, "message": "not_found", "data": None}
    return {"code": 0, "message": "ok", "data": report.model_dump()}
