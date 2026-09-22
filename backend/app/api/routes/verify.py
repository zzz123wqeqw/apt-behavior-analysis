# -*- coding: utf-8 -*-
"""GET /api/verify/{report_id} 报告完整性校验。"""
from fastapi import APIRouter, Depends

from app.api.deps import get_current_token
from app.services.report import report_service

router = APIRouter(prefix="/api/verify", tags=["verify"])


@router.get("/{report_id}")
async def verify_report(report_id: str, _: str = Depends(get_current_token)) -> dict:
    result = report_service.verify(report_id)
    return {"code": 0, "message": "ok", "data": result}
