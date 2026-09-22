# -*- coding: utf-8 -*-
"""POST /api/analyze 全流程触发。"""
from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import get_current_token
from app.models.report import AnalyzeRequest
from app.services.pipeline import pipeline

router = APIRouter(prefix="/api/analyze", tags=["analyze"])


@router.post("")
async def run_analyze(
    req: AnalyzeRequest,
    _: str = Depends(get_current_token),
) -> dict:
    """运行研判流水线，返回 report_id 列表。"""
    try:
        report_ids = pipeline.run(
            scene=req.scene, data_file=req.data_file, use_intel=req.use_intel,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"code": 0, "message": "ok", "data": {"report_ids": report_ids, "count": len(report_ids)}}
