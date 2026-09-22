# -*- coding: utf-8 -*-
"""GET /api/graph 知识图谱。"""
from typing import Optional

from fastapi import APIRouter, Depends

from app.api.deps import get_current_token
from app.services.graph_builder import graph_builder

router = APIRouter(prefix="/api/graph", tags=["graph"])


@router.get("")
async def get_graph(
    report_id: Optional[str] = None,
    _: str = Depends(get_current_token),
) -> dict:
    graph = graph_builder.get(report_id)
    return {"code": 0, "message": "ok", "data": graph.model_dump()}
