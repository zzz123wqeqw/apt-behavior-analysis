# -*- coding: utf-8 -*-
"""GET/PUT /api/features 特征库热更新。"""
import json
from pathlib import Path
from typing import Dict

from fastapi import APIRouter, Depends

from app.api.deps import get_current_token
from app.core.config import settings
from app.services.prefilter import prefilter

router = APIRouter(prefix="/api/features", tags=["features"])


@router.get("")
async def get_features(_: str = Depends(get_current_token)) -> dict:
    return {"code": 0, "message": "ok", "data": prefilter.features}


@router.put("")
async def update_features(payload: Dict, _: str = Depends(get_current_token)) -> dict:
    """覆盖特征规则库并热重载。"""
    if "behaviors" not in payload:
        return {"code": 1, "message": "缺少 behaviors 字段", "data": None}
    with open(settings.features_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    prefilter.load_features(Path(settings.features_file))
    return {"code": 0, "message": "ok", "data": prefilter.features}
