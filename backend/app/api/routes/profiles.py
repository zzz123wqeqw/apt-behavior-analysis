# -*- coding: utf-8 -*-
"""GET/PUT /api/profiles 组织画像库。"""
import json
from pathlib import Path
from typing import Dict

from fastapi import APIRouter, Depends

from app.api.deps import get_current_token
from app.core.config import settings
from app.services.attribution import attribution_service

router = APIRouter(prefix="/api/profiles", tags=["profiles"])


@router.get("")
async def get_profiles(_: str = Depends(get_current_token)) -> dict:
    return {"code": 0, "message": "ok", "data": attribution_service.profiles}


@router.put("")
async def update_profiles(payload: Dict, _: str = Depends(get_current_token)) -> dict:
    """覆盖画像库并热重载。"""
    if "apts" not in payload:
        return {"code": 1, "message": "缺少 apts 字段", "data": None}
    with open(settings.profiles_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    attribution_service.load_profiles(Path(settings.profiles_file))
    return {"code": 0, "message": "ok", "data": attribution_service.profiles}
