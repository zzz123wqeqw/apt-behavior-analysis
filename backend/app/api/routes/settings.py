# -*- coding: utf-8 -*-
"""密钥配置：GET /api/settings 状态 + POST /api/settings/keys 保存（加密、热更新）。"""
from typing import Optional

from pydantic import BaseModel
from fastapi import APIRouter, Depends

from app.api.deps import get_current_token
from app.core.config import settings
from app.core.llm_client import llm_client

router = APIRouter(prefix="/api/settings", tags=["settings"])


class KeysRequest(BaseModel):
    deepseek_api_key: Optional[str] = None
    vt_api_key: Optional[str] = None
    threatbook_api_key: Optional[str] = None
    fofa_api_key: Optional[str] = None


def _refresh_intel_keys() -> None:
    """密钥保存后同步各情报客户端单例。"""
    from app.services.intel.fofa_client import fofa_client
    from app.services.intel.threatbook_client import threatbook_client
    from app.services.intel.vt_client import vt_client
    vt_client.api_key = settings.vt_api_key
    threatbook_client.api_key = settings.threatbook_api_key
    fofa_client.api_key = settings.fofa_api_key


@router.get("")
async def get_settings(_: str = Depends(get_current_token)) -> dict:
    from app.services.intel.fofa_client import fofa_client
    from app.services.intel.threatbook_client import threatbook_client
    from app.services.intel.vt_client import vt_client
    return {"code": 0, "message": "ok", "data": {
        "keys": settings.key_status(),
        "llm": {"available": llm_client.available, "model": settings.llm_model,
                "mode": "api" if llm_client.available else "fallback"},
        "intel": {
            "virustotal": vt_client.available(),
            "threatbook": threatbook_client.available(),
            "fofa": fofa_client.available(),
        },
    }}


@router.post("/keys")
async def save_keys(req: KeysRequest, _: str = Depends(get_current_token)) -> dict:
    settings.save_keys({
        "llm_api_key": req.deepseek_api_key,
        "vt_api_key": req.vt_api_key,
        "threatbook_api_key": req.threatbook_api_key,
        "fofa_api_key": req.fofa_api_key,
    })
    llm_client.reload()
    _refresh_intel_keys()
    return {"code": 0, "message": "密钥已保存并生效", "data": settings.key_status()}
