# -*- coding: utf-8 -*-
"""API 依赖（骨架）：Token 鉴权。"""
from fastapi import Header, HTTPException

from app.core import security


def get_current_token(authorization: str = Header(default="")) -> str:
    """校验 Authorization: Bearer <token>（课设级，骨架）。"""
    token = authorization.removeprefix("Bearer ").strip()
    if not security.check_token(token):
        raise HTTPException(status_code=401, detail="无效或缺失 API Token")
    return token
