# -*- coding: utf-8 -*-
"""APT 研判系统后端入口（骨架）。

运行：
    cd backend
    pip install -r requirements.txt
    python -m uvicorn main:app --reload --port 8000
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import (
    analyze, cases, data, events, features, graph, intel,
    llm, profiles, reports, search, stats, verify,
)
from app.api.routes import settings as settings_router
from app.core.config import settings
from app.core.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """启动时初始化数据库。"""
    init_db(settings.database.path if hasattr(settings, "database") else settings.db_path)
    yield


app = FastAPI(
    title="APT 研判系统 API",
    description="面向APT攻击的大模型行为特征识别与研判研究（课设）",
    version="0.1.0",
    lifespan=lifespan,
)


# 前后端分离：允许前端 dev 地址跨域
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
for router in (
    analyze.router, events.router, cases.router, reports.router,
    graph.router, stats.router, search.router, features.router,
    profiles.router, verify.router, intel.router,
    data.router, settings_router.router, llm.router,
):
    app.include_router(router)


@app.get("/api/health")
def health() -> dict:
    return {"code": 0, "message": "ok", "data": {"status": "alive"}}
