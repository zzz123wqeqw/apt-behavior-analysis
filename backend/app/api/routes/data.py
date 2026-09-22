# -*- coding: utf-8 -*-
"""数据源管理：GET /api/data/sources 列表 + POST /api/data/upload 上传。

数据源类型：
- sim    内置模拟数据（data/events.json，3 场景混合）
- real   OTRF 真实事件日志（datasets/atomic/**）
- upload 用户上传（data/uploads/*）
切换数据 = 前端取 source.path 传入 /api/analyze 的 data_file。
"""
import json
import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, File, UploadFile

from app.api.deps import get_current_token
from app.core.config import settings

router = APIRouter(prefix="/api/data", tags=["data"])

BACKEND_DIR = Path(settings.data_dir).parent  # backend/
UPLOAD_DIR = BACKEND_DIR / "data" / "uploads"
DATASETS_DIR = BACKEND_DIR.parent / "datasets" / "atomic"

BIG_FILE = 10 * 1024 * 1024  # >10MB 不做完整解析
MAX_UPLOAD = 50 * 1024 * 1024  # 上传上限 50MB
ALLOWED_EXT = {".json", ".ndjson", ".csv", ".txt"}


def _quick_count(path: Path) -> int:
    """轻量统计事件条数（避免全量解析大文件）。"""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(4096)
        s = head.lstrip()
        if s.startswith("["):
            if path.stat().st_size > BIG_FILE:
                return -1
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return len(json.load(f))
        if s.startswith("{"):
            # 单 JSON 对象（OTRF 单条）或 NDJSON（逐行对象）
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    json.load(f)
                return 1
            except (ValueError, OSError):
                return sum(1 for line in open(path, "r", encoding="utf-8", errors="ignore") if line.strip())
        # CSV / 其他：数非空行减表头
        lines = sum(1 for line in open(path, "r", encoding="utf-8", errors="ignore") if line.strip())
        return max(lines - 1, 0)
    except Exception:  # noqa: BLE001
        return -1


def _source(sid: str, name: str, stype: str, path: Path, desc: str) -> dict:
    return {
        "id": sid, "name": name, "type": stype,
        "path": str(path), "count": _quick_count(path),
        "size_kb": round(path.stat().st_size / 1024, 1), "desc": desc,
    }


def _list_otrf() -> list:
    out = []
    if not DATASETS_DIR.exists():
        return out
    for f in sorted(DATASETS_DIR.rglob("*.json")):
        scene = f.parent.name
        out.append(_source(
            f"real:{scene}:{f.stem[:24]}", f"{scene} / {f.stem[:40]}",
            "real", f,
            f"OTRF 真实事件日志（{scene} 场景）",
        ))
    return out


def _list_uploads() -> list:
    out = []
    if not UPLOAD_DIR.exists():
        return out
    for f in sorted(UPLOAD_DIR.glob("*")):
        if f.is_file():
            out.append(_source(
                f"upload:{f.stem}", f.name, "upload", f, "用户上传数据",
            ))
    return out


@router.get("/sources")
async def list_sources(_: str = Depends(get_current_token)) -> dict:
    sim_path = Path(settings.data_dir) / "events.json"
    sources = []
    if sim_path.exists():
        sources.append(_source("sim:default", "内置模拟数据（3 场景混合）",
                               "sim", sim_path, "钓鱼+C2潜伏 / SMB横向移动 / DNS隧道+清痕，含正常噪声"))
    sources += _list_otrf()
    sources += _list_uploads()
    return {"code": 0, "message": "ok", "data": {"items": sources, "total": len(sources)}}


@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    _: str = Depends(get_current_token),
) -> dict:
    """上传数据文件（JSON / NDJSON / CSV / 文本），保存至 data/uploads/。"""
    name = Path(file.filename or "upload.json").name  # 防路径穿越
    if Path(name).suffix.lower() not in ALLOWED_EXT:
        return {"code": 1, "message": "不支持的文件类型，仅允许 .json/.ndjson/.csv/.txt", "data": None}
    # 大小限制（边读边校验）
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOAD_DIR / name
    size = 0
    with open(dest, "wb") as f:
        while chunk := file.file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD:
                f.close()
                dest.unlink(missing_ok=True)
                return {"code": 1, "message": "文件超过 50MB 上限", "data": None}
            f.write(chunk)
    return {"code": 0, "message": "ok", "data": _source(
        f"upload:{dest.stem}", name, "upload", dest, "用户上传数据")}
