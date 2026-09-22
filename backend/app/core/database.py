# -*- coding: utf-8 -*-
"""SQLite 存储层。

表：events / cases / reports / enrichments / graph / ioc_cache
敏感列加密（security.encrypt_text 加密，读取后解密展示）。
"""
import sqlite3
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    type TEXT,
    src_ip TEXT, src_port INTEGER,
    dst_ip TEXT, dst_port INTEGER,
    domain TEXT, process TEXT, parent_process TEXT,
    file_path TEXT, file_hash TEXT,
    action TEXT, user TEXT, host TEXT,
    scene TEXT, label TEXT
);
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    host TEXT, window_start TEXT, window_end TEXT,
    suspicious_score REAL, hit_rules TEXT, status TEXT,
    behaviors_json TEXT, attribution_json TEXT, final_status TEXT
);
CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    case_id TEXT,
    created_at TEXT, risk_level TEXT, status TEXT,
    behaviors_json TEXT, attribution_json TEXT,
    scope_json TEXT, timeline_json TEXT,
    recommendations_json TEXT, enrichments_json TEXT,
    signature TEXT
);
CREATE TABLE IF NOT EXISTS enrichments (
    enrichment_id TEXT PRIMARY KEY,
    report_id TEXT, ioc TEXT, ioc_type TEXT, platform TEXT,
    verdict TEXT, score REAL, family TEXT, tags TEXT,
    detail TEXT, source_url TEXT, queried_at TEXT, cited INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS graph (
    graph_id TEXT PRIMARY KEY,
    created_at TEXT, nodes_json TEXT, edges_json TEXT
);
CREATE TABLE IF NOT EXISTS ioc_cache (
    cache_key TEXT PRIMARY KEY,
    payload_json TEXT, queried_at TEXT
);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def init_db(db_path: str = "data/apt.db") -> None:
    """初始化数据库与表（含旧库列兼容迁移）。"""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA)
        # 兼容：旧 reports 表补 case_id 列
        cols = {r[1] for r in conn.execute("PRAGMA table_info(reports)").fetchall()}
        if "case_id" not in cols:
            conn.execute("ALTER TABLE reports ADD COLUMN case_id TEXT")


@contextmanager
def get_conn(db_path: Optional[str] = None):
    """获取数据库连接。"""
    from app.core.config import settings as _s
    conn = sqlite3.connect(db_path or _s.db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# ---------- 通用查询 ----------

def fetch_all(sql: str, params: tuple = ()) -> List[Dict]:
    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


def fetch_one(sql: str, params: tuple = ()) -> Optional[Dict]:
    with get_conn() as conn:
        row = conn.execute(sql, params).fetchone()
        return dict(row) if row else None


def execute(sql: str, params: tuple = ()) -> None:
    with get_conn() as conn:
        conn.execute(sql, params)
        conn.commit()


def save_json_table(table: str, primary_key: str, row: Dict[str, Any]) -> None:
    """按 dict 插入或更新（自动序列化 dict/list 字段）。"""
    cols, vals = [], []
    for k, v in row.items():
        cols.append(k)
        if isinstance(v, (dict, list)):
            vals.append(json.dumps(v, ensure_ascii=False))
        else:
            vals.append(v)
    placeholders = ", ".join("?" for _ in cols)
    updates = ", ".join(f"{c}=excluded.{c}" for c in cols if c != primary_key)
    sql = (
        f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders}) "
        f"ON CONFLICT({primary_key}) DO UPDATE SET {updates}"
    )
    with get_conn() as conn:
        conn.execute(sql, vals)
        conn.commit()
