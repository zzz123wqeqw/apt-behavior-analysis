# -*- coding: utf-8 -*-
"""情报客户端基类。

- BaseIntelClient：统一 query 接口 + 限速
- CachedClientMixin：SQLite ioc_cache 缓存（TTL 内命中，省免费额度）
"""
import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Dict, Optional

from app.core.config import settings
from app.core.database import execute, fetch_one, utcnow

logger = logging.getLogger(__name__)


class BaseIntelClient(ABC):
    """情报平台客户端基类。"""

    platform: str = "base"
    api_key: str = ""

    @abstractmethod
    def query(self, ioc: str, ioc_type: str) -> Dict:
        """查询单个 IOC，返回统一结果 dict。"""
        raise NotImplementedError

    def available(self) -> bool:
        return bool(self.api_key)


class CachedClientMixin:
    """SQLite 缓存混入。"""

    platform: str = "base"

    def cache_get(self, ioc: str) -> Optional[Dict]:
        key = f"{self.platform}:{ioc}"
        row = fetch_one("SELECT payload_json, queried_at FROM ioc_cache WHERE cache_key=?", (key,))
        if not row:
            return None
        try:
            from datetime import datetime, timezone
            q = datetime.fromisoformat(row["queried_at"])
            age_h = (datetime.now(timezone.utc) - q).total_seconds() / 3600
        except Exception:  # noqa: BLE001
            age_h = 999
        if age_h > settings.intel_cache_ttl_hours:
            return None
        try:
            return json.loads(row["payload_json"])
        except Exception:  # noqa: BLE001
            return None

    def cache_set(self, ioc: str, payload: Dict) -> None:
        key = f"{self.platform}:{ioc}"
        execute(
            "INSERT OR REPLACE INTO ioc_cache (cache_key, payload_json, queried_at) VALUES (?,?,?)",
            (key, json.dumps(payload, ensure_ascii=False), utcnow()),
        )


class RateLimiter:
    """简单限速器（跨实例单进程可用）。"""

    def __init__(self, per_sec: float = 1.0):
        self.interval = 1.0 / max(per_sec, 0.1)
        self._last = 0.0
        self._lock = None

    def wait(self) -> None:
        # 线程安全（供 enricher 并发查询多线程调用）
        import threading
        if self._lock is None:
            self._lock = threading.Lock()
        now = time.time()
        with self._lock:
            gap = now - self._last
            if gap < self.interval:
                time.sleep(self.interval - gap)
            self._last = time.time()


# 各平台独立限速（并发查询时不互相拖慢）
def make_rate_limiter(per_sec: float = 1.0) -> RateLimiter:
    return RateLimiter(per_sec)


rate_limiter = RateLimiter(settings.intel_rate_per_sec)
