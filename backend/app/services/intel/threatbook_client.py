# -*- coding: utf-8 -*-
"""微步威胁情报客户端。

用途：IP/域名恶意判定、威胁类型、家族信息（供溯源 Prompt 注入）。
API: https://api.threatbook.cn/v3/scene/{ip_reputation|dns}
"""
import logging
from typing import Dict

import httpx

from app.core.config import settings
from app.core.database import utcnow
from app.services.intel.base import BaseIntelClient, CachedClientMixin, make_rate_limiter

logger = logging.getLogger(__name__)

VERDICT_ID = {"0": "未知", "1": "正常", "2": "可疑", "3": "恶意"}

tb_rate_limiter = make_rate_limiter(1.0)


class ThreatBookClient(BaseIntelClient, CachedClientMixin):
    platform = "threatbook"

    def __init__(self) -> None:
        self.api_key = settings.threatbook_api_key
        self.base_url = "https://api.threatbook.cn/v3/scene"

    def query(self, ioc: str, ioc_type: str) -> Dict:
        if not self.available():
            return {"available": False, "reason": "no_api_key", "platform": self.platform}
        cached = self.cache_get(ioc)
        if cached:
            return cached
        tb_rate_limiter.wait()
        scene = "ip_reputation" if ioc_type == "ip" else "dns"
        try:
            resp = httpx.post(
                f"{self.base_url}/{scene}",
                params={"apikey": self.api_key, "resource": ioc},
                timeout=20,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            verdict = VERDICT_ID.get(str(data.get("verdict_id", "0")), "未知")
            severity = data.get("severity", 0) or 0
            out = {
                "available": True, "platform": self.platform, "ioc": ioc,
                "verdict": verdict,
                "score": round(float(severity) * 25, 1),
                "family": (data.get("family", []) or [""])[0] if isinstance(data.get("family"), list) else data.get("family"),
                "tags": ",".join(data.get("tags", []) or [])[:100],
                "detail": str(data.get("summary", ""))[:200],
                "source_url": "https://x.threatbook.com/v5/",
                "queried_at": utcnow(),
            }
            self.cache_set(ioc, out)
            return out
        except Exception as e:  # noqa: BLE001
            logger.warning("微步查询失败 %s: %s", ioc, e)
            return {"available": False, "reason": str(e), "platform": self.platform}


threatbook_client = ThreatBookClient()
