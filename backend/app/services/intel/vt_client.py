# -*- coding: utf-8 -*-
"""VirusTotal 客户端。

用途：IP/域名信誉、DNS↔IP 互查、检测结果。
API: https://www.virustotal.com/api/v3/{ip_addresses|domains}/{ioc}
"""
import logging
from typing import Dict

import httpx

from app.core.config import settings
from app.core.database import utcnow
from app.services.intel.base import BaseIntelClient, CachedClientMixin, make_rate_limiter

logger = logging.getLogger(__name__)

VERDICT_MAP = {"malicious": "恶意", "suspicious": "可疑", "harmless": "正常", "undetected": "未知"}

vt_rate_limiter = make_rate_limiter(1.0)


class VTClient(BaseIntelClient, CachedClientMixin):
    platform = "virustotal"

    def __init__(self) -> None:
        self.api_key = settings.vt_api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def query(self, ioc: str, ioc_type: str) -> Dict:
        if not self.available():
            return {"available": False, "reason": "no_api_key", "platform": self.platform}
        cached = self.cache_get(ioc)
        if cached:
            return cached
        vt_rate_limiter.wait()
        segment = "ip_addresses" if ioc_type == "ip" else "domains"
        try:
            resp = httpx.get(
                f"{self.base_url}/{segment}/{ioc}",
                headers={"x-apikey": self.api_key},
                timeout=20,
            )
            if resp.status_code == 404:
                out = {"available": True, "platform": self.platform, "ioc": ioc,
                       "verdict": "未知", "score": 0.0, "detail": "VT 无该 IOC 记录",
                       "source_url": f"https://www.virustotal.com/gui/{segment[:-1]}/{ioc}", "queried_at": utcnow()}
                self.cache_set(ioc, out)
                return out
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            total = sum(stats.values()) or 1
            mal = stats.get("malicious", 0) + stats.get("suspicious", 0)
            verdict = VERDICT_MAP.get("malicious" if stats.get("malicious", 0) > 0 else
                                      ("suspicious" if stats.get("suspicious", 0) > 0 else
                                       ("harmless" if stats.get("harmless", 0) > 0 else "undetected")), "未知")
            out = {
                "available": True, "platform": self.platform, "ioc": ioc,
                "verdict": verdict, "score": round(mal / total * 100, 1),
                "detail": f"恶意引擎 {stats.get('malicious',0)}/{total}，可疑 {stats.get('suspicious',0)}",
                "source_url": f"https://www.virustotal.com/gui/{segment[:-1]}/{ioc}",
                "queried_at": utcnow(),
            }
            self.cache_set(ioc, out)
            return out
        except Exception as e:  # noqa: BLE001
            logger.warning("VT 查询失败 %s: %s", ioc, e)
            return {"available": False, "reason": str(e), "platform": self.platform}


vt_client = VTClient()
