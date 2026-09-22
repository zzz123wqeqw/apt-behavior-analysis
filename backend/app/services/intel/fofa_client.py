# -*- coding: utf-8 -*-
"""FOFA 客户端。

用途：资产扩线——同证书/同IP/同指纹查询关联资产。
API: https://fofa.info/api/v1/search/all?key=&qbase64=&fields=&size=
"""
import base64
import logging
from typing import Dict, List

import httpx

from app.core.config import settings
from app.services.intel.base import BaseIntelClient, rate_limiter

logger = logging.getLogger(__name__)


class FofaClient(BaseIntelClient):
    platform = "fofa"

    def __init__(self) -> None:
        self.api_key = settings.fofa_api_key
        self.base_url = "https://fofa.info/api/v1/search/all"

    def query(self, ioc: str, ioc_type: str) -> Dict:
        results = self.expand(ioc, ioc_type, limit=5)
        return {
            "available": self.available(),
            "platform": self.platform, "ioc": ioc,
            "verdict": "参考" if results else "未知",
            "score": 0.0,
            "detail": f"查询到 {len(results)} 条关联资产",
            "source_url": f"https://fofa.info/result?qbase64={self._q(ioc, ioc_type)}",
        }

    def expand(self, ioc: str, ioc_type: str, limit: int = 10) -> List[dict]:
        if not self.available():
            return []
        rate_limiter.wait()
        q = f'domain="{ioc}"' if ioc_type == "domain" else f'ip="{ioc}"'
        try:
            resp = httpx.get(
                self.base_url,
                params={"key": self.api_key, "qbase64": self._b64(q),
                        "fields": "host,ip,port,protocol,cert", "size": limit},
                timeout=25,
            )
            resp.raise_for_status()
            body = resp.json()
            if body.get("error"):
                logger.warning("FOFA 错误: %s", body.get("errmsg"))
                return []
            return [
                {"asset": r[0], "ip": r[1], "port": r[2], "protocol": r[3],
                 "cert": (r[4] or "")[:80], "relation": "同IP/同域名资产", "source": "fofa"}
                for r in body.get("results", [])[:limit]
            ]
        except Exception as e:  # noqa: BLE001
            logger.warning("FOFA 扩线失败 %s: %s", ioc, e)
            return []

    @staticmethod
    def _b64(s: str) -> str:
        return base64.b64encode(s.encode("utf-8")).decode("utf-8")

    def _q(self, ioc: str, ioc_type: str) -> str:
        return self._b64(f'domain="{ioc}"' if ioc_type == "domain" else f'ip="{ioc}"')


fofa_client = FofaClient()
