# -*- coding: utf-8 -*-
"""B13 资产扩线（expander）。

对确认恶意 IOC 调 FOFA 查询关联资产（同证书/同IP/同指纹），
返回候选资产列表，供图谱挂接与人工复核。
"""
import logging
from typing import List

from app.services.intel.fofa_client import fofa_client

logger = logging.getLogger(__name__)


class Expander:
    """FOFA 资产扩线服务。"""

    def expand(self, ioc: str, ioc_type: str, limit: int = 10) -> List[dict]:
        """扩线查询。返回项：{asset, ip, port, protocol, cert, relation, source}"""
        if not fofa_client.available():
            return []
        results = fofa_client.expand(ioc, ioc_type, limit=limit)
        for r in results:
            r["query"] = ioc
        logger.info("IOC %s 扩线得到 %d 条资产", ioc, len(results))
        return results


expander = Expander()
