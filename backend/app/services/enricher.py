# -*- coding: utf-8 -*-
"""B13 情报增强（enricher）。

对案例/报告 IOC 批量查询 VT + 微步，生成 Enrichment 列表：
- 落库 enrichments（ioc 加密）
- 生成"情报支撑"Prompt 注入行（供 attribution 使用）
- 平台不可用自动降级，不中断流水线
"""
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

from app.core.database import save_json_table, utcnow
from app.core.security import encrypt_text
from app.models.case import Case
from app.models.enrichment import Enrichment
from app.models.event import Event
from app.services.intel.fofa_client import fofa_client
from app.services.intel.threatbook_client import threatbook_client
from app.services.intel.vt_client import vt_client

logger = logging.getLogger(__name__)

PROMPT_VERDICTS = ("恶意", "可疑")


class Enricher:
    """IOC 情报增强服务。"""

    def extract_iocs(self, case: Optional[Case], events: List, limit: int = 10) -> List[Dict]:
        """从案例事件提取 IOC：{ioc, ioc_type}，按频次排序截断。

        事件可为 Event 对象或 dict（路由层解密后传入）。
        """
        ev_map = {e.event_id: e for e in events if hasattr(e, "event_id")}
        cnt: Dict[str, int] = {}
        eids = case.events if case else [getattr(e, "event_id", None) for e in events]
        for eid in eids:
            e = ev_map.get(eid)
            if e is None:
                e = eid  # dict 事件
            domain = getattr(e, "domain", None) if not isinstance(e, dict) else e.get("domain")
            dst_ip = getattr(e, "dst_ip", None) if not isinstance(e, dict) else e.get("dst_ip")
            if domain and not domain.endswith((".local", ".corp", ".lan")):
                cnt[domain.lower()] = cnt.get(domain.lower(), 0) + 1
            if dst_ip and not dst_ip.startswith(("10.", "192.168.", "172.")):
                cnt[dst_ip] = cnt.get(dst_ip, 0) + 1
        ordered = sorted(cnt.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{"ioc": k, "ioc_type": ("domain" if "." in k and not k.replace(".", "").isdigit() else "ip")}
                for k, _ in ordered]

    def enrich_report(self, case: Case, events: List[Event], force: bool = False) -> List[Enrichment]:
        """对案例 IOC 做多平台情报查询（并发，各平台独立限速）。"""
        iocs = self.extract_iocs(case, events)

        def _query_one(item: Dict) -> List[Enrichment]:
            out: List[Enrichment] = []
            for client in (vt_client, threatbook_client):
                try:
                    res = client.query(item["ioc"], item["ioc_type"])
                except Exception as e:  # noqa: BLE001
                    logger.warning("查询异常 %s: %s", item["ioc"], e)
                    continue
                if not res.get("available"):
                    continue
                out.append(Enrichment(
                    enrichment_id=f"en_{item['ioc']}_{client.platform}",
                    report_id=None,
                    ioc=item["ioc"],
                    ioc_type=item["ioc_type"],
                    platform=client.platform,
                    verdict=res.get("verdict", "未知"),
                    score=float(res.get("score", 0.0)),
                    family=res.get("family") or None,
                    tags=res.get("tags", ""),
                    detail=res.get("detail", ""),
                    source_url=res.get("source_url", ""),
                    queried_at=res.get("queried_at", utcnow()),
                ))
            return out

        out: List[Enrichment] = []
        workers = min(max(int(settings.intel_concurrency), 1), 3)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for batch in ex.map(_query_one, iocs):
                out.extend(batch)
        self._save(out, case.case_id)
        return out

    @staticmethod
    def _save(items: List[Enrichment], case_id: str) -> None:
        for e in items:
            save_json_table("enrichments", "enrichment_id", {
                "enrichment_id": e.enrichment_id,
                "report_id": case_id,
                "ioc": encrypt_text(e.ioc),
                "ioc_type": e.ioc_type,
                "platform": e.platform,
                "verdict": e.verdict,
                "score": e.score,
                "family": e.family,
                "tags": e.tags,
                "detail": e.detail,
                "source_url": encrypt_text(e.source_url),
                "queried_at": e.queried_at,
                "cited": 0,
            })

    @staticmethod
    def to_prompt_lines(enrichments: List[Enrichment], limit: int = 8) -> str:
        """压缩为 Prompt 注入行（每条一行，供溯源注入）。"""
        lines = []
        for e in enrichments:
            if e.verdict not in PROMPT_VERDICTS:
                continue
            parts = [f"{e.ioc}", f"{e.platform}[{e.verdict}]", f"评分{e.score}"]
            if e.family:
                parts.append(f"家族/{e.family}")
            if e.tags:
                parts.append(f"标签:{e.tags[:40]}")
            lines.append("- " + " ".join(parts))
            if len(lines) >= limit:
                break
        return "\n".join(lines) or "（无外部情报支撑，请仅基于行为特征研判）"


enricher = Enricher()
