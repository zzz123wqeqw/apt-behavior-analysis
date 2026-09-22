# -*- coding: utf-8 -*-
"""B4 流水线编排。

解析 → 预筛 → (逐案例) 行为识别 → 情报增强(可选) → 溯源 → 误报过滤 → 报告 → 图谱。
输入：模拟数据（data/events.json）或真实数据集（OTRF NDJSON 路径）。
"""
import json
import logging
from pathlib import Path
from typing import List, Optional

from app.core.config import settings
from app.core.database import execute, init_db, save_json_table, utcnow
from app.core.security import encrypt_text
from app.models.event import Event
from app.services.attribution import attribution_service
from app.services.detector import detector
from app.services.enricher import enricher
from app.services.expander import expander
from app.services.filter import filter_engine
from app.services.graph_builder import graph_builder
from app.services.parser import parser
from app.services.prefilter import prefilter
from app.services.report import report_service

logger = logging.getLogger(__name__)


class Pipeline:
    """研判流水线。"""

    def run(
        self,
        scene: Optional[str] = None,
        data_file: Optional[str] = None,
        use_intel: bool = True,
    ) -> List[str]:
        init_db(settings.db_path)
        self._reset()
        events = self._load_events(data_file, scene)
        self._save_events(events)

        cases = prefilter.aggregate(events)
        self._save_cases(cases)
        logger.info("预筛产出 %d 个可疑案例", len(cases))

        report_ids: List[str] = []
        for case in cases:
            try:
                rid = self._process_case(case, events, use_intel)
                if rid:
                    report_ids.append(rid)
            except Exception as e:  # noqa: BLE001
                logger.exception("案例 %s 处理失败: %s", case.case_id, e)
        return report_ids

    # ---------- 步骤 ----------

    @staticmethod
    def _reset() -> None:
        """清空分析表，保证全流程从干净状态开始。"""
        for t in ("enrichments", "graph", "reports", "cases", "events", "ioc_cache"):
            execute(f"DELETE FROM {t}")

    def _load_events(self, data_file: Optional[str], scene: Optional[str]) -> List[Event]:
        """加载事件：优先真实数据集文件，否则模拟数据（可按场景过滤）。

        安全：data_file 仅允许项目数据目录内的文件（防任意文件读取）。
        """
        if data_file:
            path = Path(data_file).resolve()
            allowed = [
                Path(settings.data_dir).resolve(),
                (Path(settings.data_dir).parent / "uploads").resolve(),
                (Path(settings.data_dir).parent.parent / "datasets").resolve(),
            ]
            if not any(path.is_relative_to(base) for base in allowed if base.exists()):
                logger.warning("拒绝越权数据文件: %s", path)
                raise ValueError(f"data_file 超出允许目录: {path}")
            if path.exists():
                logger.info("使用数据文件: %s", path)
                return parser.parse_file(path)
        sim = Path(settings.data_dir) / "events.json"
        if not sim.exists():
            import data_gen
            data_gen.generate()
        events = parser.parse_file(sim)
        if scene:
            events = [e for e in events if e.scene == scene]
            logger.info("按场景 %s 过滤后 %d 条", scene, len(events))
        return events

    @staticmethod
    def _save_events(events: List[Event]) -> None:
        for e in events:
            row = e.model_dump()
            for f in ("src_ip", "dst_ip", "domain", "file_hash"):
                if row.get(f):
                    row[f] = encrypt_text(row[f])
            save_json_table("events", "event_id", row)

    @staticmethod
    def _save_cases(cases) -> None:
        for c in cases:
            save_json_table("cases", "case_id", {
                "case_id": c.case_id, "host": c.host,
                "window_start": c.window_start, "window_end": c.window_end,
                "suspicious_score": c.suspicious_score,
                "hit_rules": c.hit_rules, "status": "pending",
            })

    def _process_case(self, case, events: List[Event], use_intel: bool) -> Optional[str]:
        ev_map = {e.event_id: e for e in events}
        case_events = [ev_map[i] for i in case.events if i in ev_map]

        # 1. 行为识别
        behaviors = detector.detect(case, case_events)
        # 2. 情报增强（可选）
        enrichments = enricher.enrich_report(case, case_events) if use_intel else []
        # 3. 溯源（注入情报支撑）
        attribution = attribution_service.attribute(case, behaviors, enrichments)
        # 4. 误报过滤
        status, risk = filter_engine.apply(case, behaviors, attribution, enrichments)
        # 5. 报告
        report = report_service.build(
            case, behaviors, attribution, status, risk, case_events, enrichments,
        )
        # 6. 图谱（扩线资产挂接，仅对恶意/可疑 IOC 优先扩线，最多 3 个）
        expand_results = []
        if use_intel:
            malicious = {e.ioc for e in enrichments if e.verdict in ("恶意", "可疑")}
            targets = [s for s in report.scope if s["type"] in ("ip", "domain")]
            picked = [t for t in targets if t["value"] in malicious][:3]
            if len(picked) < 3:
                picked += [t for t in targets if t["value"] not in malicious][:3 - len(picked)]
            for s in picked:
                expand_results.extend(expander.expand(s["value"], s["type"], limit=5))
        graph_builder.build(report, enrichments, expand_results)
        logger.info("案例 %s 报告完成: %s/%s org=%s", case.case_id, status, risk,
                    attribution.org if attribution else "")
        return report.report_id


pipeline = Pipeline()
