# -*- coding: utf-8 -*-
"""B8 报告生成。

生成结构化研判报告：行为/归因/影响范围/时间线/处置建议，
敏感字段（IP/域名/Hash）加密落库，HMAC-SHA256 签名保证完整性。
"""
import json
import logging
from typing import Dict, List, Optional

from app.core import security
from app.core.database import utcnow, execute, fetch_one
from app.models.case import Case
from app.models.enrichment import Enrichment
from app.models.event import Event
from app.models.report import Attribution, Behavior, Recommendation, Report

logger = logging.getLogger(__name__)

# 处置建议模板（按行为类型）
BLOCK_TIPS = {
    "long_term_latency": ["封禁外联 C2 IP/域名", "隔离受影响主机", "切断低频 beacon 回连"],
    "lateral_movement": ["封禁源主机对 445/WMI 端口的出方向连接", "隔离被控主机", "重置横向移动涉及的账户口令"],
    "hidden_channel": ["封禁高熵子域/隧道域名", "拦截异常 DNS 请求", "阻断异常端口外连"],
    "trace_cleaning": ["限制 wevtutil 等清理工具执行", "恢复日志服务", "启动日志集中采集"],
}
CLEAN_TIPS = {
    "long_term_latency": ["清除持久化项（计划任务/服务/启动项）", "删除恶意脚本与文件"],
    "lateral_movement": ["终止 wmic/psexec 等异常进程", "清理新增账户与计划任务"],
    "hidden_channel": ["清除隧道进程", "删除持久化载荷"],
    "trace_cleaning": ["修复事件日志配置", "删除攻击工具残留"],
}
TRACE_TIPS = {
    "long_term_latency": ["提取 C2 通信样本与 IOC", "保全长期行为时间线"],
    "lateral_movement": ["提取横向移动路径与凭证使用记录", "全网排查同类 IOC"],
    "hidden_channel": ["提取隧道流量 pcap", "关联其他主机 DNS 日志"],
    "trace_cleaning": ["从集中日志平台恢复被删日志", "取证清理工具执行痕迹"],
}


class ReportService:
    """研判报告服务。"""

    def build(
        self,
        case: Case,
        behaviors: List[Behavior],
        attribution: Attribution,
        final_status: str,
        risk_level: str,
        events: List[Event],
        enrichments: List[Enrichment] = None,
    ) -> Report:
        enrichments = enrichments or []
        scope = self._scope(case, events)
        timeline = self._timeline(case, events)
        rec = Recommendation(
            block=self._dedup([t for b in behaviors for t in BLOCK_TIPS.get(b.type, [])]),
            clean=self._dedup([t for b in behaviors for t in CLEAN_TIPS.get(b.type, [])]),
            trace=self._dedup([t for b in behaviors for t in TRACE_TIPS.get(b.type, [])]),
        )
        report = Report(
            report_id=f"rep_{case.case_id}",
            created_at=utcnow(),
            case_id=case.case_id,
            behaviors=behaviors,
            attribution=attribution,
            risk_level=risk_level,
            scope=scope,
            timeline=timeline,
            recommendations=rec,
            status=final_status,
        )
        report.signature = self._sign(report)
        self._save(report, enrichments)
        return report

    # ---------- 组装 ----------

    @staticmethod
    def _scope(case: Case, events: List[Event]) -> List[dict]:
        ev_map = {e.event_id: e for e in events}
        hosts, ips, domains = set(), set(), set()
        for eid in case.events:
            e = ev_map.get(eid)
            if not e:
                continue
            if e.host:
                hosts.add(e.host)
            if e.dst_ip:
                ips.add(e.dst_ip)
            if e.src_ip:
                ips.add(e.src_ip)
            if e.domain:
                domains.add(e.domain)
        scope = (
            [{"type": "host", "value": h} for h in sorted(hosts)]
            + [{"type": "ip", "value": ip} for ip in sorted(ips)]
            + [{"type": "domain", "value": d} for d in sorted(domains)]
        )
        return scope[:50]

    @staticmethod
    def _timeline(case: Case, events: List[Event]) -> List[dict]:
        ev_map = {e.event_id: e for e in events}
        items = []
        for eid in case.events[:100]:
            e = ev_map.get(eid)
            if not e:
                continue
            items.append({
                "ts": e.ts, "type": e.type.value, "process": e.process,
                "dst_ip": e.dst_ip, "domain": e.domain, "action": e.action,
            })
        items.sort(key=lambda x: x["ts"])
        return items

    @staticmethod
    def _dedup(items: List[str]) -> List[str]:
        seen = set()
        return [x for x in items if not (x in seen or seen.add(x))]

    # ---------- 签名 ----------

    @staticmethod
    def _canonical(report: Report) -> str:
        return json.dumps({
            "case_id": report.case_id,
            "behaviors": [b.model_dump() for b in report.behaviors],
            "attribution": report.attribution.model_dump() if report.attribution else {},
            "risk_level": report.risk_level,
            "status": report.status,
            "scope": report.scope,
            "timeline": report.timeline,
            "recommendations": report.recommendations.model_dump() if report.recommendations else {},
        }, ensure_ascii=False, sort_keys=True)

    @classmethod
    def _sign(cls, report: Report) -> str:
        return security.sign_report(report.report_id, cls._canonical(report))

    # ---------- 落库 ----------

    @staticmethod
    def _enc_if_sensitive(payload: str, scope_types: tuple) -> str:
        """含敏感字段（ip/domain/hash）时整段加密。"""
        if any(t in scope_types for t in ("ip", "domain")):
            return security.encrypt_text(payload)
        return payload

    def _save(self, report: Report, enrichments: List[Enrichment]) -> None:
        scope_types = tuple(s["type"] for s in report.scope)
        timeline_types = ("ip", "domain")
        enc_scope = self._enc_if_sensitive(json.dumps(report.scope, ensure_ascii=False), scope_types)
        enc_timeline = self._enc_if_sensitive(json.dumps(report.timeline, ensure_ascii=False), timeline_types)

        from app.core.database import save_json_table
        save_json_table("reports", "report_id", {
            "report_id": report.report_id,
            "case_id": report.case_id,
            "created_at": report.created_at,
            "risk_level": report.risk_level,
            "status": report.status,
            "behaviors_json": [b.model_dump() for b in report.behaviors],
            "attribution_json": report.attribution.model_dump() if report.attribution else {},
            "scope_json": enc_scope,
            "timeline_json": enc_timeline,
            "recommendations_json": report.recommendations.model_dump() if report.recommendations else {},
            "enrichments_json": [e.model_dump() for e in enrichments],
            "signature": report.signature,
        })
        # 案例状态回写
        execute("UPDATE cases SET final_status=?, status='processed' WHERE case_id=?",
                (report.status, report.case_id))

    # ---------- 读取与校验 ----------

    def get(self, report_id: str) -> Optional[Report]:
        row = fetch_one(
            "SELECT * FROM reports WHERE report_id=?", (report_id,))
        if not row:
            return None

        def _decrypt_field(raw: Optional[str], is_json: bool = True):
            """兼容：加密串（非 JSON 前缀）解密，明文 JSON 直接解析。"""
            if not raw:
                return [] if is_json else ""
            try:
                if not raw.lstrip().startswith("["):
                    raw = security.decrypt_text(raw)
            except Exception:  # noqa: BLE001
                pass
            return json.loads(raw) if is_json else raw

        scope = _decrypt_field(row["scope_json"])
        timeline = _decrypt_field(row["timeline_json"])
        report = Report(
            report_id=row["report_id"],
            created_at=row["created_at"],
            case_id=row["case_id"] or "",
            behaviors=[Behavior(**b) for b in json.loads(row["behaviors_json"])],
            attribution=Attribution(**json.loads(row["attribution_json"])),
            risk_level=row["risk_level"],
            scope=scope,
            timeline=timeline,
            recommendations=Recommendation(**json.loads(row["recommendations_json"])),
            status=row["status"],
            signature=row["signature"],
        )
        return report

    def verify(self, report_id: str) -> dict:
        report = self.get(report_id)
        if not report:
            return {"valid": False, "reason": "not_found"}
        recomputed = self._sign(report)
        return {"valid": security.verify(f"{report.report_id}|{self._canonical(report)}", report.signature),
                "recomputed": recomputed}

    def list(self, risk_level: Optional[str] = None, status: Optional[str] = None,
             org: Optional[str] = None, limit: int = 50, offset: int = 0) -> List[Dict]:
        from app.core.database import fetch_all
        sql = "SELECT * FROM reports WHERE 1=1"
        params: list = []
        if risk_level:
            sql += " AND risk_level=?"
            params.append(risk_level)
        if status:
            sql += " AND status=?"
            params.append(status)
        if org:
            sql += " AND attribution_json LIKE ?"
            params.append(f"%{org}%")
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        rows = fetch_all(sql, tuple(params))
        return [{
            "report_id": r["report_id"], "created_at": r["created_at"],
            "risk_level": r["risk_level"], "status": r["status"],
            "org": (json.loads(r["attribution_json"]) or {}).get("org", ""),
        } for r in rows]


report_service = ReportService()
