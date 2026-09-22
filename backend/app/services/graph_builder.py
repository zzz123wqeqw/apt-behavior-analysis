# -*- coding: utf-8 -*-
"""B9 知识图谱构建。

由研判结果自动构建图谱：
- 节点：APT组织 / 攻击行为 / 手法TTP / IP / 域名 / 案例 / 目标领域 / 疑似关联资产
- 边：使用 / 涉及 / 具备 / 利用 / 关联 / 针对
- 扩线资产节点 marked confirmed=False（前端虚线展示）
"""
import json
import logging
import re
from typing import Dict, List, Optional

from app.core.database import utcnow, save_json_table, fetch_one
from app.models.enrichment import Enrichment
from app.models.graph import GraphEdge, GraphNode, KnowledgeGraph
from app.models.report import Report

logger = logging.getLogger(__name__)

NODE_COLORS = {
    "apt": "#d4380d", "behavior": "#096dd9", "ttp": "#722ed1",
    "ip": "#389e0d", "domain": "#13c2c2", "case": "#8c8c8c",
    "target": "#eb2f96", "asset": "#faad14",
}


class GraphBuilder:
    """知识图谱构建器。"""

    def build(
        self,
        report: Report,
        enrichments: List[Enrichment] = None,
        expand_results: List[dict] = None,
    ) -> KnowledgeGraph:
        enrichments = enrichments or []
        expand_results = expand_results or []
        nodes: Dict[str, GraphNode] = {}
        edges: List[GraphEdge] = []
        apt_name = (report.attribution.org if report.attribution else "") or "疑似未知组织"

        def add_node(nid: str, label: str, ntype: str, props: Optional[dict] = None) -> None:
            if nid not in nodes:
                nodes[nid] = GraphNode(id=nid, label=label, type=ntype, props=props or {})

        def add_edge(src: str, dst: str, rel: str, w: float = 1.0) -> None:
            if src in nodes and dst in nodes:
                edges.append(GraphEdge(source=src, target=dst, relation=rel, weight=w))

        # 1. 组织 + 案例 + 行为节点
        add_node("apt:" + apt_name, apt_name, "apt", {"region": self._region_of(apt_name)})
        add_node("case:" + report.case_id, report.case_id, "case", {"risk": report.risk_level})
        add_edge("case:" + report.case_id, "apt:" + apt_name, "涉及", 1.0)
        for b in report.behaviors:
            bkey = f"{b.type}:{report.case_id}"
            add_node(bkey, b.name, "behavior", {"confidence": round(b.confidence, 2)})
            add_edge("case:" + report.case_id, bkey, "具备", b.confidence)

        # 2. 目标领域
        intent = (report.attribution.intent if report.attribution else "") or ""
        if intent:
            add_node("target:" + intent[:12], intent[:12], "target", {})
            add_edge("apt:" + apt_name, "target:" + intent[:12], "针对", 1.0)

        # 3. IOC 节点（来自 scope）
        for s in report.scope:
            if s["type"] == "ip":
                nid = "ip:" + s["value"]
                add_node(nid, s["value"], "ip", {})
                add_edge("apt:" + apt_name, nid, "关联", 0.8)
            elif s["type"] == "domain":
                nid = "domain:" + s["value"]
                add_node(nid, s["value"], "domain", {})
                add_edge("apt:" + apt_name, nid, "关联", 0.8)

        # 4. 情报增强：家族/平台标签 -> 手法节点
        for e in enrichments:
            if e.verdict not in ("恶意", "可疑"):
                continue
            fam = e.family or ""
            if fam and re.search(r"[A-Za-z0-9]", fam):
                nid = "ttp:" + fam
                add_node(nid, fam, "ttp", {"source": e.platform})
                add_edge("apt:" + apt_name, nid, "使用", 0.7)
                # 情报 IOC 挂到组织
                ioc_nid = ("domain:" + e.ioc) if e.ioc_type == "domain" else ("ip:" + e.ioc)
                add_node(ioc_nid, e.ioc, e.ioc_type, {"intel": e.platform})
                add_edge("apt:" + apt_name, ioc_nid, "关联", 0.9)

        # 5. 扩线资产（confirmed=False 虚线）
        for a in expand_results[:10]:
            nid = "asset:" + a.get("asset", "")
            add_node(nid, a.get("asset", ""), "asset", {
                "confirmed": False, "relation": a.get("relation", ""),
                "ip": a.get("ip", ""), "port": a.get("port", ""),
            })
            add_edge("domain:" + a.get("query", ""), nid, "关联", 0.5)

        graph = KnowledgeGraph(nodes=list(nodes.values()), edges=edges)
        self._save(graph, report.report_id)
        return graph

    @staticmethod
    def _region_of(org: str) -> str:
        from app.services.attribution import attribution_service
        for apt in attribution_service.profiles.get("apts", []):
            if apt["name"] == org:
                return apt.get("region", "")
        return ""

    @staticmethod
    def _save(graph: KnowledgeGraph, report_id: str) -> None:
        # 图谱节点含 IOC（IP/域名）明文 -> 加密落库
        from app.core.security import encrypt_text
        save_json_table("graph", "graph_id", {
            "graph_id": f"g_{report_id}",
            "created_at": utcnow(),
            "nodes_json": encrypt_text(json.dumps([n.model_dump() for n in graph.nodes], ensure_ascii=False)),
            "edges_json": json.dumps([e.model_dump() for e in graph.edges], ensure_ascii=False),
        })

    def get(self, report_id: Optional[str] = None) -> KnowledgeGraph:
        """读取图谱：指定报告或全局聚合（最新 N 张合并）。"""
        from app.core.database import fetch_all
        if report_id:
            row = fetch_one("SELECT * FROM graph WHERE graph_id=?", (f"g_{report_id}",))
            if row:
                return KnowledgeGraph(
                    nodes=[GraphNode(**n) for n in _loads(row["nodes_json"])],
                    edges=[GraphEdge(**e) for e in _loads(row["edges_json"])],
                )
            return KnowledgeGraph()
        rows = fetch_all("SELECT * FROM graph ORDER BY created_at DESC LIMIT 5")
        nodes: Dict[str, GraphNode] = {}
        edges: List[GraphEdge] = []
        seen: List[dict] = []
        for r in rows:
            for n in _loads(r["nodes_json"]):
                nodes[n["id"]] = GraphNode(**n)
            for e in _loads(r["edges_json"]):
                if not any(e["source"] == x["source"] and e["target"] == x["target"] and e["relation"] == x["relation"] for x in seen):
                    seen.append(e)
                    edges.append(GraphEdge(**e))
        return KnowledgeGraph(nodes=list(nodes.values()), edges=edges)


def _loads(s: str) -> list:
    import json
    # 兼容：加密串（非 JSON 前缀）先解密
    try:
        if s and not s.lstrip().startswith(("[", "{")):
            from app.core.security import decrypt_text
            s = decrypt_text(s)
        return json.loads(s) or []
    except Exception:  # noqa: BLE001
        return []


graph_builder = GraphBuilder()
