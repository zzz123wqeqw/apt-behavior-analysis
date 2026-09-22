# -*- coding: utf-8 -*-
"""B6 溯源研判。

结合组织画像库（RAG-lite 检索）与情报增强结果，LLM 推理：
攻击组织 / 攻击路径 / 入侵入口 / 目标意图。
- 无匹配组织时输出"疑似未知组织"，禁止编造。
- LLM 不可用 → 直接使用 RAG-lite Top1 匹配结果兜底。
"""
import json
import logging
from pathlib import Path
from typing import Dict, List

from app.core.config import settings
from app.core.llm_client import llm_client
from app.models.case import Case
from app.models.enrichment import Enrichment
from app.models.report import Attribution, Behavior

logger = logging.getLogger(__name__)


class AttributionService:
    """LLM 溯源研判服务。"""

    def __init__(self) -> None:
        self.profiles = self.load_profiles(Path(settings.profiles_file))

    def load_profiles(self, path: Path) -> dict:
        if not path.exists():
            return {"apts": []}
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    # ---------- RAG-lite ----------

    def rag_lite(self, behaviors: List[Behavior], keywords: List[str] = None) -> List[dict]:
        """按行为类型+关键词检索 Top3 组织画像。"""
        btypes = {b.type for b in behaviors}
        kws = [k.lower() for k in (keywords or [])]
        scored: List[tuple] = []
        for apt in self.profiles.get("apts", []):
            s = 0
            # 行为类型匹配（画像 behaviors 中文名 ↔ 行为 key）
            name_map = {
                "long_term_latency": "长期潜伏", "lateral_movement": "内网横向移动",
                "hidden_channel": "隐蔽数据传输", "trace_cleaning": "痕迹清理",
            }
            for bt in btypes:
                if name_map.get(bt) in apt.get("behaviors", []):
                    s += 2
            # 关键词/工具/手法匹配
            hay = " ".join(apt.get("keywords", []) + apt.get("tools", []) + apt.get("ttps", []))
            for kw in kws:
                if kw and kw in hay.lower():
                    s += 1
            if s > 0:
                scored.append((s, apt))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [apt for _, apt in scored[:3]]

    # ---------- 溯源 ----------

    def attribute(
        self,
        case: Case,
        behaviors: List[Behavior],
        enrichments: List[Enrichment] = None,
    ) -> Attribution:
        enrichments = enrichments or []
        # 用行为+情报家族关键词做 RAG-lite
        kws = [e.family for e in enrichments if e.family] + [e.tags for e in enrichments if e.tags]
        top_profiles = self.rag_lite(behaviors, kws)

        if llm_client.available:
            attr = self._llm_attribute(case, behaviors, top_profiles, enrichments)
            if attr.org:
                return attr
        return self._rule_fallback(case, behaviors, top_profiles)

    def _llm_attribute(
        self,
        case: Case,
        behaviors: List[Behavior],
        top_profiles: List[dict],
        enrichments: List[Enrichment],
    ) -> Attribution:
        system = (
            "你是一名威胁情报专家。根据行为识别结果、外部情报支撑与组织画像，研判攻击组织。\n"
            "规则：1) 只输出 JSON：{org, org_confidence, path:[步骤], entry, intent, reasoning}；"
            "2) 画像库无匹配时 org 填\"疑似未知组织\"且 org_confidence<=0.3，禁止编造；"
            "3) reasoning 需引用证据（行为/情报条目）；4) 情报平台判定仅供参考，与行为矛盾时以行为为主。"
        )
        intel_lines = "\n".join(
            f"- {e.ioc}：{e.platform}[{e.verdict}] 评分{e.score} {e.family or ''} {e.tags}"
            for e in enrichments[:8] if e.verdict in ("恶意", "可疑")
        ) or "（无外部情报支撑，请仅基于行为特征研判）"
        user = (
            f"案件摘要：host={case.host}，窗口 {case.window_start}~{case.window_end}\n"
            f"行为识别结果：{json.dumps([b.model_dump() for b in behaviors], ensure_ascii=False)}\n"
            f"【情报支撑】（微步/VT，查询时间见报告）\n{intel_lines}\n"
            f"候选组织画像（Top{len(top_profiles)}）：\n{json.dumps(top_profiles, ensure_ascii=False)}"
        )
        out = llm_client.generate_json(system, user)
        return Attribution(
            org=str(out.get("org", "")),
            org_confidence=float(out.get("org_confidence", 0.0)),
            path=[str(x) for x in out.get("path", [])],
            entry=str(out.get("entry", "")),
            intent=str(out.get("intent", "")),
            reasoning=str(out.get("reasoning", ""))[:500],
        )

    @staticmethod
    def _rule_fallback(case: Case, behaviors: List[Behavior], top_profiles: List[dict]) -> Attribution:
        """规则兜底：RAG-lite Top1 直接作为结论。"""
        if not top_profiles:
            return Attribution(
                org="疑似未知组织", org_confidence=0.25,
                path=[], entry="未知", intent="待评估",
                reasoning="画像库无匹配（规则兜底），建议结合外部情报人工研判。",
            )
        apt = top_profiles[0]
        bnames = "、".join(b.name for b in behaviors) or "无明显行为"
        return Attribution(
            org=apt["name"],
            org_confidence=0.6,
            path=apt.get("ttps", [])[:5],
            entry=apt.get("ttps", ["未知"])[0],
            intent=f"针对{('、'.join(apt.get('targets', [])[:3]))}领域（画像库匹配，规则兜底）",
            reasoning=f"行为({bnames})与画像库组织 {apt['name']} 的 TTP/工具匹配，结合外部情报可进一步确认。",
        )


attribution_service = AttributionService()
