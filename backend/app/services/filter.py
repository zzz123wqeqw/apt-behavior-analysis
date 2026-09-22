# -*- coding: utf-8 -*-
"""B7 误报过滤。

多条件交叉校验：
- 证据校验：行为引用的有效事件数 >= min_evidence，不足则降级
- 置信度门限：>=0.8 确认 / >=0.6 待复核 / 更低或证据不足 -> 误报或复核
- 规则交叉：LLM 行为类型与预筛 hit_rules 一致性（有交集加分）
- 情报一致性：微步判定与归因组织关键词匹配加分
"""
import logging
from typing import List, Tuple

from app.core.config import settings
from app.models.case import Case
from app.models.enrichment import Enrichment
from app.models.report import Attribution, Behavior

logger = logging.getLogger(__name__)

CONFIRM = 0.8
REVIEW = 0.6

# 风险等级权重
RISK_WEIGHT = {
    "long_term_latency": 2,
    "lateral_movement": 3,
    "hidden_channel": 3,
    "trace_cleaning": 2,
}


class Filter:
    """误报过滤模块。"""

    def apply(
        self,
        case: Case,
        behaviors: List[Behavior],
        attribution: Attribution,
        enrichments: List[Enrichment] = None,
    ) -> Tuple[str, str]:
        """返回 (final_status, risk_level)。"""
        enrichments = enrichments or []
        if not behaviors:
            return "误报", "低"

        # 证据校验：过滤掉证据不足的行为
        valid = [
            b for b in behaviors
            if len(b.evidence) >= settings.min_evidence
        ]
        if not valid:
            # 全部证据不足：规则已命中 -> 待复核（保守）；规则也未命中 -> 判误报
            return ("误报" if not case.hit_rules else "待复核"), self._risk_level(behaviors, attribution)

        max_conf = max(b.confidence for b in valid)

        # 规则交叉一致性
        hit_set = set(case.hit_rules)
        type_set = {b.type for b in valid}
        overlap = len(hit_set & type_set)

        # 情报一致性加分（微步家族关键词命中画像组织名）
        intel_boost = 0.0
        if attribution.org and attribution.org != "疑似未知组织":
            org_kw = attribution.org.lower().replace(" ", "")
            for e in enrichments:
                if e.verdict in ("恶意", "可疑") and org_kw in (e.family or "").lower():
                    intel_boost = 0.05

        if max_conf >= CONFIRM and overlap >= 1:
            status = "确认"
        elif max_conf >= REVIEW:
            status = "确认" if overlap >= 1 else "待复核"
        else:
            status = "待复核"

        # 情报强证据：高评分恶意 IOC 且行为置信度达复核线 -> 直接确认
        # （防止情报平台误报污染：仅当行为层面已有一定置信度时才升级）
        if enrichments and max(e.score for e in enrichments) >= 85 and max_conf >= REVIEW:
            status = "确认"

        risk = self._risk_level(valid, attribution, intel_boost)
        logger.info("案例 %s -> %s / %s (max_conf=%.2f overlap=%d)", case.case_id, status, risk, max_conf, overlap)
        return status, risk

    @staticmethod
    def _risk_level(behaviors: List[Behavior], attribution: Attribution, boost: float = 0.0) -> str:
        """风险等级：行为权重和 + 组织确认度。"""
        w = sum(RISK_WEIGHT.get(b.type, 1) for b in behaviors if b.confidence >= 0.6)
        if attribution.org_confidence >= 0.7:
            w += 1
        w += boost * 10
        if w >= 8:
            return "严重"
        if w >= 6:
            return "高"
        if w >= 3:
            return "中"
        return "低"


filter_engine = Filter()
