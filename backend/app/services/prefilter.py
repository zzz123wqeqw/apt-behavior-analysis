# -*- coding: utf-8 -*-
"""B3 特征规则库与预筛。

按 features.json 规则对事件打分，按主机+时间窗聚合为可疑案例 Case：
- 事件级规则：匹配字段规则给行为加分（domain_entropy/hour 等派生字段即时计算）
- 聚合级规则：distinct_dst_ip_count / beacon_interval_stable 在窗口内统计
- 行为得分 >= threshold 即命中，Case.suspicious_score 为总得分
"""
import json
import math
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from statistics import pstdev
from typing import Dict, List, Optional

from app.core.config import settings
from app.models.case import Case
from app.models.event import Event


def domain_entropy(domain: str) -> float:
    """子域熵：取域名第一个标签（host 标签）计算字符分布熵。

    DNS 隧道常见高熵随机子域（如 12 位 hex），正常业务子域熵低。
    """
    if not domain:
        return 0.0
    label = domain.split(".")[0]
    n = len(label)
    if n == 0:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in Counter(label).values())


def _hour_of(ts: str) -> int:
    try:
        return int(datetime.fromisoformat(ts).hour)
    except Exception:  # noqa: BLE001
        return 0


def _field_value(event: Event, field: str):
    """取事件字段（含派生字段）。"""
    if field == "domain_entropy":
        return domain_entropy(event.domain or "")
    if field == "hour":
        return _hour_of(event.ts)
    if field == "type":
        return event.type.value
    return getattr(event, field, None)


def _match_rule(event: Event, rule: dict) -> bool:
    """单条规则匹配。"""
    val = _field_value(event, rule["field"])
    op, target = rule["op"], rule["value"]
    if op == "eq":
        return val == target
    if op == "gte":
        try:
            return float(val or 0) >= float(target)
        except (TypeError, ValueError):
            return False
    if op == "between":
        try:
            return float(target[0]) <= float(val) <= float(target[1])
        except (TypeError, ValueError):
            return False
    if op == "in":
        # 子串匹配（进程名带 .exe 后缀等）
        return any(t.lower() in str(val or "").lower() for t in target)
    if op == "contains":
        return any(t.lower() in str(val or "").lower() for t in target)
    return False


class Prefilter:
    """规则预筛引擎。"""

    def __init__(self) -> None:
        self.features: Dict = self.load_features(Path(settings.features_file))

    def load_features(self, path: Path) -> Dict:
        if not path.exists():
            return {"behaviors": {}}
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def score_event(self, event: Event) -> Dict[str, float]:
        """单事件按规则打分：{behavior_key: 得分}。"""
        scores: Dict[str, float] = defaultdict(float)
        for bkey, bcfg in self.features.get("behaviors", {}).items():
            for rule in bcfg.get("event_rules", []):
                if _match_rule(event, rule):
                    scores[bkey] += float(rule.get("weight", 1))
        return dict(scores)

    def aggregate(self, events: List[Event], window_minutes: Optional[int] = None) -> List[Case]:
        """按主机+时间窗聚合可疑事件为 Case。"""
        wm = window_minutes or settings.window_minutes
        by_host: Dict[str, List[Event]] = defaultdict(list)
        for e in events:
            by_host[e.host or "unknown"].append(e)
        for h in by_host:
            by_host[h].sort(key=lambda e: e.ts)

        cases: List[Case] = []
        for host, evts in by_host.items():
            for window in self._windows(evts, wm):
                case = self._build_case(host, window)
                if case.suspicious_score > 0:
                    cases.append(case)
        cases.sort(key=lambda c: c.suspicious_score, reverse=True)
        return cases[: 50]

    @staticmethod
    def _windows(events: List[Event], window_minutes: int,
                 merge_gap_minutes: int = 60) -> List[List[Event]]:
        """按时间窗切分（首个事件起 window_minutes 一个窗口）。

        相邻窗口首尾间隔 <= merge_gap_minutes 时合并，避免长期潜伏
        （低频 beacon 跨多窗口）被切成多个冗余案例。
        """
        windows: List[List[Event]] = []
        cur: List[Event] = []
        cur_start: Optional[float] = None
        for e in events:
            try:
                t = datetime.fromisoformat(e.ts).timestamp()
            except Exception:  # noqa: BLE001
                continue
            if cur_start is None:
                cur_start = t
            if t - cur_start > window_minutes * 60:
                if cur:
                    windows.append(cur)
                cur, cur_start = [], t
            cur.append(e)
        if cur:
            windows.append(cur)

        # 合并相邻窗口（间隔 <= merge_gap 分钟）
        merged: List[List[Event]] = []
        for w in windows:
            if merged:
                try:
                    prev_end = datetime.fromisoformat(merged[-1][-1].ts).timestamp()
                    cur_start = datetime.fromisoformat(w[0].ts).timestamp()
                except Exception:  # noqa: BLE001
                    prev_end, cur_start = 0, 0
                if cur_start - prev_end <= merge_gap_minutes * 60:
                    merged[-1].extend(w)
                    continue
            merged.append(w)
        return merged

    @staticmethod
    def _beacon_stable(evts: List[Event]) -> bool:
        """同目标低频 flow 间隔是否稳定（beacon 特征）。

        要求：同 dst 的 flow >= 6 条，平均间隔 > 10 分钟（低频），
        且间隔变异系数 < 0.4（规律性）。
        """
        flows = [e for e in evts if e.type.value == "flow" and e.dst_ip]
        if len(flows) < 6:
            return False
        by_dst: Dict[str, List[float]] = defaultdict(list)
        for e in flows:
            try:
                by_dst[e.dst_ip].append(datetime.fromisoformat(e.ts).timestamp())
            except Exception:  # noqa: BLE001
                continue
        for dst, ts in by_dst.items():
            ts.sort()
            gaps = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
            if len(gaps) < 5:
                continue
            mean = sum(gaps) / len(gaps)
            if mean > 600 and pstdev(gaps) / mean < 0.4:  # 低频且规律
                return True
        return False

    @staticmethod
    def _max_internal_dst_in_window(evts: List[Event], sub_minutes: int = 30) -> int:
        """任意 sub_minutes 滑动子窗口内 distinct 内网目标数的最大值。

        横向移动等爆发型行为不应跨长时间窗累计（低频 beacon 的零星内网
        连接会被排除，避免误报）。
        """
        pts: List[tuple] = []
        for e in evts:
            try:
                t = datetime.fromisoformat(e.ts).timestamp()
            except Exception:  # noqa: BLE001
                continue
            ip = e.dst_ip or ""
            if ip.startswith(("10.", "192.168.", "172.")):
                pts.append((t, ip))
        pts.sort()
        best = 0
        for i, (t0, _) in enumerate(pts):
            cnt = len({ip for t, ip in pts if t0 <= t <= t0 + sub_minutes * 60})
            if cnt > best:
                best = cnt
        return best

    def _build_case(self, host: str, evts: List[Event]) -> Case:
        """对窗口内事件打分并生成 Case。"""
        total = 0.0
        hit: List[str] = []
        for bkey, bcfg in self.features.get("behaviors", {}).items():
            score = 0.0
            for e in evts:
                for rule in bcfg.get("event_rules", []):
                    if _match_rule(e, rule):
                        score += float(rule.get("weight", 1))
            # 聚合规则
            internal_dsts = self._max_internal_dst_in_window(evts)
            for rule in bcfg.get("agg_rules", []):
                f, op, target, w = rule["field"], rule["op"], rule["value"], rule.get("weight", 1)
                if f == "distinct_dst_ip_count" and op == "gte" and internal_dsts >= int(target):
                    score += float(w)
                if f == "beacon_interval_stable" and target is True and self._beacon_stable(evts):
                    score += float(w)
            if score >= float(bcfg.get("threshold", 3)):
                hit.append(bkey)
                total += score

        return Case(
            case_id=f"case_{host}_{evts[0].ts[:16].replace(':', '')}",
            host=host,
            window_start=evts[0].ts,
            window_end=evts[-1].ts,
            events=[e.event_id for e in evts][:300],
            suspicious_score=round(total, 2),
            hit_rules=hit,
        )


prefilter = Prefilter()
