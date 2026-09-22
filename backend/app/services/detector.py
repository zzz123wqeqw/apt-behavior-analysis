# -*- coding: utf-8 -*-
"""B5 行为识别。

对可疑案例做 LLM 深度行为识别，输出行为标签 + 置信度 + 证据事件 ID。
四类行为：long_term_latency / lateral_movement / hidden_channel / trace_cleaning
- LLM 不可用/解析失败 → 基于预筛 hit_rules 的规则兜底（保证可演示）
"""
import json
import logging
from typing import Dict, List, Optional

from app.core.llm_client import llm_client
from app.models.case import Case
from app.models.event import Event
from app.models.report import Behavior

logger = logging.getLogger(__name__)

BEHAVIOR_DEFS = {
    "long_term_latency": "长期潜伏：低频规律回连、凌晨活动、长会话、持久化",
    "lateral_movement": "内网横向移动：445/SMB 批量连接、WMI/PsExec 远程执行、同源多目标",
    "hidden_channel": "隐蔽数据传输：DNS 隧道高熵子域、异常端口外连、低频长连接",
    "trace_cleaning": "痕迹清理：wevtutil 清日志、文件删除、时间戳篡改",
}

MAX_EVENTS_IN_PROMPT = 60


def _compact_event(e: Event) -> dict:
    """精简事件字段（控制 token）。"""
    return {
        "id": e.event_id,
        "t": e.ts[11:19],
        "type": e.type.value,
        "sip": e.src_ip, "dip": e.dst_ip,
        "dport": e.dst_port, "domain": e.domain,
        "proc": e.process, "pproc": e.parent_process,
        "file": e.file_path, "act": e.action,
    }


class Detector:
    """LLM 行为识别引擎。"""

    def detect(self, case: Case, events: List[Event]) -> List[Behavior]:
        """识别案例行为。"""
        ev_map: Dict[str, Event] = {e.event_id: e for e in events}
        window = [ev_map[i] for i in case.events if i in ev_map][:MAX_EVENTS_IN_PROMPT]

        if llm_client.available and window:
            behaviors = self._llm_detect(case, window)
            if behaviors:
                return behaviors

        # 规则兜底
        return self._rule_fallback(case, window)

    def _llm_detect(self, case: Case, window: List[Event]) -> List[Behavior]:
        system = (
            "你是一名资深网络安全分析师。根据给定的事件序列，识别其中存在的 APT 攻击行为。\n"
            "行为定义：\n" + "\n".join(f"- {k}: {v}" for k, v in BEHAVIOR_DEFS.items()) + "\n"
            "规则：1) 只输出 JSON；2) confidence 为 0-1 小数；"
            "3) evidence 必须是给定事件中的事件 id；4) 无攻击行为时输出 {\"behaviors\": []}；"
            "5) 每条行为的 description 用一句话说明依据。"
        )
        user = (
            f"可疑案例：host={case.host}，窗口 {case.window_start} ~ {case.window_end}，预筛命中规则={case.hit_rules}\n"
            f"事件序列（{len(window)} 条）：\n" + json.dumps([_compact_event(e) for e in window], ensure_ascii=False)
        )
        out = llm_client.generate_json(system, user)
        raw = out.get("behaviors", [])
        behaviors: List[Behavior] = []
        valid_ids = {e.event_id for e in window}
        for b in raw[:6]:
            if not isinstance(b, dict) or b.get("type") not in BEHAVIOR_DEFS:
                continue
            ev = [i for i in b.get("evidence", []) if i in valid_ids][:10]
            try:
                conf = max(0.0, min(1.0, float(b.get("confidence", 0.5))))
            except (TypeError, ValueError):
                conf = 0.5
            behaviors.append(Behavior(
                type=b["type"], name=BEHAVIOR_DEFS[b["type"]].split("：")[0],
                confidence=conf, evidence=ev,
                description=str(b.get("description", ""))[:200],
            ))
        if behaviors:
            logger.info("案例 %s LLM 识别到 %d 个行为", case.case_id, len(behaviors))
        return behaviors

    @staticmethod
    def _rule_fallback(case: Case, window: List[Event]) -> List[Behavior]:
        """预筛规则兜底：hit_rules -> 行为，证据取相关事件。"""
        rule_to_type = {
            "lateral_movement": "lateral_movement",
            "hidden_channel": "hidden_channel",
            "long_term_latency": "long_term_latency",
            "trace_cleaning": "trace_cleaning",
        }
        behaviors: List[Behavior] = []
        for hr in case.hit_rules:
            btype = rule_to_type.get(hr)
            if not btype:
                continue
            # 证据：窗口内与命中行为相关的子集
            ev_ids: List[str] = []
            for e in window[:60]:
                hit = False
                proc = (e.process or "").lower()
                if btype == "lateral_movement" and (e.dst_port == 445 or any(t in proc for t in ("wmic", "psexec", "smbexec", "mimikatz"))):
                    hit = True
                if btype == "hidden_channel" and (
                    e.type.value == "dns" or e.dst_port in (53, 443) or (e.domain and e.action == "connect")
                ):
                    hit = True
                if btype == "long_term_latency" and e.type.value == "flow" and e.dst_ip:
                    hit = True
                if btype == "trace_cleaning" and (any(t in proc for t in ("wevtutil", "sdelete", "timestomp")) or e.action == "delete"):
                    hit = True
                if hit:
                    ev_ids.append(e.event_id)
            behaviors.append(Behavior(
                type=btype,
                name=BEHAVIOR_DEFS[btype].split("：")[0],
                confidence=0.65,
                evidence=ev_ids[:10],
                description="规则预筛兜底（无 LLM API 时依据 features.json 命中规则生成）",
            ))
        return behaviors


detector = Detector()
