# -*- coding: utf-8 -*-
"""大模型分析：POST /api/llm/analyze。

对所选数据源（模拟/真实/上传）做开放式 LLM 研判问答：
加载事件 → 预筛案例 → 组装上下文 → LLM 深度分析。
未配置 Key 时返回规则引擎分析结论（可演示）。
"""
import json
import logging
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import get_current_token
from app.core.config import settings
from app.core.llm_client import llm_client
from app.models.event import Event
from app.services.prefilter import prefilter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/llm", tags=["llm"])


class LLMAnalyzeRequest(BaseModel):
    data_file: Optional[str] = None
    scene: Optional[str] = None
    question: str = "请综合分析这批数据的攻击行为、攻击组织与处置建议"


def _load_events(data_file: Optional[str], scene: Optional[str]) -> List[Event]:
    from app.services.pipeline import pipeline
    return pipeline._load_events(data_file, scene)


def _compact(e: Event) -> str:
    parts = [e.ts[11:19], e.type.value, e.host or "-"]
    if e.type.value == "flow":
        parts.append(f"{e.src_ip}->{e.dst_ip}:{e.dst_port or '-'}" + (f"({e.domain})" if e.domain else ""))
    elif e.type.value == "dns":
        parts.append(f"query {e.domain} [{e.action}]")
    elif e.type.value == "process":
        parts.append(f"{e.process} <- {e.parent_process or '-'} [{e.action}]")
    elif e.type.value == "file":
        parts.append(f"{e.file_path or '-'} [{e.action}]")
    else:
        parts.append(f"{e.user or '-'} [{e.action}]")
    return " ".join(parts)


@router.post("/analyze")
async def llm_analyze(req: LLMAnalyzeRequest, _: str = Depends(get_current_token)) -> dict:
    try:
        events = _load_events(req.data_file, req.scene)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    cases = prefilter.aggregate(events)
    ev_map = {e.event_id: e for e in events}

    case_info = []
    for c in cases[:10]:
        window = [ev_map[i] for i in c.events if i in ev_map][:60]
        case_info.append({
            "case_id": c.case_id, "host": c.host,
            "window_start": c.window_start, "hit_rules": c.hit_rules,
            "events": [e.event_id for e in window],
        })

    # 上下文（控制 token：全量最多 150 条事件摘要）
    lines = [_compact(e) for e in events[:150]]
    context = "\n".join(lines)

    system = (
        "你是一名资深网络安全分析师，专注 APT 攻击行为研判。"
        "根据给定的事件序列回答用户问题，输出结构化结论：攻击行为、可疑组织画像、"
        "研判依据（引用具体事件）、影响范围与处置建议。用中文，分点输出。"
    )
    user = (
        f"数据概况：{len(events)} 条事件，预筛可疑案例 {len(cases)} 个。\n"
        f"案例摘要：\n" + json.dumps([{k: v for k, v in c.items() if k != 'events'} for c in case_info],
                                     ensure_ascii=False) + "\n"
        f"事件序列（前 {len(lines)} 条）：\n{context}\n"
        f"用户问题：{req.question}"
    )

    answer = ""
    if llm_client.available:
        answer = llm_client.generate_text(system, user)
        if not answer:
            answer = "（LLM 调用未返回有效结果，请检查 Key 后重试）"

    mode = "api" if llm_client.available else "fallback"
    if not answer:
        # 规则兜底结论
        lines2 = ["当前未配置 LLM API Key，以下为规则引擎分析结论：", ""]
        if cases:
            for c in case_info[:10]:
                lines2.append(f"- 案例 {c['case_id']}（主机 {c['host']}，窗口 {c['window_start']}）："
                              f"命中规则 {', '.join(c['hit_rules']) or '无'}")
            lines2.append("")
            lines2.append("建议：配置 DEEPSEEK_API_KEY 后启用 LLM 深度研判；或点击「一键全流程研判」生成正式报告。")
        else:
            lines2.append("未发现可疑案例：该数据无明显 APT 行为特征。")
        answer = "\n".join(lines2)

    return {"code": 0, "message": "ok", "data": {
        "mode": mode, "llm_available": llm_client.available,
        "event_count": len(events), "case_count": len(cases),
        "cases": case_info, "answer": answer,
    }}
