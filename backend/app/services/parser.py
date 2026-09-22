# -*- coding: utf-8 -*-
"""B2 解析标准化。

支持两类输入：
1. 标准 events.json（统一 Event schema 的 JSON 数组）
2. OTRF Security-Datasets NDJSON（每行一个 Windows 事件对象，Sysmon/Security）
   —— 自动按 EventID/Channel 映射为统一 Event。

输出：Event 对象列表（字段校验、非法时间戳过滤、时间升序）。
"""
import hashlib
import json
import re
from pathlib import Path
from typing import List, Optional

from app.models.event import Event, EventType

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")


def _is_ts(v: Optional[str]) -> bool:
    return bool(v) and bool(_TS_RE.match(v))


def _to_iso(v: str) -> str:
    return v.replace(" ", "T") if v and "T" not in v else v


def _basename(path: Optional[str]) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").split("/")[-1]


# ---------- NDJSON (OTRF) -> Event 映射 ----------

def _map_ndjson_type(o: dict) -> EventType:
    eid = o.get("EventID")
    channel = str(o.get("Channel") or "")
    if "Sysmon" in channel:
        if eid in (1, 10):
            return EventType.process
        if eid == 3:
            return EventType.flow
        if eid in (11, 23):
            return EventType.file
        if eid == 22:
            return EventType.dns
        if eid in (12, 13, 14):
            return EventType.process  # 注册表操作归入进程侧行为
        return EventType.process
    if "Security" in channel:
        if eid in (4624, 4625, 4648, 4634):
            return EventType.auth
        if eid in (5156, 5157, 5158):
            return EventType.flow
        if eid in (4656, 4658, 4663, 4690):
            return EventType.file
        if eid in (4103, 4104, 800):
            return EventType.process  # PowerShell 模块日志
        return EventType.process
    return EventType.process


def _ndjson_to_event(o: dict, idx: int) -> Event:
    eid = o.get("EventID")
    channel = str(o.get("Channel") or "")
    et = _map_ndjson_type(o)

    src_ip = o.get("SourceAddress") or o.get("SourceIp") or o.get("IpAddress")
    dst_ip = o.get("DestAddress") or o.get("DestinationIp") or o.get("DestinationAddress")
    src_port = o.get("SourcePort")
    dst_port = o.get("DestPort") or o.get("DestinationPort")
    src_port = int(src_port) if str(src_port).isdigit() else None
    dst_port = int(dst_port) if str(dst_port).isdigit() else None

    domain = o.get("QueryName") or o.get("DNS")
    if isinstance(domain, dict):
        domain = domain.get("QueryName")

    # 进程/文件字段（Sysmon 常见命名）
    image = o.get("Image") or o.get("SourceImage") or o.get("TargetImage") or ""
    process = _basename(image) or (o.get("ProcessName") or "")
    parent = _basename(o.get("ParentImage") or "")
    fpath = o.get("TargetFilename") or o.get("TargetObject") or o.get("Image")
    hashes = o.get("Hashes") or ""
    sha = ""
    if hashes:
        m = re.search(r"SHA256=([0-9A-Fa-f]{64})", hashes)
        if m:
            sha = m.group(1).lower()

    ts = _to_iso(o.get("@timestamp") or o.get("EventTime") or "")
    action = o.get("Action") or ""
    user = o.get("AccountName") or o.get("User") or ""
    host = o.get("Hostname") or o.get("host") or ""

    # 生成稳定 event_id（真实数据无原始 id，用内容哈希前缀）
    raw = o.get("RecordNumber") or o.get("ExecutionProcessID") or idx
    event_id = f"evt_{hashlib.md5(f'{ts}|{channel}|{eid}|{raw}'.encode()).hexdigest()[:10]}"

    return Event(
        event_id=event_id,
        ts=ts or "",
        type=et,
        src_ip=src_ip, src_port=src_port,
        dst_ip=dst_ip, dst_port=dst_port,
        domain=domain,
        process=process, parent_process=parent,
        file_path=fpath, file_hash=sha,
        action=action, user=user, host=host,
        scene="real", label="attack",  # OTRF 数据均为恶意活动
    )


class Parser:
    """事件解析器。"""

    def parse_file(self, path: str | Path) -> List[Event]:
        """按扩展名/内容自动识别格式。"""
        p = Path(path)
        raw = p.read_text(encoding="utf-8", errors="ignore").lstrip()
        if raw.startswith("["):
            return self.parse_dicts(json.loads(raw))
        # NDJSON：每行一个 JSON 对象
        return self.parse_ndjson_lines(raw.splitlines())

    def parse_ndjson_lines(self, lines: List[str]) -> List[Event]:
        events: List[Event] = []
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
                if not isinstance(o, dict):
                    continue
                events.append(_ndjson_to_event(o, i))
            except Exception:  # noqa: BLE001
                continue
        return self._finalize(events)

    def parse_dicts(self, items: List[dict]) -> List[Event]:
        """从标准 schema 字典列表解析。"""
        events: List[Event] = []
        for it in items:
            try:
                etype = EventType(it.get("type", "flow"))
            except ValueError:
                continue
            try:
                events.append(Event(**{**it, "type": etype}))
            except Exception:  # noqa: BLE001
                continue
        return self._finalize(events)

    @staticmethod
    def _finalize(events: List[Event]) -> List[Event]:
        """过滤非法时间戳并按时间升序。"""
        ok = [e for e in events if _is_ts(e.ts)]
        ok.sort(key=lambda e: e.ts)
        return ok


parser = Parser()
