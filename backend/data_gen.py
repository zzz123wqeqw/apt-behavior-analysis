# -*- coding: utf-8 -*-
"""B1 数据生成。

生成带标签的模拟 APT 场景数据集 events.json + labels.json。
- 场景 A・朝鲜系：鱼叉钓鱼 → 宏文档 → HTTP C2 → 长期潜伏（低频 beacon）
- 场景 B・南亚系：Web 弱口令 → SMB/WMI 内网横向移动
- 场景 C・伊朗系：DNS 隧道外传 → 定时任务持久化 → 痕迹清理
- 正常流量噪声约占 70%

用法：
    cd backend && .venv\\Scripts\\python data_gen.py
"""
import json
import random
import string
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

SCENES = {
    "A": {
        "behaviors": ["hidden_channel", "long_term_latency"],
        "hosts": ["work-a1"],
        "iocs": ["45.77.10.20", "c2-a.secure-update.net"],
    },
    "B": {
        "behaviors": ["lateral_movement"],
        "hosts": ["web-b1", "web-b2", "web-b3"],
        "iocs": ["103.75.12.66"],
    },
    "C": {
        "behaviors": ["hidden_channel", "trace_cleaning"],
        "hosts": ["server-c1"],
        "iocs": ["exfil.tunnel-notes.top"],
    },
}

INTERNAL_NETS = ["10.10.0.", "10.10.1.", "10.10.2."]
USERS = ["zhang", "li", "wang", "admin", "ops01"]
NORMAL_DOMAINS = ["mail.corp.local", "wiki.corp.local", "update.corp.local", "office.com", "baidu.com"]
NORMAL_PROCESSES = ["chrome.exe", "explorer.exe", "outlook.exe", "svchost.exe", "winword.exe", "python.exe"]
_eid = 0


def _next_event_id() -> str:
    global _eid
    _eid += 1
    return f"evt_{_eid:06d}"


def _ts(base: datetime, minutes: float) -> str:
    return (base + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S")


def _normal_event(base: datetime, host: str, user: str) -> Dict:
    """一条正常流量事件。"""
    t = random.random() * 480  # 8 小时工作窗口
    kind = random.choices(["flow", "dns", "process", "auth", "file"], weights=[35, 30, 20, 10, 5])[0]
    e = {
        "event_id": _next_event_id(),
        "ts": _ts(base, t),
        "type": kind,
        "src_ip": f"{random.choice(INTERNAL_NETS)}{random.randint(2, 250)}",
        "src_port": random.randint(1024, 65535),
        "host": host,
        "user": user,
        "scene": None,
        "label": "normal",
    }
    if kind == "flow":
        e["dst_ip"] = random.choice(["8.8.8.8", "114.114.114.114", "203.0.113.5", "198.51.100.9"])
        e["dst_port"] = random.choice([80, 443, 53, 3389, 22])
        e["action"] = "connect"
    elif kind == "dns":
        e["domain"] = random.choice(NORMAL_DOMAINS)
        e["action"] = "query"
    elif kind == "process":
        e["process"] = random.choice(NORMAL_PROCESSES)
        e["parent_process"] = "explorer.exe"
        e["action"] = "exec"
    elif kind == "auth":
        e["dst_ip"] = f"{random.choice(INTERNAL_NETS)}{random.randint(2, 250)}"
        e["action"] = "login"
    else:
        e["file_path"] = rf"C:\Users\{user}\Documents\report_{random.randint(1000, 9999)}.docx"
        e["action"] = "write"
    return e


def _scene_a(base: datetime) -> List[Dict]:
    """朝鲜系：钓鱼→宏→C2→潜伏。"""
    host, user = "work-a1", "zhang"
    evts = []
    # 1. 钓鱼邮件附件宏文档
    evts.append({**_norm(host, user), **{
        "event_id": _next_event_id(), "ts": _ts(base, 0), "type": "file",
        "file_path": r"C:\Users\zhang\Downloads\invitation.docm", "action": "write",
        "process": "outlook.exe", "label": "attack",
    }})
    evts.append({**_norm(host, user), **{
        "event_id": _next_event_id(), "ts": _ts(base, 2), "type": "process",
        "process": "winword.exe", "parent_process": "explorer.exe",
        "action": "exec", "label": "attack",
    }})
    evts.append({**_norm(host, user), **{
        "event_id": _next_event_id(), "ts": _ts(base, 3), "type": "process",
        "process": "powershell.exe", "parent_process": "winword.exe",
        "action": "exec", "label": "attack",
    }})
    # 2. HTTP C2 回连（高熵子域 C2）
    for i in range(4):
        evts.append({**_norm(host, user), **{
            "event_id": _next_event_id(), "ts": _ts(base, 5 + i * 2), "type": "flow",
            "dst_ip": "45.77.10.20", "dst_port": 443, "src_port": 50000 + i,
            "action": "connect", "domain": "3f9a2c1d8b5e.secure-update.net", "label": "attack",
        }})
    # 3. 长期潜伏：凌晨 0 点起每 30 分钟一次低频 beacon（0:00-4:30）
    midnight = base + timedelta(hours=15)
    for i in range(10):
        evts.append({**_norm(host, user), **{
            "event_id": _next_event_id(), "ts": _ts(midnight, i * 30),
            "type": "flow", "dst_ip": "45.77.10.20", "dst_port": 443,
            "src_port": 51000 + i, "action": "connect",
            "domain": "3f9a2c1d8b5e.secure-update.net", "label": "attack",
        }})
    return evts


def _norm(host: str, user: str) -> Dict:
    return {"src_ip": "10.10.0.10", "src_port": 0, "host": host, "user": user, "scene": "A"}


def _scene_b(base: datetime) -> List[Dict]:
    """南亚系：弱口令→SMB/WMI 横向移动。"""
    evts = []
    # 1. Web 弱口令爆破成功
    evts.append({**_norm("web-b1", "admin"), **{
        "event_id": _next_event_id(), "ts": _ts(base, 0), "type": "auth",
        "dst_ip": "10.10.1.10", "dst_port": 80, "action": "login_fail", "label": "attack",
    }})
    evts.append({**_norm("web-b1", "admin"), **{
        "event_id": _next_event_id(), "ts": _ts(base, 1), "type": "auth",
        "dst_ip": "10.10.1.10", "dst_port": 80, "action": "login", "label": "attack",
    }})
    # 2. SMB 445 批量连接（同源多目标）
    for i in range(8):
        evts.append({**_norm("web-b1", "admin"), **{
            "event_id": _next_event_id(), "ts": _ts(base, 3 + i * 0.5), "type": "flow",
            "dst_ip": f"10.10.2.{30 + i}", "dst_port": 445, "src_port": 40000 + i,
            "action": "connect", "label": "attack",
        }})
    # 3. WMI 远程执行
    evts.append({**_norm("web-b1", "admin"), **{
        "event_id": _next_event_id(), "ts": _ts(base, 8), "type": "process",
        "process": "wmic.exe", "parent_process": "cmd.exe",
        "action": "exec", "label": "attack",
    }})
    return evts


def _scene_c(base: datetime) -> List[Dict]:
    """伊朗系：DNS 隧道→计划任务→痕迹清理。"""
    host, user = "server-c1", "ops01"
    evts = []
    # 1. DNS 隧道高熵子域名
    for i in range(6):
        sub = "".join(random.choices(string.hexdigits.lower(), k=12))
        evts.append({**_norm(host, user), **{
            "event_id": _next_event_id(), "ts": _ts(base, i * 3), "type": "dns",
            "domain": f"{sub}.exfil.tunnel-notes.top", "action": "query", "label": "attack",
        }})
    # 2. 计划任务持久化
    evts.append({**_norm(host, user), **{
        "event_id": _next_event_id(), "ts": _ts(base, 20), "type": "process",
        "process": "schtasks.exe", "parent_process": "cmd.exe",
        "action": "exec", "label": "attack",
    }})
    # 3. 痕迹清理：wevtutil 清日志 + 删除临时文件
    evts.append({**_norm(host, user), **{
        "event_id": _next_event_id(), "ts": _ts(base, 25), "type": "process",
        "process": "wevtutil.exe", "parent_process": "cmd.exe",
        "action": "exec", "label": "attack",
    }})
    evts.append({**_norm(host, user), **{
        "event_id": _next_event_id(), "ts": _ts(base, 26), "type": "file",
        "file_path": r"C:\Windows\Temp\payload.dll", "action": "delete", "label": "attack",
    }})
    return evts


def generate(scene: Optional[str] = None, output_dir: str = "data", noise_ratio: float = 0.7) -> Dict:
    """生成模拟数据集（默认全量三场景 + 70% 正常噪声）。"""
    random.seed(2026)
    global _eid
    _eid = 0
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    base = datetime(2026, 9, 20, 9, 0)
    events: List[Dict] = []
    labels: Dict = {"scenes": {}}

    scenes = [scene] if scene else list(SCENES.keys())
    for s in scenes:
        gen = {"A": _scene_a, "B": _scene_b, "C": _scene_c}[s]
        attack_evts = gen(base)
        # 该场景主机上的正常噪声
        hosts = SCENES[s]["hosts"]
        normal_evts = [
            _normal_event(base, random.choice(hosts), random.choice(USERS))
            for _ in range(int(len(attack_evts) * noise_ratio / (1 - noise_ratio)))
        ]
        for e in attack_evts:
            e["scene"] = s
        for e in normal_evts:
            e["scene"] = s
        events.extend(attack_evts + normal_evts)
        labels["scenes"][s] = {
            "behaviors": SCENES[s]["behaviors"],
            "hosts": hosts,
            "iocs": SCENES[s]["iocs"],
        }

    events.sort(key=lambda e: e["ts"])
    with open(out / "events.json", "w", encoding="utf-8") as f:
        json.dump(events, f, ensure_ascii=False, indent=1)
    with open(out / "labels.json", "w", encoding="utf-8") as f:
        json.dump(labels, f, ensure_ascii=False, indent=1)

    stats = {"total": len(events), "attack": sum(1 for e in events if e["label"] == "attack"),
             "normal": sum(1 for e in events if e["label"] == "normal"), "scenes": list(scenes)}
    return stats


if __name__ == "__main__":
    print(generate())
