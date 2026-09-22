# -*- coding: utf-8 -*-
"""奇安信公开报告导入器。

奇安信无公开 API：将公开 APT 报告/公开 IOC（人工放置的文本文件）
半自动导入组织画像库，不爬取网页。
- LLM 可用时用 LLM 结构化抽取
- 否则用关键词规则抽取
"""
import json
import logging
import re
from pathlib import Path
from typing import Dict, List

from app.core.config import settings
from app.core.llm_client import llm_client
from app.services.attribution import attribution_service

logger = logging.getLogger(__name__)

_TTP_KEYWORDS = ["钓鱼", "宏", "C2", "PowerShell", "计划任务", "WMI", "SMB", "PsExec",
                 "DNS隧道", "wevtutil", "注册表", "漏洞", "0day", "水坑", "鱼叉"]
_TOOL_KEYWORDS = ["BabyShark", "AppleSeed", "Mimikatz", "Empire", "Cobalt Strike", "NukeSped"]


class QianxinImporter:
    """公开报告 -> 画像库导入器。"""

    def __init__(self, source_dir: str = "data/intel_reports") -> None:
        self.source_dir = Path(source_dir)

    def list_reports(self) -> List[str]:
        if not self.source_dir.exists():
            return []
        return [str(p) for p in sorted(self.source_dir.glob("*.md"))] + \
               [str(p) for p in sorted(self.source_dir.glob("*.txt"))]

    def import_one(self, file_path: str, org: str) -> Dict:
        text = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        if llm_client.available:
            extracted = self._llm_extract(text)
        else:
            extracted = self._keyword_extract(text)

        apts = attribution_service.profiles.setdefault("apts", [])
        entry = {
            "name": org,
            "region": extracted.get("region", ""),
            "targets": extracted.get("targets", []),
            "behaviors": extracted.get("behaviors", []),
            "ttps": extracted.get("ttps", []),
            "tools": extracted.get("tools", []),
            "keywords": [org.lower()] + extracted.get("iocs", [])[:10],
            "source": file_path,
        }
        for i, a in enumerate(apts):
            if a["name"] == org:
                apts[i] = entry
                break
        else:
            apts.append(entry)
        self._save()
        return entry

    @staticmethod
    def _keyword_extract(text: str) -> Dict:
        """关键词规则抽取（兜底）。"""
        ttps = [k for k in _TTP_KEYWORDS if k in text]
        tools = [k for k in _TOOL_KEYWORDS if k in text]
        iocs = re.findall(r"(?i)([a-z0-9.-]+\.(?:com|net|org|top|cn|io|xyz))", text)
        return {"region": "", "targets": [], "behaviors": [], "ttps": ttps,
                "tools": tools, "iocs": list(dict.fromkeys(iocs))[:10]}

    @staticmethod
    def _llm_extract(text: str) -> Dict:
        system = ("你是威胁情报分析师。从 APT 报告中抽取结构化信息，只输出 JSON："
                  "{region, targets[], behaviors[], ttps[], tools[], iocs[]}")
        out = llm_client.generate_json(system, text[:4000])
        return {
            "region": str(out.get("region", "")),
            "targets": [str(x) for x in out.get("targets", [])][:5],
            "behaviors": [str(x) for x in out.get("behaviors", [])][:5],
            "ttps": [str(x) for x in out.get("ttps", [])][:10],
            "tools": [str(x) for x in out.get("tools", [])][:10],
            "iocs": [str(x) for x in out.get("iocs", [])][:10],
        }

    def _save(self) -> None:
        with open(settings.profiles_file, "w", encoding="utf-8") as f:
            json.dump(attribution_service.profiles, f, ensure_ascii=False, indent=2)
        attribution_service.load_profiles(Path(settings.profiles_file))


qianxin_importer = QianxinImporter()
