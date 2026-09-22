# -*- coding: utf-8 -*-
"""知识图谱数据模型（见设计方案 4.6 / 第 6 章）。"""
from typing import Any, Dict, List

from pydantic import BaseModel


class GraphNode(BaseModel):
    id: str
    label: str
    type: str   # apt/behavior/ttp/ip/domain/sample/case/target
    props: Dict[str, Any] = {}


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str  # 使用/关联/涉及/具备/针对/利用
    weight: float = 1.0


class KnowledgeGraph(BaseModel):
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []
