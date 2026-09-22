# -*- coding: utf-8 -*-
"""评测脚本。

对 labels.json 标准答案，逐场景对比行为识别结果：
- 行为级 Precision / Recall / F1
- 组织归因命中率
- 输出评测报告（JSON + Markdown）

用法：cd backend && .venv\\Scripts\\python evaluate.py
"""
import json
from pathlib import Path

from app.core.config import settings
from app.core.database import fetch_all, init_db
from app.services.pipeline import pipeline


def main() -> dict:
    init_db(settings.db_path)
    labels_path = Path(settings.data_dir) / "labels.json"
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    scenes = labels.get("scenes", {})

    # 全量跑流水线
    report_ids = pipeline.run(use_intel=False)

    # 汇总各案例的行为与归因
    rows = fetch_all("SELECT * FROM reports")
    per_scene: dict = {}
    per_case_org: list = []   # 案例级归因（含 case_id）
    for r in rows:
        behaviors = json.loads(r["behaviors_json"])
        attr = json.loads(r["attribution_json"]) or {}
        # 场景：从案例所在主机反查
        case = fetch_all(
            "SELECT scene FROM events WHERE host=(SELECT host FROM cases WHERE case_id=?) LIMIT 1",
            (r["case_id"],),
        )
        scene = case[0]["scene"] if case and case[0].get("scene") else "?"
        per_scene.setdefault(scene, []).extend(
            {"behavior": b.get("type")} for b in behaviors
        )
        per_case_org.append({
            "case_id": r["case_id"],
            "scene": scene,
            "org": attr.get("org", ""),
        })

    # 计算指标
    result = {"report_count": len(rows), "scenes": {}}
    tp_all = fp_all = fn_all = 0
    for scene, cfg in scenes.items():
        gold = set(cfg["behaviors"])
        pred = {b["behavior"] for b in per_scene.get(scene, [])}
        tp = len(gold & pred)
        fp = len(pred - gold)
        fn = len(gold - pred)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        result["scenes"][scene] = {
            "gold": sorted(gold), "predicted": sorted(pred),
            "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        }
        tp_all += tp; fp_all += fp; fn_all += fn

    # 组织归因产出率（按案例计）：每个报告案例归因出具体组织才算命中
    org_total = len(per_case_org)
    org_hit = sum(
        1 for c in per_case_org
        if c["org"] and c["org"] != "疑似未知组织"
    )

    p = tp_all / (tp_all + fp_all) if (tp_all + fp_all) else 0
    rr = tp_all / (tp_all + fn_all) if (tp_all + fn_all) else 0
    f = 2 * p * rr / (p + rr) if (p + rr) else 0
    result["overall"] = {
        "precision": round(p, 3), "recall": round(rr, 3), "f1": round(f, 3),
        "org_attribution_rate": round(org_hit / org_total, 3) if org_total else 0,
    }

    out = Path(settings.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "evaluation.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    md = ["# 评测报告", "", f"- 报告数：{result['report_count']}",
          f"- 总体：Precision {p:.3f} / Recall {rr:.3f} / F1 {f:.3f}",
          f"- 组织归因产出率：{result['overall']['org_attribution_rate']:.1%}", ""]
    for s, v in result["scenes"].items():
        md.append(f"## 场景 {s}：P {v['precision']} / R {v['recall']} / F1 {v['f1']}")
        md.append(f"- 标准答案：{v['gold']}")
        md.append(f"- 识别结果：{v['predicted']}")
    (out / "evaluation.md").write_text("\n".join(md), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return result


if __name__ == "__main__":
    main()
