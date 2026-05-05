# ============================================================
# 21_supply_industry.py
# 用途：V5 — 用 LLM 抽取每个专业的"主要服务行业"
#       行业候选集 = 企查查 21 门类（来自 1,337 家企业的实际分布）
# 输出：data/v5_supply_industry.parquet
#       data/v5_supply_industry.csv
# 依赖：scripts/llm_client.py
#       data/v4_supply_majors_raw.parquet（聚合培养方案文本）
# ============================================================

import os
import sys
import pathlib
import json

import pandas as pd
import numpy as np

sys.path.insert(0, ".")
from scripts.llm_client import batch_extract

# 企查查 21 门类（来自 1,337 家企业实际分布）
QCC_INDUSTRIES = [
    "信息技术", "机械设备", "电力设备", "医药生物", "基础化工",
    "商贸零售", "商业服务", "汽车", "环保", "轻工制造",
    "航空航天与国防", "建筑业", "家用电器", "建材及非金属", "公用事业",
    "金属及金属矿", "农林牧渔", "文化传媒", "房地产", "石油石化", "交通运输",
]

OUT = pathlib.Path("data/v5_supply_industry.parquet")
OUT.parent.mkdir(parents=True, exist_ok=True)

SYSTEM = (
    "你是专业的高职专业建设分析师。请根据人才培养方案文本，判断该专业毕业生最可能服务的"
    "深圳市专精特新'小巨人'企业群所在行业（企查查行业门类口径）。"
    "只返回JSON，不要任何额外说明。"
)

USER_TPL = (
    "从以下{count}份人才培养方案中，分别判断每份方案最匹配的服务行业（可多选，最多3个）。\n\n"
    "可选行业（共21个，来自深圳1,337家专精特新企业的实际企查查行业门类分布）：\n"
    f"{', '.join(QCC_INDUSTRIES)}\n\n"
    "判断依据：（1）培养目标提及的行业领域；（2）就业岗位涉及的产业；"
    "（3）核心课程指向的产业链环节；（4）实习实训单位类型。\n\n"
    "输出格式（JSON 数组）：\n"
    '[{{"id": "记录ID", "industries": [{{"name": "行业1", "score": 0-100, "reason": "理由"}}, ...]}}, ...]\n\n'
    "score 表示置信度。如果没有任何行业明显对应，industries 输出 []。\n\n"
    "人才培养方案文本：\n{texts}"
)


def main():
    df = pd.read_parquet("data/v4_supply_majors_raw.parquet")
    df["分析文本"] = df["聚合文本"].str.slice(0, 5000)

    print(f"专业数：{len(df)}")

    out = batch_extract(
        df=df,
        id_column="major_id",
        text_column="分析文本",
        task_name="v5_supply_industry",
        system_prompt=SYSTEM,
        user_prompt_template=USER_TPL,
        output_field="industries",
        batch_size=3,
        text_truncate=5000,
        reset=True,
    )

    # 合并基础字段
    out = df[["major_id", "专业名", "学院", "教育层次", "是否含子轨道", "子轨道数"]].merge(
        out, on="major_id", how="left"
    )
    # industries 字段统一为 list[dict]
    out["industries"] = out["industries"].apply(
        lambda x: list(x) if hasattr(x, "__iter__") and not isinstance(x, str) else []
    )
    # 解析为 top1/top2/top3 名+分
    def topn(items, n):
        items = sorted([i for i in items if isinstance(i, dict) and "name" in i],
                       key=lambda x: -x.get("score", 0))[:n]
        return [(i.get("name"), i.get("score", 0)) for i in items]

    out["top_industry_name"] = out["industries"].apply(lambda x: (topn(x, 1)[0][0] if topn(x, 1) else None))
    out["top_industry_score"] = out["industries"].apply(lambda x: (topn(x, 1)[0][1] if topn(x, 1) else None))
    out["top_industries_str"] = out["industries"].apply(
        lambda x: " | ".join([f"{n}({s})" for n, s in topn(x, 3)])
    )
    out["industry_names"] = out["industries"].apply(lambda x: [str(i.get("name")) for i in x if isinstance(i, dict) and i.get("name")])
    # 把 industries (list of dict) 转为 JSON 字符串以便 pyarrow 兼容
    out["industries_json"] = out["industries"].apply(lambda x: json.dumps(list(x), ensure_ascii=False) if x else "[]")
    out = out.drop(columns=["industries"])

    out.to_parquet(OUT, index=False)
    out_csv = out.copy()
    out_csv["industry_names"] = out_csv["industry_names"].apply(lambda x: "|".join([s for s in x if s]))
    out_csv.to_csv(OUT.with_suffix(".csv"), index=False, encoding="utf-8-sig")
    print(f"输出 → {OUT}")

    # 统计学院 → 行业 集中度
    print("\n=== 学院 → Top 行业（按出现频次） ===")
    rows = []
    for _, r in out.iterrows():
        for ind in r["industry_names"]:
            if ind:
                rows.append({"学院": r["学院"], "行业": ind})
    flat = pd.DataFrame(rows)
    if len(flat):
        ct = pd.crosstab(flat["学院"], flat["行业"]).T
        ct["合计"] = ct.sum(axis=1)
        ct = ct.sort_values("合计", ascending=False)
        print(ct.head(15).to_string())

    print("\n=== Step 21 完成 ===")


if __name__ == "__main__":
    main()
