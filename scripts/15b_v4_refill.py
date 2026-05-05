# ============================================================
# 15b_supply_refill_empty_tools.py
# 用途：为工具列表为空的 13 个专业重新抽取（多窗口扫描策略）
#       将聚合文本切成 5000 字符的窗口，对每个窗口分别调用 LLM，
#       最后把所有窗口的工具取并集。
# 输出：覆盖更新 data/v4_supply_majors.parquet
# 依赖：scripts/llm_client.py（已支持 text_truncate）
# ============================================================

import os
import sys
import pathlib
import json
from typing import List

import pandas as pd
import numpy as np

sys.path.insert(0, ".")
from scripts.llm_client import batch_extract

# 引用 15 中的同 prompt（保持一致）
SYSTEM_TOOLS = (
    "你是专业的高职专业建设分析师。"
    "请从人才培养方案中提取所有具体的技术工具、软件、框架、平台、编程语言名称（即课程会教学/学生应掌握的工具）。"
    "只返回JSON，不要任何额外说明。"
)
USER_TOOLS_TPL = (
    "从以下{count}份人才培养方案文本片段中，分别提取每份片段明确教学的具体技术工具/软件/编程语言列表。\n\n"
    "提取范围：编程语言（Python、Java、C++等）、软件（AutoCAD、SolidWorks、MATLAB等）、"
    "框架/库（Vue、React、TensorFlow等）、平台（AWS、阿里云、SAP等）、"
    "行业工具（PLC、ANSYS、Altium Designer、ERP等）。\n\n"
    "不要提取通用词（如\u300c计算机\u300d、\u300c系统\u300d、\u300c软件\u300d等），只要具体产品/工具名称。\n\n"
    "输出格式（JSON数组）：\n"
    '[{{"id": "记录ID", "tools": ["工具1", "工具2", ...]}}, ...]\n\n'
    "如果没有提及具体工具名称，输出空列表[]。\n\n"
    "人才培养方案文本片段：\n{texts}"
)

OUT_FINAL = pathlib.Path("data/v4_supply_majors.parquet")
WINDOW_SIZE = 5000
N_WINDOWS = 4  # 每专业最多扫描 4 个窗口（即覆盖前 20K 字符）


def slice_into_windows(text: str, w: int = WINDOW_SIZE, n: int = N_WINDOWS) -> List[str]:
    """把长文本切成最多 n 个 w 字符的窗口（不重叠）。"""
    chunks = []
    for i in range(n):
        start = i * w
        end = start + w
        if start >= len(text):
            break
        chunks.append(text[start:end])
    return chunks


def main():
    df = pd.read_parquet(OUT_FINAL)

    # 同时加载 raw 以拿到完整聚合文本
    raw = pd.read_parquet("data/v4_supply_majors_raw.parquet")
    df = df.merge(raw[["major_id", "聚合文本"]], on="major_id", how="left")

    # 找到工具空的专业
    empty_mask = df["tools_normalized"].apply(
        lambda x: not bool(list(x)) if hasattr(x, "__iter__") else True
    )
    empty = df[empty_mask].copy()
    print(f"工具列表为空的专业：{len(empty)} 个")
    for _, r in empty.iterrows():
        print(f"  - {r['专业名']}（{r['学院']}）")

    # 为每个空专业生成多个窗口
    rows = []
    for _, r in empty.iterrows():
        windows = slice_into_windows(str(r["聚合文本"]))
        for wi, chunk in enumerate(windows):
            rows.append({
                "scan_id": f"{r['major_id']}_W{wi}",
                "major_id": r["major_id"],
                "专业名": r["专业名"],
                "window_idx": wi,
                "text": chunk,
            })
    scan_df = pd.DataFrame(rows)
    print(f"\n生成扫描批次：{len(scan_df)} 个窗口（{len(empty)} 专业 × 最多 {N_WINDOWS} 窗口）")

    # 批量抽取（每条记录就是一个 5000 字符片段）
    print("\n开始多窗口工具抽取 …")
    results = batch_extract(
        df=scan_df,
        id_column="scan_id",
        text_column="text",
        task_name="v4_supply_tools_refill",
        system_prompt=SYSTEM_TOOLS,
        user_prompt_template=USER_TOOLS_TPL,
        output_field="tools",
        batch_size=3,
        text_truncate=5000,
        reset=True,
    )

    # 按 major_id 聚合所有窗口的工具，取并集
    scan_df = scan_df.merge(results, on="scan_id", how="left")
    by_major = {}
    for _, r in scan_df.iterrows():
        mid = r["major_id"]
        tools = list(r["tools"]) if hasattr(r["tools"], "__iter__") and not isinstance(r["tools"], str) else []
        by_major.setdefault(mid, set()).update(tools)

    # 更新主 parquet 中这些专业的 tools / tools_normalized 字段
    df_full = pd.read_parquet(OUT_FINAL)
    # 先把所有列表/数组列统一为 Python list，避免 pyarrow 类型混乱
    for col in ["tools", "tools_normalized", "soft_skills", "soft_skills_normalized"]:
        if col in df_full.columns:
            df_full[col] = df_full[col].apply(
                lambda x: list(x) if hasattr(x, "__iter__") and not isinstance(x, str) else []
            )
    for mid, tools_set in by_major.items():
        tool_list = sorted(tools_set)
        idx = df_full.index[df_full["major_id"] == mid]
        if len(idx) == 0:
            continue
        df_full.at[idx[0], "tools"] = tool_list
        df_full.at[idx[0], "tools_normalized"] = tool_list
        major = df_full.at[idx[0], "专业名"]
        print(f"  ✓ 更新 {major}：{len(tool_list)} 项工具 → {tool_list[:8]}{'…' if len(tool_list) > 8 else ''}")

    df_full.to_parquet(OUT_FINAL, index=False)
    print(f"\n更新完成 → {OUT_FINAL}")
    n_have = df_full["tools_normalized"].apply(
        lambda x: bool(list(x)) if hasattr(x, "__iter__") else False
    ).sum()
    print(f"现在工具非空的专业：{n_have} / 54")


if __name__ == "__main__":
    main()
