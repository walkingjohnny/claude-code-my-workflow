# ============================================================
# 12_tech_tools.py
# 用途：V2研究 - 从职位描述中提取具体技术工具/软件/框架名称
#       补充V1结构化技术关键词字段，揭示更精细的工具图谱
# 输出：data/v2_tech_tools.parquet
#       Figures/fig37_tech_tools_top30.png/.pdf
#       Figures/fig38_tools_category_heatmap.png/.pdf
#       Figures/fig39_tools_trend.png/.pdf
# 依赖：scripts/llm_client.py, scripts/_common.py
#       scripts/job_classified_data.csv
# ============================================================

import os
import sys
import pathlib
import collections

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import seaborn as sns

sys.path.insert(0, ".")
from scripts._common import setup_style, save_fig, RANDOM_SEED
from scripts.llm_client import batch_extract

np.random.seed(RANDOM_SEED)

TASK_NAME = "tech_tools"
OUTPUT_PARQUET = pathlib.Path("data/v2_tech_tools.parquet")

SYSTEM_PROMPT = (
    "你是专业的技术招聘数据分析师。"
    "请从招聘职位描述中提取所有具体的技术工具、软件、框架、平台、编程语言名称。"
    "只返回JSON，不要任何额外说明。"
)

USER_PROMPT_TEMPLATE = (
    "从以下{count}条职位描述中，分别提取每个职位提到的具体技术工具名称列表。\n\n"
    "提取范围：编程语言（Python、Java、C++等）、软件（AutoCAD、SolidWorks、MATLAB等）、"
    "框架/库（Vue、React、TensorFlow等）、平台（AWS、阿里云、SAP等）、"
    "行业工具（PLC、ANSYS、Altium Designer等）。\n\n"
    "不要提取通用词（如\u300c计算机\u300d、\u300c系统\u300d、\u300c软件\u300d等），只要具体产品/工具名称。\n\n"
    "输出格式（JSON数组）：\n"
    '[{{"id": "记录ID", "tools": ["工具1", "工具2", ...]}}, ...]\n\n'
    "如果没有提及具体工具名称，输出空列表[]。\n\n"
    "职位描述：\n{texts}"
)

# 工具名称标准化（统一大小写和常见别名）
NORMALIZE_MAP = {
    "python": "Python",
    "Python3": "Python",
    "java": "Java",
    "c++": "C++",
    "c/c++": "C/C++",
    "c#": "C#",
    "javascript": "JavaScript",
    "js": "JavaScript",
    "typescript": "TypeScript",
    "ts": "TypeScript",
    "vue": "Vue.js",
    "vue.js": "Vue.js",
    "vue3": "Vue.js",
    "react": "React",
    "react.js": "React",
    "angular": "Angular",
    "tensorflow": "TensorFlow",
    "pytorch": "PyTorch",
    "autocad": "AutoCAD",
    "solidworks": "SolidWorks",
    "solid works": "SolidWorks",
    "matlab": "MATLAB",
    "proe": "Pro/E",
    "pro/e": "Pro/E",
    "catia": "CATIA",
    "ug": "UG/NX",
    "nx": "UG/NX",
    "ansys": "ANSYS",
    "altium": "Altium Designer",
    "altium designer": "Altium Designer",
    "sap": "SAP",
    "plc": "PLC",
    "mysql": "MySQL",
    "postgresql": "PostgreSQL",
    "redis": "Redis",
    "mongodb": "MongoDB",
    "docker": "Docker",
    "kubernetes": "Kubernetes",
    "k8s": "Kubernetes",
    "git": "Git",
    "linux": "Linux",
    "android": "Android",
    "ios": "iOS",
    "pycharm": "PyCharm",
    "office": "Microsoft Office",
    "excel": "Excel",
    "word": "Word",
    "powerpoint": "PowerPoint",
}


def normalize_tool(tool: str) -> str:
    """工具名称标准化。"""
    tool = tool.strip()
    lower = tool.lower()
    return NORMALIZE_MAP.get(lower, tool)


def run_extraction(df: pd.DataFrame, reset: bool = False) -> pd.DataFrame:
    df = df.copy()
    df["jd_id"] = [f"JD_{i:05d}" for i in range(len(df))]
    return batch_extract(
        df=df,
        id_column="jd_id",
        text_column="职位描述",
        task_name=TASK_NAME,
        system_prompt=SYSTEM_PROMPT,
        user_prompt_template=USER_PROMPT_TEMPLATE,
        output_field="tools",
        batch_size=20,
        reset=reset,
    )


def plot_tools_top30(tool_counts: pd.Series, fig_name: str = "fig37_tech_tools_top30"):
    """图37：工具频率Top30条形图。"""
    top30 = tool_counts.head(30)
    fig, ax = plt.subplots(figsize=(11, 9))
    colors = plt.cm.Greens_r(np.linspace(0.3, 0.85, len(top30)))
    bars = ax.barh(range(len(top30)), top30.values, color=colors)
    ax.set_yticks(range(len(top30)))
    ax.set_yticklabels(top30.index, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel("出现频次（条）", fontsize=11)
    ax.set_title(
        '\u6df1\u5733\u5e02\u4e13\u7cbe\u7279\u65b0\u201c\u5c0f\u5de8\u4eba\u201d\u4f01\u4e1a\u62db\u8058\u6280\u672f\u5de5\u5177 Top30\uff08\u804c\u4f4d\u63cf\u8ff0\u63d0\u53d6\uff09',
        fontsize=12, pad=12
    )
    for i, (val, bar) in enumerate(zip(top30.values, bars)):
        ax.text(val + 2, i, str(val), va="center", fontsize=8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    plt.tight_layout()
    save_fig(fig_name)
    print("fig37 已保存")


def plot_tools_category_heatmap(tool_cat_matrix: pd.DataFrame, fig_name: str = "fig38_tools_category_heatmap"):
    """图38：工具×岗位类别热力图。"""
    fig, ax = plt.subplots(figsize=(14, 9))
    sns.heatmap(
        tool_cat_matrix,
        cmap="Blues",
        annot=True,
        fmt=".0f",
        linewidths=0.4,
        ax=ax,
        cbar_kws={"label": "每千条出现率"},
    )
    ax.set_title(
        '\u6280\u672f\u5de5\u5177\u00d7\u5c97\u4f4d\u7c7b\u522b\u51fa\u73b0\u70ed\u529b\u56fe\uff08\u6bcf\u5343\u6761\u51fa\u73b0\u7387\uff09',
        fontsize=13, pad=12
    )
    ax.set_xlabel("岗位类别", fontsize=11)
    ax.set_ylabel("技术工具", fontsize=11)
    plt.xticks(rotation=30, ha="right", fontsize=9)
    plt.yticks(fontsize=9)
    plt.tight_layout()
    save_fig(fig_name)
    print("fig38 已保存")


def plot_tools_trend(trend_df: pd.DataFrame, fig_name: str = "fig39_tools_trend"):
    """图39：Top10工具历年趋势折线图。"""
    n_tools = len(trend_df.columns)
    colors = plt.cm.tab10(np.linspace(0, 1, n_tools))
    fig, ax = plt.subplots(figsize=(12, 6))
    for i, col in enumerate(trend_df.columns):
        ax.plot(trend_df.index, trend_df[col], marker="o", linewidth=1.8,
                color=colors[i], label=col, alpha=0.85)
    ax.set_xlabel("年份", fontsize=11)
    ax.set_ylabel("每千条出现率", fontsize=11)
    ax.set_title(
        '\u4e3b\u8981\u6280\u672f\u5de5\u5177\u5386\u5e74\u9700\u6c42\u8d8b\u52bf\uff08Top10\uff09',
        fontsize=13, pad=12
    )
    ax.legend(loc="upper left", fontsize=8, ncol=2)
    ax.xaxis.set_major_locator(mticker.MultipleLocator(1))
    plt.xticks(rotation=30)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    plt.tight_layout()
    save_fig(fig_name)
    print("fig39 已保存")


def main():
    setup_style()
    os.makedirs("data", exist_ok=True)

    print("加载V1分类数据...")
    classified = pd.read_csv("scripts/job_classified_data.csv", encoding="utf-8-sig", low_memory=False)

    cat_col = "岗位类别" if "岗位类别" in classified.columns else None

    print("\n开始技术工具提取（断点续传）...")
    classified["jd_id"] = [f"JD_{i:05d}" for i in range(len(classified))]
    result_df = run_extraction(classified, reset=False)

    merged = classified.merge(result_df, on="jd_id", how="left")

    # 保存
    OUTPUT_PARQUET.parent.mkdir(exist_ok=True)
    save_cols = ["jd_id", "招聘岗位", "招聘发布年份", "tools"]
    if cat_col:
        save_cols.insert(3, cat_col)
    merged[save_cols].to_parquet(OUTPUT_PARQUET, index=False)
    print(f"结果已保存：{OUTPUT_PARQUET}")

    # ===== 分析 =====
    records = []
    for _, row in merged.iterrows():
        tools = row.get("tools", [])
        if not isinstance(tools, list):
            continue
        year = row.get("招聘发布年份")
        cat = row.get(cat_col) if cat_col else "未知"
        for t in tools:
            t_norm = normalize_tool(str(t))
            records.append({"year": year, "category": cat, "tool": t_norm})

    tool_df = pd.DataFrame(records)
    print(f"\n提取到工具记录：{len(tool_df):,}条，唯一工具：{tool_df['tool'].nunique()}种")

    tool_counts = tool_df["tool"].value_counts()
    print("\nTop30技术工具：")
    print(tool_counts.head(30).to_string())

    # --- 图37 ---
    plot_tools_top30(tool_counts)

    # --- 图38：工具×类别热力图 ---
    if cat_col:
        top15_tools = tool_counts.head(15).index.tolist()
        cat_counts = classified[cat_col].value_counts()
        main_cats = cat_counts[cat_counts > 50].index.tolist()

        matrix_data = {}
        for tool in top15_tools:
            row_data = {}
            for cat in main_cats:
                cat_total = (merged[cat_col] == cat).sum()
                count = ((tool_df["category"] == cat) & (tool_df["tool"] == tool)).sum()
                row_data[cat] = round(count / cat_total * 1000, 1) if cat_total > 0 else 0
            matrix_data[tool] = row_data

        heatmap_df = pd.DataFrame(matrix_data).T[main_cats]
        plot_tools_category_heatmap(heatmap_df)

    # --- 图39：历年趋势 ---
    valid_years = sorted([y for y in tool_df["year"].dropna().unique() if 2016 <= int(y) <= 2024])
    top10_tools = tool_counts.head(10).index.tolist()
    year_totals = merged["招聘发布年份"].value_counts()

    trend_data = {}
    for tool in top10_tools:
        year_counts = tool_df[tool_df["tool"] == tool]["year"].value_counts()
        trend_data[tool] = {
            y: round(year_counts.get(y, 0) / year_totals.get(y, 1) * 1000, 1)
            for y in valid_years
        }
    trend_df = pd.DataFrame(trend_data, index=valid_years)
    plot_tools_trend(trend_df)

    non_empty = merged["tools"].apply(lambda x: isinstance(x, list) and len(x) > 0).sum()
    print(f"\n===== 运行摘要 =====")
    print(f"分析样本：{len(merged):,}条")
    print(f"有工具提取率：{non_empty/len(merged):.1%}（{non_empty:,}/{len(merged):,}）")
    print(f"工具总记录：{len(tool_df):,}条，唯一种类：{tool_df['tool'].nunique()}")
    print(f"输出数据：{OUTPUT_PARQUET}")
    print(f"输出图表：fig37–fig39")
    print("====================")


if __name__ == "__main__":
    main()
