# ============================================================
# 17_demand_annual.py
# 用途：V4 — 需求侧 2021—2024 年度数字化进展统计与可视化
#       对 v2_digitalization / v2_tech_tools / v2_soft_skills 三个 parquet
#       按招聘发布年份分组，输出年度均值/中位数及岗位类别细分。
# 输出：data/v4_demand_annual.parquet
#       Figures/journal/v4/fig_v4_a01_digi_trend.png/.pdf
#       Figures/journal/v4/fig_v4_a02_digi_by_category_year.png/.pdf
#       Figures/journal/v4/fig_v4_a03_top_tools_yearly.png/.pdf
# 依赖：scripts/_common.py
# ============================================================

import os
import sys
import pathlib
from collections import Counter

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.insert(0, ".")
from scripts._common import setup_style, COLORS, RANDOM_SEED

np.random.seed(RANDOM_SEED)
setup_style()

YEAR_RANGE = [2021, 2022, 2023, 2024]
FIG_DIR = pathlib.Path("Figures/journal/v4")
FIG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR = pathlib.Path("data")


def load():
    digi = pd.read_parquet(DATA_DIR / "v2_digitalization.parquet")
    digi = digi[digi["招聘发布年份"].isin(YEAR_RANGE)].copy()
    tools = pd.read_parquet(DATA_DIR / "v2_tech_tools.parquet")
    tools = tools[tools["招聘发布年份"].isin(YEAR_RANGE)].copy()
    soft = pd.read_parquet(DATA_DIR / "v2_soft_skills.parquet")
    soft = soft[soft["招聘发布年份"].isin(YEAR_RANGE)].copy()
    return digi, tools, soft


def annual_digi_summary(digi: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for y in YEAR_RANGE:
        sub = digi[digi["招聘发布年份"] == y]
        rows.append({
            "year": y,
            "n": len(sub),
            "数字化程度_均值": round(sub["数字化程度"].mean(), 2),
            "数字化程度_中位": round(sub["数字化程度"].median(), 1),
            "数字化程度_p25": round(sub["数字化程度"].quantile(0.25), 1),
            "数字化程度_p75": round(sub["数字化程度"].quantile(0.75), 1),
            "AI相关性_均值": round(sub["AI相关性"].mean(), 2),
            "AI相关性_中位": round(sub["AI相关性"].median(), 1),
            "AI相关性_p75": round(sub["AI相关性"].quantile(0.75), 1),
            "技术复杂度_均值": round(sub["技术复杂度"].mean(), 2),
            "技术复杂度_中位": round(sub["技术复杂度"].median(), 1),
        })
    return pd.DataFrame(rows)


def annual_digi_by_category(digi: pd.DataFrame) -> pd.DataFrame:
    """按 (年份, 岗位类别) 分组的数字化均值。"""
    if "岗位类别" not in digi.columns:
        return pd.DataFrame()
    pivot = digi.groupby(["招聘发布年份", "岗位类别"])[
        ["数字化程度", "AI相关性", "技术复杂度"]
    ].mean().round(2).reset_index()
    return pivot


def annual_top_tools(tools: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    """每年 Top N 工具频次（不归一化，原始名）。"""
    rows = []
    for y in YEAR_RANGE:
        sub = tools[tools["招聘发布年份"] == y]
        c = Counter()
        for val in sub["tools"].dropna():
            items = list(val) if hasattr(val, "__iter__") and not isinstance(val, str) else []
            for x in items:
                if isinstance(x, str) and x.strip():
                    c[x.strip()] += 1
        for rank, (tool, freq) in enumerate(c.most_common(top_n), 1):
            rows.append({"year": y, "rank": rank, "tool": tool, "freq": freq})
    return pd.DataFrame(rows)


# ============== 可视化 ==============
def fig_digi_trend(annual: pd.DataFrame):
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.5))
    dims = [("数字化程度_均值", "数字化程度", COLORS[0]),
            ("AI相关性_均值", "AI 相关性", COLORS[1]),
            ("技术复杂度_均值", "技术复杂度", COLORS[2])]
    for ax, (col, label, color) in zip(axes, dims):
        ax.plot(annual["year"], annual[col], "o-", lw=2.4, ms=10, color=color)
        for _, r in annual.iterrows():
            ax.text(r["year"], r[col] + 1.0, f'{r[col]:.1f}',
                    ha="center", fontsize=10, color="#333")
        ax.set_title(f"{label}（满分100）逐年均值", fontsize=12)
        ax.set_xlabel("年份")
        ax.set_xticks(annual["year"])
        ax.grid(alpha=0.25)
        ax.set_ylim(0, max(annual[col].max() * 1.25, 12))
    plt.tight_layout()
    plt.savefig(FIG_DIR / "fig_v4_a01_digi_trend.png", dpi=300, bbox_inches="tight")
    plt.savefig(FIG_DIR / "fig_v4_a01_digi_trend.pdf", bbox_inches="tight")
    plt.close()
    print("  ✓ fig_v4_a01_digi_trend")


def fig_digi_by_category(by_cat: pd.DataFrame):
    if by_cat.empty:
        return
    pivot = by_cat.pivot(index="岗位类别", columns="招聘发布年份", values="数字化程度")
    pivot = pivot.loc[pivot.mean(axis=1).sort_values(ascending=False).index]
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.heatmap(pivot, cmap="YlOrRd", annot=True, fmt=".1f",
                cbar_kws={"label": "数字化程度均值"}, ax=ax,
                linewidths=0.4, linecolor="white")
    ax.set_title("各岗位类别数字化程度均值（按年份）", fontsize=12, pad=10)
    ax.set_xlabel("年份")
    ax.set_ylabel("")
    plt.tight_layout()
    plt.savefig(FIG_DIR / "fig_v4_a02_digi_by_category_year.png", dpi=300, bbox_inches="tight")
    plt.savefig(FIG_DIR / "fig_v4_a02_digi_by_category_year.pdf", bbox_inches="tight")
    plt.close()
    print("  ✓ fig_v4_a02_digi_by_category_year")


def fig_top_tools_yearly(top_tools: pd.DataFrame):
    """画 Top10 工具的年度排名变化。"""
    if top_tools.empty:
        return
    # 取四年合并 Top15 工具
    overall = top_tools.groupby("tool")["freq"].sum().sort_values(ascending=False).head(12)
    pivot = top_tools[top_tools["tool"].isin(overall.index)].pivot(
        index="tool", columns="year", values="freq"
    ).fillna(0).loc[overall.index]
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.heatmap(pivot.astype(int), cmap="Blues", annot=True, fmt="d",
                cbar_kws={"label": "出现频次"}, ax=ax,
                linewidths=0.4, linecolor="white")
    ax.set_title("需求侧 Top12 工具的年度频次（2021—2024）", fontsize=12, pad=10)
    ax.set_xlabel("年份")
    ax.set_ylabel("")
    plt.tight_layout()
    plt.savefig(FIG_DIR / "fig_v4_a03_top_tools_yearly.png", dpi=300, bbox_inches="tight")
    plt.savefig(FIG_DIR / "fig_v4_a03_top_tools_yearly.pdf", bbox_inches="tight")
    plt.close()
    print("  ✓ fig_v4_a03_top_tools_yearly")


def main():
    print("=" * 60)
    print("V4 — Step 1：需求侧逐年数字化进展")
    print("=" * 60)

    digi, tools, soft = load()
    print(f"  数字化记录：{len(digi):,}（2021—2024）")
    print(f"  工具记录：{len(tools):,}")
    print(f"  软技能记录：{len(soft):,}")

    annual = annual_digi_summary(digi)
    print("\n=== 逐年数字化均值 ===")
    print(annual.to_string(index=False))

    by_cat = annual_digi_by_category(digi)
    if not by_cat.empty:
        print("\n=== 按 (年份, 岗位类别) 的数字化均值 — 部分 ===")
        print(by_cat.head(15).to_string(index=False))

    top_tools = annual_top_tools(tools, top_n=10)
    print("\n=== 每年 Top5 工具 ===")
    print(top_tools[top_tools["rank"] <= 5].to_string(index=False))

    annual.to_parquet(DATA_DIR / "v4_demand_annual.parquet", index=False)
    by_cat.to_parquet(DATA_DIR / "v4_demand_by_year_category.parquet", index=False)
    top_tools.to_parquet(DATA_DIR / "v4_demand_top_tools_yearly.parquet", index=False)
    print(f"\n输出：data/v4_demand_annual.parquet 等三份")

    print("\n=== 生成图表 ===")
    fig_digi_trend(annual)
    fig_digi_by_category(by_cat)
    fig_top_tools_yearly(top_tools)

    print("\n=== Step 1 完成 ===")


if __name__ == "__main__":
    main()
