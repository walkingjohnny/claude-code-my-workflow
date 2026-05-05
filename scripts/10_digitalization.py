# ============================================================
# 10_digitalization.py
# 用途：V2研究 - 对每条职位描述评分三个维度（0-100）：
#       数字化程度、AI相关性、技术复杂度
#       追踪历年均值趋势，分析各岗位类别评分分布
# 输出：data/v2_digitalization.parquet
#       Figures/fig32_digitalization_trend.png/.pdf
#       Figures/fig33_digitalization_category_boxplot.png/.pdf
#       Figures/fig34_digitalization_salary_scatter.png/.pdf
# 依赖：scripts/llm_client.py, scripts/_common.py
#       scripts/job_classified_data.csv
# ============================================================

import os
import sys
import pathlib

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import seaborn as sns

sys.path.insert(0, ".")
from scripts._common import setup_style, save_fig, RANDOM_SEED, COLORS
from scripts.llm_client import batch_rate

np.random.seed(RANDOM_SEED)

TASK_NAME = "digitalization"
OUTPUT_PARQUET = pathlib.Path("data/v2_digitalization.parquet")

ATTRIBUTES = {
    "数字化程度": "该岗位涉及数字化技术、信息系统、数字化工具的程度（0=完全不涉及，100=核心数字化岗位）",
    "AI相关性": "该岗位与人工智能、机器学习、数据科学的相关程度（0=完全不涉及，100=AI核心岗位）",
    "技术复杂度": "该岗位要求的技术技能深度和复杂程度（0=无技术要求，100=高度专业技术岗位）",
}


def run_rating(df: pd.DataFrame, reset: bool = False) -> pd.DataFrame:
    df = df.copy()
    df["jd_id"] = [f"JD_{i:05d}" for i in range(len(df))]
    return batch_rate(
        df=df,
        id_column="jd_id",
        text_column="职位描述",
        task_name=TASK_NAME,
        attributes=ATTRIBUTES,
        batch_size=10,
        reset=reset,
    )


def plot_trend(year_means: pd.DataFrame, fig_name: str = "fig32_digitalization_trend"):
    """图32：三维评分历年均值趋势。"""
    dim_colors = {
        "数字化程度": COLORS[0],
        "AI相关性": COLORS[1],
        "技术复杂度": COLORS[2],
    }
    fig, ax = plt.subplots(figsize=(10, 6))
    for dim, color in dim_colors.items():
        if dim in year_means.columns:
            ax.plot(year_means.index, year_means[dim], marker="o",
                    linewidth=2.2, color=color, label=dim)
    ax.set_xlabel("年份", fontsize=11)
    ax.set_ylabel("平均评分（0-100）", fontsize=11)
    ax.set_title(
        '\u6df1\u5733\u5e02\u4e13\u7cbe\u7279\u65b0\u201c\u5c0f\u5de8\u4eba\u201d\u4f01\u4e1a\u5c97\u4f4d\u6570\u5b57\u5316\u6307\u6807\u5386\u5e74\u8d8b\u52bf',
        fontsize=13, pad=12
    )
    ax.legend(fontsize=10)
    ax.set_ylim(0, 100)
    ax.xaxis.set_major_locator(mticker.MultipleLocator(1))
    plt.xticks(rotation=30)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    # 2019注释
    if 2019 in year_means.index:
        pass
    else:
        ax.axvspan(2018.5, 2019.5, alpha=0.1, color="gray", label="数据缺失")
    plt.tight_layout()
    save_fig(fig_name)
    print("fig32 已保存")


def plot_category_boxplot(merged: pd.DataFrame, cat_col: str, fig_name: str = "fig33_digitalization_category_boxplot"):
    """图33：各岗位类别数字化评分箱线图。"""
    valid = merged[[cat_col, "数字化程度", "AI相关性", "技术复杂度"]].dropna()
    cat_order = valid.groupby(cat_col)["数字化程度"].median().sort_values(ascending=False).index.tolist()

    fig, axes = plt.subplots(1, 3, figsize=(16, 6), sharey=False)
    dims = ["数字化程度", "AI相关性", "技术复杂度"]
    colors = [COLORS[0], COLORS[1], COLORS[2]]

    for ax, dim, color in zip(axes, dims, colors):
        data_by_cat = [valid[valid[cat_col] == cat][dim].dropna().values for cat in cat_order]
        bp = ax.boxplot(data_by_cat, vert=True, patch_artist=True,
                        medianprops=dict(color="white", linewidth=2))
        for patch in bp["boxes"]:
            patch.set_facecolor(color)
            patch.set_alpha(0.7)
        ax.set_xticklabels(cat_order, rotation=40, ha="right", fontsize=8)
        ax.set_ylabel("评分（0-100）", fontsize=10)
        ax.set_title(dim, fontsize=11)
        ax.set_ylim(0, 105)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

    fig.suptitle(
        '\u5404\u5c97\u4f4d\u7c7b\u522b\u6570\u5b57\u5316\u8bc4\u5206\u5206\u5e03',
        fontsize=13, y=1.01
    )
    plt.tight_layout()
    save_fig(fig_name)
    print("fig33 已保存")


def plot_salary_scatter(merged: pd.DataFrame, cat_col: str, fig_name: str = "fig34_digitalization_salary_scatter"):
    """图34：数字化程度×薪资散点图（按类别着色）。"""
    merged = merged.copy()
    merged["mid_salary"] = (
        pd.to_numeric(merged.get("最低月薪"), errors="coerce") +
        pd.to_numeric(merged.get("最高月薪"), errors="coerce")
    ) / 2
    valid = merged[["数字化程度", "mid_salary", cat_col]].dropna()
    valid = valid[(valid["mid_salary"] > 0) & (valid["mid_salary"] < 80000)]

    cats = valid[cat_col].value_counts().head(6).index.tolist()
    colors_map = {cat: COLORS[i % len(COLORS)] for i, cat in enumerate(cats)}

    fig, ax = plt.subplots(figsize=(10, 7))
    for cat in cats:
        sub = valid[valid[cat_col] == cat]
        ax.scatter(sub["数字化程度"], sub["mid_salary"] / 1000,
                   alpha=0.3, s=15, color=colors_map[cat], label=cat)

    # 添加趋势线
    from numpy.polynomial.polynomial import polyfit
    x = valid["数字化程度"].values
    y = valid["mid_salary"].values / 1000
    coef = polyfit(x, y, 1)
    x_line = np.linspace(0, 100, 100)
    ax.plot(x_line, coef[0] + coef[1] * x_line, "k--", linewidth=1.5, alpha=0.6, label="趋势线")

    ax.set_xlabel("数字化程度评分（0-100）", fontsize=11)
    ax.set_ylabel("月薪中位数（千元）", fontsize=11)
    ax.set_title(
        '\u5c97\u4f4d\u6570\u5b57\u5316\u7a0b\u5ea6\u4e0e\u6708\u85aa\u7684\u5173\u8054\u5173\u7cfb',
        fontsize=13, pad=12
    )
    ax.legend(loc="upper left", fontsize=9, markerscale=2)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    plt.tight_layout()
    save_fig(fig_name)
    print("fig34 已保存")


def main():
    setup_style()
    os.makedirs("data", exist_ok=True)

    print("加载V1分类数据...")
    classified = pd.read_csv("scripts/job_classified_data.csv", encoding="utf-8-sig", low_memory=False)

    cat_col = "岗位类别" if "岗位类别" in classified.columns else None

    print("\n开始数字化评分（断点续传）...")
    classified["jd_id"] = [f"JD_{i:05d}" for i in range(len(classified))]
    result_df = run_rating(classified, reset=False)

    merged = classified.merge(result_df, on="jd_id", how="left")

    OUTPUT_PARQUET.parent.mkdir(exist_ok=True)
    save_cols = ["jd_id", "招聘岗位", "招聘发布年份", "数字化程度", "AI相关性", "技术复杂度"]
    if cat_col:
        save_cols.insert(3, cat_col)
    if "最低月薪" in merged.columns:
        save_cols += ["最低月薪", "最高月薪"]
    merged[save_cols].to_parquet(OUTPUT_PARQUET, index=False)
    print(f"结果已保存：{OUTPUT_PARQUET}")

    # ===== 图32：历年趋势 =====
    valid_years = sorted([
        int(y) for y in merged["招聘发布年份"].dropna().unique()
        if 2016 <= int(y) <= 2024
    ])
    dims = list(ATTRIBUTES.keys())
    year_means = {}
    for y in valid_years:
        mask = merged["招聘发布年份"].astype(float) == y
        year_means[y] = {d: merged.loc[mask, d].mean() for d in dims}
    year_means_df = pd.DataFrame(year_means).T
    print("\n各年度平均评分：")
    print(year_means_df.round(1).to_string())
    plot_trend(year_means_df)

    # ===== 图33：各类别评分分布 =====
    if cat_col:
        plot_category_boxplot(merged, cat_col)

    # ===== 图34：数字化×薪资 =====
    if cat_col and "最低月薪" in merged.columns:
        plot_salary_scatter(merged, cat_col)

    valid_count = merged["数字化程度"].notna().sum()
    print(f"\n===== 运行摘要 =====")
    print(f"分析样本：{len(merged):,}条")
    print(f"评分成功率：{valid_count/len(merged):.1%}（{valid_count:,}/{len(merged):,}）")
    print(f"数字化程度均值：{merged['数字化程度'].mean():.1f}")
    print(f"AI相关性均值：{merged['AI相关性'].mean():.1f}")
    print(f"技术复杂度均值：{merged['技术复杂度'].mean():.1f}")
    print(f"输出数据：{OUTPUT_PARQUET}")
    print(f"输出图表：fig32–fig34")
    print("====================")


if __name__ == "__main__":
    main()
