# ============================================================
# 02_temporal_analysis.py
# 用途：历年招聘时间趋势分析
# 输出：Figures/fig03_annual_job_postings.png/.pdf
#        Figures/fig04_annual_company_count.png/.pdf
#        Figures/fig05_annual_avg_salary.png/.pdf
# ============================================================

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from _common import (
    RANDOM_SEED,
    COLORS,
    COLOR_PRIMARY,
    setup_style,
    load_filtered_data,
    save_fig,
)

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# --- 初始化 ---
setup_style()
df, _ = load_filtered_data()

# 年份清洗：转为整数，丢弃无效值
df["招聘发布年份"] = pd.to_numeric(df["招聘发布年份"], errors="coerce")
df_valid = df.dropna(subset=["招聘发布年份"]).copy()
df_valid["招聘发布年份"] = df_valid["招聘发布年份"].astype(int)

# 完整年份轴（2016–2025，含缺失年份）
all_years = list(range(2016, 2026))

# ============================================================
# 图 3：历年招聘条数折线图
# ============================================================
print("\n生成图3：历年招聘条数 ...")

annual_count = df_valid.groupby("招聘发布年份").size().reindex(all_years, fill_value=0)

fig, ax = plt.subplots(figsize=(11, 5))

# 正常年份和异常年份分开处理
normal_years = annual_count[annual_count > 10]
sparse_years = annual_count[(annual_count > 0) & (annual_count <= 10)]
missing_years = annual_count[annual_count == 0]

ax.plot(
    normal_years.index,
    normal_years.values,
    color=COLOR_PRIMARY,
    linewidth=2.2,
    marker="o",
    markersize=7,
    markerfacecolor="white",
    markeredgewidth=2,
    zorder=4,
    label="招聘条数",
)

# 标注数值
for yr, cnt in normal_years.items():
    ax.text(yr, cnt + 80, f"{cnt:,}", ha="center", va="bottom", fontsize=9, color=COLOR_PRIMARY)

# 标注稀疏年份（2020=2条）
for yr, cnt in sparse_years.items():
    ax.scatter(yr, cnt, color=COLORS[3], s=60, zorder=5)
    ax.text(yr, cnt + 80, f"{cnt}条", ha="center", va="bottom", fontsize=9, color=COLORS[3])

# 标注缺失年份（2019）
for yr in missing_years.index:
    ax.axvline(x=yr, color=COLORS[7], linestyle=":", linewidth=1.2, alpha=0.6)
    ax.text(yr, ax.get_ylim()[1] if ax.get_ylim()[1] > 0 else 5500,
            f"{yr}\n（无数据）", ha="center", va="top", fontsize=8.5, color=COLORS[7])

# 标注特殊事件
ax.axvspan(2019.5, 2020.5, alpha=0.06, color=COLORS[3])
ax.text(2020, 200, "疫情影响\n（数据极少）", ha="center", fontsize=8, color=COLORS[3], style="italic")

ax.set_xticks(all_years)
ax.set_xticklabels([str(y) for y in all_years], fontsize=10)
ax.set_xlabel("年份", fontsize=11)
ax.set_ylabel("招聘条数", fontsize=11)
ax.set_title('深圳市专精特新\u201c小巨人\u201d企业历年招聘条数（2016\u20132025）', fontsize=14, fontweight="bold", pad=12)
ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{int(x):,}"))
ax.set_ylim(0, max(annual_count.values) * 1.18)
ax.legend(fontsize=10)

plt.tight_layout()
save_fig("fig03_annual_job_postings")

# ============================================================
# 图 4：历年活跃招聘企业数量
# ============================================================
print("\n生成图4：历年活跃企业数量 ...")

annual_firms = (
    df_valid.groupby("招聘发布年份")["企业名称"]
    .nunique()
    .reindex(all_years, fill_value=0)
)

fig, ax = plt.subplots(figsize=(11, 5))

bar_colors = [
    COLORS[3] if annual_firms[y] <= 5 else (COLORS[7] if annual_firms[y] == 0 else COLOR_PRIMARY)
    for y in all_years
]

bars = ax.bar(all_years, annual_firms.values, color=bar_colors, alpha=0.82, width=0.65, zorder=3)

for yr, cnt in annual_firms.items():
    if cnt > 0:
        ax.text(yr, cnt + 1, f"{cnt}", ha="center", va="bottom", fontsize=9)

ax.set_xticks(all_years)
ax.set_xticklabels([str(y) for y in all_years], fontsize=10)
ax.set_xlabel("年份", fontsize=11)
ax.set_ylabel("企业数量（家）", fontsize=11)
ax.set_title(
    '深圳市专精特新\u201c小巨人\u201d企业历年活跃招聘企业数量（2016\u20132025）',
    fontsize=14,
    fontweight="bold",
    pad=12,
)
ax.set_ylim(0, max(annual_firms.values) * 1.15)

# 图例
import matplotlib.patches as mpatches
legend_patches = [
    mpatches.Patch(color=COLOR_PRIMARY, alpha=0.82, label="正常年份"),
    mpatches.Patch(color=COLORS[3], alpha=0.82, label="数据稀少年份"),
]
ax.legend(handles=legend_patches, fontsize=9)

plt.tight_layout()
save_fig("fig04_annual_company_count")

# ============================================================
# 图 5：历年平均薪资区间趋势
# ============================================================
print("\n生成图5：历年平均薪资 ...")

df_salary = df_valid.copy()
df_salary["最低月薪"] = pd.to_numeric(df_salary["最低月薪"], errors="coerce")
df_salary["最高月薪"] = pd.to_numeric(df_salary["最高月薪"], errors="coerce")
df_salary = df_salary.dropna(subset=["最低月薪", "最高月薪"])
df_salary = df_salary[(df_salary["最低月薪"] > 0) & (df_salary["最高月薪"] > 0)]
df_salary["平均月薪"] = (df_salary["最低月薪"] + df_salary["最高月薪"]) / 2

# 按年份计算均值（只含有效薪资记录）
salary_by_year = df_salary.groupby("招聘发布年份").agg(
    均值最低=("最低月薪", "mean"),
    均值最高=("最高月薪", "mean"),
    均值平均=("平均月薪", "mean"),
    样本量=("平均月薪", "count"),
).reindex([y for y in all_years if y not in missing_years.index and annual_firms.get(y, 0) > 5])

fig, ax = plt.subplots(figsize=(11, 5))

ax.fill_between(
    salary_by_year.index,
    salary_by_year["均值最低"],
    salary_by_year["均值最高"],
    alpha=0.15,
    color=COLOR_PRIMARY,
    label="薪资区间（最低–最高均值）",
)
ax.plot(
    salary_by_year.index,
    salary_by_year["均值最低"],
    color=COLORS[2],
    linewidth=1.8,
    marker="s",
    markersize=6,
    markerfacecolor="white",
    markeredgewidth=1.8,
    label="最低月薪（均值）",
)
ax.plot(
    salary_by_year.index,
    salary_by_year["均值最高"],
    color=COLOR_PRIMARY,
    linewidth=1.8,
    marker="o",
    markersize=6,
    markerfacecolor="white",
    markeredgewidth=1.8,
    label="最高月薪（均值）",
)
ax.plot(
    salary_by_year.index,
    salary_by_year["均值平均"],
    color=COLORS[1],
    linewidth=2.2,
    linestyle="--",
    marker="D",
    markersize=5,
    markerfacecolor=COLORS[1],
    label="平均月薪",
)

# 标注样本量
for yr, row in salary_by_year.iterrows():
    ax.text(yr, row["均值最低"] - 600, f"n={int(row['样本量'])}", ha="center", fontsize=7.5, color=COLORS[7])

ax.set_xticks(salary_by_year.index)
ax.set_xticklabels([str(y) for y in salary_by_year.index], fontsize=10)
ax.set_xlabel("年份", fontsize=11)
ax.set_ylabel("月薪（元）", fontsize=11)
ax.set_title(
    '深圳市专精特新\u201c小巨人\u201d企业历年招聘平均薪资趋势',
    fontsize=14,
    fontweight="bold",
    pad=12,
)
ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{int(x):,}"))
ax.legend(fontsize=9, loc="upper left")

# 注释（数据说明）
ax.text(
    0.99, 0.03,
    f"注：仅含薪资有效记录（共 {len(df_salary):,} 条，占样本 {len(df_salary)/len(df_valid):.0%}）；2019/2020年数据缺失，不绘制。",
    transform=ax.transAxes,
    fontsize=8,
    ha="right",
    va="bottom",
    color=COLORS[7],
)

plt.tight_layout()
save_fig("fig05_annual_avg_salary")

# ============================================================
# 运行摘要
# ============================================================
print("\n===== 运行摘要 =====")
print(f"数据文件：源数据/合并画像后_智联招聘数据库2016-2025.7.csv")
print(f"分析样本：{len(df_valid):,} 条记录（含有效年份）")
print(f"时间跨度：{df_valid['招聘发布年份'].min()} – {df_valid['招聘发布年份'].max()}")
print(f"缺失年份：{sorted(missing_years.index.tolist())}")
print(f"稀少年份：{sorted(sparse_years.index.tolist())}（各≤10条）")
print(f"薪资有效样本：{len(df_salary):,} 条（{len(df_salary)/len(df_valid):.1%}）")
print(f"输出图表：Figures/fig03 – fig05")
print("====================")
