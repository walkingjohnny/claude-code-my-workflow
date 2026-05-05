# ============================================================
# 01_data_overview.py
# 用途：数据质量概览——样本过滤瀑布图 + 关键字段缺失值热力图
# 输出：Figures/fig01_sample_filter_waterfall.png/.pdf
#        Figures/fig02_missing_values_heatmap.png/.pdf
# ============================================================

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from _common import (
    RANDOM_SEED,
    COLORS,
    COLOR_PRIMARY,
    COLOR_NEUTRAL,
    setup_style,
    load_filtered_data,
    save_fig,
    DATA_PATH,
)

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# --- 初始化 ---
setup_style()

# --- 加载数据 ---
df, filter_stats = load_filtered_data()
n_raw = filter_stats["raw"]
n_city = filter_stats["after_city"]
n_final = filter_stats["final"]

# ============================================================
# 图 1：样本过滤瀑布图
# ============================================================
print("\n生成图1：样本过滤瀑布图 ...")

fig, ax = plt.subplots(figsize=(9, 5))

steps = [
    ("原始数据", n_raw, COLORS[0]),
    ("过滤：目前所属城市\n= 深圳市", n_city, COLORS[2]),
    ("过滤：复核结果\n≠ 未见信息", n_final, COLORS[1]),
]

bar_width = 0.5
x_positions = [0, 1.4, 2.8]

for i, (label, val, color) in enumerate(steps):
    ax.bar(x_positions[i], val, width=bar_width, color=color, alpha=0.85, zorder=3)
    ax.text(
        x_positions[i],
        val + 200,
        f"{val:,}",
        ha="center",
        va="bottom",
        fontsize=12,
        fontweight="bold",
    )
    ax.text(
        x_positions[i],
        -1000,
        label,
        ha="center",
        va="top",
        fontsize=10,
    )

# 标注移除量
for i in range(1, len(steps)):
    prev_val = steps[i - 1][1]
    curr_val = steps[i][1]
    removed = prev_val - curr_val
    pct = removed / n_raw * 100
    mid_x = (x_positions[i - 1] + x_positions[i]) / 2
    mid_y = (prev_val + curr_val) / 2
    ax.annotate(
        f"－{removed:,}\n（{pct:.1f}%）",
        xy=(mid_x, mid_y),
        ha="center",
        va="center",
        fontsize=9,
        color="#D55E00",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="white", edgecolor="#D55E00", alpha=0.8),
    )

ax.set_xlim(-0.6, 3.4)
ax.set_ylim(-2000, n_raw * 1.12)
ax.set_xticks([])
ax.set_yticks([])
ax.spines["left"].set_visible(False)
ax.spines["bottom"].set_visible(False)
ax.set_title("分析样本筛选流程", fontsize=15, fontweight="bold", pad=15)

save_fig("fig01_sample_filter_waterfall")

# ============================================================
# 图 2：关键字段缺失值热力图
# ============================================================
print("\n生成图2：关键字段缺失值热力图 ...")

# 选取分析关键字段
key_cols = [
    "招聘岗位",
    "最低月薪",
    "最高月薪",
    "学历要求",
    "要求经验",
    "招聘人数",
    "招聘类别",
    "初级分类",
    "招聘发布年份",
    "入选批次",
    "国标行业门类",
    "国标行业大类",
    "企业规模",
    "目前所属区县",
    "技术关键词",
    "核心技术领域",
    "应用场景行业",
    "招聘岗位类型",
]

# 计算缺失率
missing_data = []
for col in key_cols:
    if col in df.columns:
        n_missing = df[col].isna().sum() + (df[col] == "").sum()
        missing_rate = n_missing / len(df) * 100
        missing_data.append((col, missing_rate, n_missing))

missing_data.sort(key=lambda x: -x[1])
cols_sorted = [x[0] for x in missing_data]
rates_sorted = [x[1] for x in missing_data]

fig, ax = plt.subplots(figsize=(10, 6))

bar_colors = [
    COLORS[3] if r > 50 else (COLORS[1] if r > 10 else COLORS[2])
    for r in rates_sorted
]

bars = ax.barh(
    range(len(cols_sorted)),
    rates_sorted,
    color=bar_colors,
    alpha=0.85,
    height=0.65,
)

# 标注数值
for i, (rate, n_miss) in enumerate(zip(rates_sorted, [x[2] for x in missing_data])):
    ax.text(
        rate + 0.5,
        i,
        f"{rate:.1f}%  （{n_miss:,}条）",
        va="center",
        fontsize=9,
    )

ax.set_yticks(range(len(cols_sorted)))
ax.set_yticklabels(cols_sorted, fontsize=10)
ax.set_xlabel("缺失率（%）", fontsize=11)
ax.set_xlim(0, 105)
ax.set_title("关键字段缺失率分析（分析样本 N=22,022）", fontsize=14, fontweight="bold", pad=12)
ax.axvline(x=50, color="#D55E00", linestyle="--", linewidth=1.0, alpha=0.6, label="50% 线")
ax.legend(fontsize=9)

# 图例说明
legend_patches = [
    mpatches.Patch(color=COLORS[3], alpha=0.85, label="严重缺失（>50%）"),
    mpatches.Patch(color=COLORS[1], alpha=0.85, label="中度缺失（10–50%）"),
    mpatches.Patch(color=COLORS[2], alpha=0.85, label="轻微缺失（<10%）"),
]
ax.legend(handles=legend_patches, loc="lower right", fontsize=9)

plt.tight_layout()
save_fig("fig02_missing_values_heatmap")

# ============================================================
# 数据质量控制台报告
# ============================================================
print("\n===== 数据质量摘要报告 =====")
print(f"数据文件：{DATA_PATH}")
print(f"分析样本：{n_final:,} 条记录 / 59 列")
print(f"随机种子：{RANDOM_SEED}")
print()
print("字段缺失率排名（Top 10）：")
for col, rate, n in missing_data[:10]:
    bar = "█" * int(rate / 5)
    print(f"  {col:<18} {rate:5.1f}%  {bar}")
print()
print("关键发现：")
print(f"  - 初级分类 缺失率：{next(r for c,r,n in missing_data if c=='初级分类'):.1f}%")
print(f"    → 岗位结构分析需补充分类方案")
print(f"  - 最低/最高月薪 有一定缺失，薪资分析需去除空值")
print("============================")
