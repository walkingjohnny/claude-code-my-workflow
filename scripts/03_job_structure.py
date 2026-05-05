# ============================================================
# 03_job_structure.py
# 用途：招聘岗位结构分析——岗位类别、学历、经验、薪资
# 输出：Figures/fig06_top30_job_titles.png/.pdf
#        Figures/fig07_education_dist.png/.pdf
#        Figures/fig08_experience_dist.png/.pdf
#        Figures/fig09_salary_boxplot.png/.pdf
#        Figures/fig10_chuji_dist.png/.pdf
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
)

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# --- 初始化 ---
setup_style()
df, _ = load_filtered_data()

# 项目名称常量（含 Unicode 引号）
PROJ_TITLE = '\u6df1\u5733\u5e02\u4e13\u7cbe\u7279\u65b0\u201c\u5c0f\u5de8\u4eba\u201d\u4f01\u4e1a'

# ============================================================
# 图 6：Top 30 招聘岗位（横向条形图）
# ============================================================
print('\n生成图6：Top 30 招聘岗位 ...')

top_jobs = df['招聘岗位'].value_counts().head(30)

fig, ax = plt.subplots(figsize=(10, 10))

bar_colors = [COLORS[i % 4] for i in range(len(top_jobs))]
bars = ax.barh(
    range(len(top_jobs) - 1, -1, -1),
    top_jobs.values,
    color=bar_colors,
    alpha=0.82,
    height=0.72,
)

for i, (job, cnt) in enumerate(zip(top_jobs.index, top_jobs.values)):
    ax.text(cnt + 1, len(top_jobs) - 1 - i, f'{cnt}', va='center', fontsize=9)

ax.set_yticks(range(len(top_jobs)))
ax.set_yticklabels(top_jobs.index[::-1], fontsize=10)
ax.set_xlabel('招聘条数', fontsize=11)
ax.set_title(
    f'{PROJ_TITLE}招聘岗位 Top 30（2016\u20132025）',
    fontsize=14, fontweight='bold', pad=12
)
ax.set_xlim(0, max(top_jobs.values) * 1.15)

# 注释
ax.text(
    0.99, 0.01,
    f'注：分析样本 N=22,022，唯一岗位名称 {df["招聘岗位"].nunique():,} 个',
    transform=ax.transAxes, fontsize=8, ha='right', va='bottom', color=COLOR_NEUTRAL
)

plt.tight_layout()
save_fig('fig06_top30_job_titles')

# ============================================================
# 图 7：学历要求分布
# ============================================================
print('\n生成图7：学历要求分布 ...')

# 合并相似类别
edu_map = {
    '本科': '本科',
    '大专': '大专',
    '中专/中技': '中专/技校',
    '中专': '中专/技校',
    '技校': '中专/技校',
    '高中': '高中及以下',
    '初中及以下': '高中及以下',
    '硕士': '硕士及以上',
    '博士': '硕士及以上',
    '不限': '学历不限',
    '学历不限': '学历不限',
}
df['学历分类'] = df['学历要求'].map(edu_map).fillna('其他')

edu_order = ['本科', '大专', '中专/技校', '高中及以下', '硕士及以上', '学历不限', '其他']
edu_counts = df['学历分类'].value_counts().reindex(edu_order, fill_value=0)
edu_pcts = edu_counts / edu_counts.sum() * 100

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

# 左：条形图
bar_clrs = COLORS[:len(edu_order)]
bars = ax1.bar(range(len(edu_order)), edu_counts.values, color=bar_clrs, alpha=0.85, width=0.65)
for i, (cnt, pct) in enumerate(zip(edu_counts.values, edu_pcts.values)):
    ax1.text(i, cnt + 50, f'{cnt:,}\n({pct:.1f}%)', ha='center', va='bottom', fontsize=9)
ax1.set_xticks(range(len(edu_order)))
ax1.set_xticklabels(edu_order, fontsize=9, rotation=15, ha='right')
ax1.set_ylabel('招聘条数', fontsize=11)
ax1.set_title('学历要求分布', fontsize=13, fontweight='bold')
ax1.set_ylim(0, max(edu_counts.values) * 1.2)

# 右：饼图
wedge_clrs = COLORS[:len(edu_order)]
wedges, texts, autotexts = ax2.pie(
    edu_pcts.values,
    labels=edu_order,
    colors=wedge_clrs,
    autopct='%1.1f%%',
    startangle=90,
    pctdistance=0.78,
)
for text in texts:
    text.set_fontsize(9)
for autotext in autotexts:
    autotext.set_fontsize(8.5)
    autotext.set_fontweight('bold')
ax2.set_title('学历要求构成', fontsize=13, fontweight='bold')

fig.suptitle(
    f'{PROJ_TITLE}招聘学历要求分布（2016\u20132025）',
    fontsize=14, fontweight='bold', y=1.01
)
plt.tight_layout()
save_fig('fig07_education_dist')

# ============================================================
# 图 8：工作经验要求分布
# ============================================================
print('\n生成图8：工作经验要求分布 ...')

exp_counts = df['要求经验'].value_counts()

# 定义排序顺序
exp_order = [
    '不限', '1年以下', '1-3年', '3-5年', '5-10年', '10年以上'
]
exp_counts_ordered = exp_counts.reindex(
    [e for e in exp_order if e in exp_counts.index],
    fill_value=0
)
# 追加不在预定列表中的类别
others = exp_counts[~exp_counts.index.isin(exp_order)]
if len(others) > 0:
    exp_counts_ordered = pd.concat([exp_counts_ordered, others])

exp_pcts = exp_counts_ordered / exp_counts_ordered.sum() * 100

fig, ax = plt.subplots(figsize=(10, 5))
bar_clrs = COLORS[:len(exp_counts_ordered)]
bars = ax.bar(range(len(exp_counts_ordered)), exp_counts_ordered.values,
              color=bar_clrs, alpha=0.85, width=0.65)

for i, (cnt, pct) in enumerate(zip(exp_counts_ordered.values, exp_pcts.values)):
    ax.text(i, cnt + 50, f'{cnt:,}\n({pct:.1f}%)', ha='center', va='bottom', fontsize=9)

ax.set_xticks(range(len(exp_counts_ordered)))
ax.set_xticklabels(exp_counts_ordered.index, fontsize=10)
ax.set_ylabel('招聘条数', fontsize=11)
ax.set_title(
    f'{PROJ_TITLE}招聘工作经验要求分布（2016\u20132025）',
    fontsize=14, fontweight='bold', pad=12
)
ax.set_ylim(0, max(exp_counts_ordered.values) * 1.2)
plt.tight_layout()
save_fig('fig08_experience_dist')

# ============================================================
# 图 9：薪资箱线图（按学历分组）
# ============================================================
print('\n生成图9：薪资箱线图（按学历）...')

df_sal = df.copy()
df_sal['最低月薪'] = pd.to_numeric(df_sal['最低月薪'], errors='coerce')
df_sal['最高月薪'] = pd.to_numeric(df_sal['最高月薪'], errors='coerce')
df_sal['平均月薪'] = (df_sal['最低月薪'] + df_sal['最高月薪']) / 2
df_sal = df_sal.dropna(subset=['平均月薪'])
df_sal = df_sal[(df_sal['平均月薪'] > 0) & (df_sal['平均月薪'] < 100000)]  # 去除极端值

edu_for_box = ['大专', '本科', '硕士及以上', '学历不限']
df_sal['学历分类'] = df_sal['学历要求'].map(edu_map).fillna('其他')

box_data = [df_sal[df_sal['学历分类'] == edu]['平均月薪'].dropna().values
            for edu in edu_for_box]
n_labels = [f'{edu}\n(n={len(d):,})' for edu, d in zip(edu_for_box, box_data)]

fig, ax = plt.subplots(figsize=(10, 5))
bp = ax.boxplot(
    box_data,
    labels=n_labels,
    patch_artist=True,
    medianprops=dict(color='white', linewidth=2.5),
    whiskerprops=dict(linewidth=1.2),
    capprops=dict(linewidth=1.2),
    flierprops=dict(marker='o', markersize=3, alpha=0.3),
    widths=0.55,
)
for patch, color in zip(bp['boxes'], COLORS[:4]):
    patch.set_facecolor(color)
    patch.set_alpha(0.75)

ax.set_ylabel('平均月薪（元）', fontsize=11)
ax.set_title(
    f'{PROJ_TITLE}招聘薪资分布（按学历，2016\u20132025）',
    fontsize=14, fontweight='bold', pad=12
)
ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f'{int(x):,}'))

# 标注中位数
for i, d in enumerate(box_data):
    if len(d) > 0:
        median = np.median(d)
        ax.text(i + 1, median + 300, f'{median:,.0f}', ha='center', fontsize=9, color='#333333')

ax.text(
    0.99, 0.01,
    '注：已剔除平均月薪为0或超10万的异常值',
    transform=ax.transAxes, fontsize=8, ha='right', va='bottom', color=COLOR_NEUTRAL
)

plt.tight_layout()
save_fig('fig09_salary_boxplot')

# ============================================================
# 图 10：初级分类分布（含空值占比说明）
# ============================================================
print('\n生成图10：初级分类分布 ...')

chuji_all = df['初级分类'].copy()
n_total = len(chuji_all)
n_empty = (chuji_all.isna() | (chuji_all == '')).sum()
n_filled = n_total - n_empty

chuji_top = (
    chuji_all.replace('', pd.NA)
    .dropna()
    .value_counts()
    .head(15)
)

fig, ax = plt.subplots(figsize=(10, 6))

# 展示 Top 15，最后一条为"其他（含空值）"
labels = list(chuji_top.index) + [f'空值\n（未分类）']
values = list(chuji_top.values) + [n_empty]
clrs = COLORS[:len(chuji_top)] + [COLOR_NEUTRAL]

bars = ax.barh(range(len(labels) - 1, -1, -1), values, color=clrs, alpha=0.85, height=0.68)

for i, (lbl, cnt) in enumerate(zip(labels, values)):
    pct = cnt / n_total * 100
    ax.text(cnt + 10, len(labels) - 1 - i, f'{cnt:,}  ({pct:.1f}%)', va='center', fontsize=9)

ax.set_yticks(range(len(labels)))
ax.set_yticklabels(labels[::-1], fontsize=9.5)
ax.set_xlabel('招聘条数', fontsize=11)
ax.set_title(
    f'{PROJ_TITLE}招聘岗位初级分类分布',
    fontsize=14, fontweight='bold', pad=12
)
ax.set_xlim(0, max(values) * 1.25)

# 空值占比注释框
ax.annotate(
    f'空值占总样本 {n_empty/n_total:.1%}\n（共 {n_empty:,} 条缺失初级分类）\n→ 需补充分类方案',
    xy=(n_empty, 0), xytext=(n_empty * 0.5, 3),
    fontsize=9, color='#8B0000',
    arrowprops=dict(arrowstyle='->', color='#8B0000', lw=1.2),
    bbox=dict(boxstyle='round,pad=0.4', facecolor='#fff5f5', edgecolor='#cc0000', alpha=0.9)
)

plt.tight_layout()
save_fig('fig10_chuji_dist')

# ============================================================
# 运行摘要
# ============================================================
print('\n===== 运行摘要 =====')
print(f'分析样本：{len(df):,} 条')
print(f'唯一岗位名称：{df["招聘岗位"].nunique():,} 个')
print(f'初级分类填充率：{n_filled/n_total:.1%}（{n_filled:,}/{n_total:,}）')
print(f'薪资有效样本：{len(df_sal):,} 条（{len(df_sal)/len(df):.1%}）')
print(f'输出图表：Figures/fig06 \u2013 fig10')
print('====================')
