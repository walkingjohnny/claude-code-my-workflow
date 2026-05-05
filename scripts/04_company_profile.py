# ============================================================
# 04_company_profile.py
# 用途：企业画像分析——行业、规模、入选批次、区县分布
# 输出：Figures/fig11_industry_bar.png/.pdf
#        Figures/fig12_company_size_pie.png/.pdf
#        Figures/fig13_batch_dist.png/.pdf
#        Figures/fig14_district_bar.png/.pdf
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
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# --- 初始化 ---
setup_style()
df, _ = load_filtered_data()

# 项目名称（含 Unicode 引号）
PROJ_TITLE = '\u6df1\u5733\u5e02\u4e13\u7cbe\u7279\u65b0\u201c\u5c0f\u5de8\u4eba\u201d\u4f01\u4e1a'

# 企业级唯一数据（每家企业一行）
df_firm = df.drop_duplicates(subset=['企业名称']).copy()
n_firms = len(df_firm)
print(f'\n唯一企业数量（按企业名称去重）：{n_firms} 家')

# ============================================================
# 图 11：国标行业门类分布（招聘条数视角）
# ============================================================
print('\n生成图11：国标行业门类分布（招聘条数）...')

industry_counts = df['国标行业门类'].value_counts()
industry_pcts = industry_counts / len(df) * 100

fig, ax = plt.subplots(figsize=(10, 5))

# Top 8 + 其他
top_n = 8
top_industries = industry_counts.head(top_n)
others_cnt = industry_counts.iloc[top_n:].sum()
plot_data = pd.concat([top_industries, pd.Series({'其他': others_cnt})])
plot_pcts = plot_data / len(df) * 100

bar_clrs = COLORS[:top_n] + [COLOR_NEUTRAL]
bars = ax.barh(
    range(len(plot_data) - 1, -1, -1),
    plot_data.values,
    color=bar_clrs, alpha=0.85, height=0.65
)

for i, (cnt, pct) in enumerate(zip(plot_data.values, plot_pcts.values)):
    ax.text(cnt + 20, len(plot_data) - 1 - i, f'{cnt:,}  ({pct:.1f}%)', va='center', fontsize=9.5)

ax.set_yticks(range(len(plot_data)))
ax.set_yticklabels(plot_data.index[::-1], fontsize=10.5)
ax.set_xlabel('招聘条数', fontsize=11)
ax.set_title(
    f'{PROJ_TITLE}招聘条数行业分布（国标一级）',
    fontsize=14, fontweight='bold', pad=12
)
ax.set_xlim(0, max(plot_data.values) * 1.25)
ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f'{int(x):,}'))

plt.tight_layout()
save_fig('fig11_industry_bar')

# ============================================================
# 图 12：企业规模分布（饼图，以企业为单位）
# ============================================================
print('\n生成图12：企业规模分布 ...')

# 规模标签映射
size_map = {
    'S(小型)': '小型（S）',
    'M(中型)': '中型（M）',
    'L(大型)': '大型（L）',
}
df_firm['规模标签'] = df_firm['企业规模'].map(size_map).fillna('未知')

size_counts_firm = df_firm['规模标签'].value_counts()

# 招聘条数维度
df['规模标签'] = df['企业规模'].map(size_map).fillna('未知')
size_counts_jobs = df['规模标签'].value_counts()

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

pie_clrs = [COLORS[0], COLORS[2], COLORS[1], COLOR_NEUTRAL]

for ax, data, subtitle in [
    (ax1, size_counts_firm, f'按企业数量（N={n_firms}家）'),
    (ax2, size_counts_jobs, f'按招聘条数（N=22,022条）'),
]:
    wedges, texts, autotexts = ax.pie(
        data.values,
        labels=data.index,
        colors=pie_clrs[:len(data)],
        autopct='%1.1f%%',
        startangle=140,
        pctdistance=0.72,
    )
    for text in texts:
        text.set_fontsize(11)
    for autotext in autotexts:
        autotext.set_fontsize(10)
        autotext.set_fontweight('bold')
    ax.set_title(subtitle, fontsize=12, pad=10)

fig.suptitle(
    f'{PROJ_TITLE}规模分布',
    fontsize=14, fontweight='bold', y=1.02
)
plt.tight_layout()
save_fig('fig12_company_size_pie')

# ============================================================
# 图 13：入选批次分布（条形图，以招聘条数和企业数两个维度）
# ============================================================
print('\n生成图13：入选批次分布 ...')

# 批次排序
batch_order = ['第一批', '第二批', '第三批', '第四批', '第五批', '第六批', '第七批']
batch_jobs = df['入选批次'].value_counts().reindex(batch_order, fill_value=0)
batch_firms = df_firm['入选批次'].value_counts().reindex(batch_order, fill_value=0)

fig, ax = plt.subplots(figsize=(11, 5))

x = range(len(batch_order))
width = 0.38

bars1 = ax.bar(
    [xi - width / 2 for xi in x], batch_jobs.values,
    width=width, color=COLOR_PRIMARY, alpha=0.85, label='招聘条数'
)
bars2 = ax.bar(
    [xi + width / 2 for xi in x], batch_firms.values,
    width=width, color=COLORS[1], alpha=0.85, label='企业数量（家）'
)

for bar in bars1:
    h = bar.get_height()
    ax.text(bar.get_x() + bar.get_width() / 2, h + 30, f'{h:,}',
            ha='center', va='bottom', fontsize=8.5, color=COLOR_PRIMARY)
for bar in bars2:
    h = bar.get_height()
    ax.text(bar.get_x() + bar.get_width() / 2, h + 5, f'{h}',
            ha='center', va='bottom', fontsize=8.5, color=COLORS[1])

ax.set_xticks(list(x))
ax.set_xticklabels(batch_order, fontsize=10)
ax.set_ylabel('数量', fontsize=11)
ax.set_title(
    f'{PROJ_TITLE}历批次入选分布',
    fontsize=14, fontweight='bold', pad=12
)

# 双 y 轴说明
ax.legend(fontsize=10)
ax.set_ylim(0, max(batch_jobs.values) * 1.18)

plt.tight_layout()
save_fig('fig13_batch_dist')

# ============================================================
# 图 14：企业所属区县分布（招聘条数）
# ============================================================
print('\n生成图14：企业区县分布 ...')

district_jobs = df['目前所属区县'].value_counts().head(12)
district_firms = df_firm['目前所属区县'].value_counts().reindex(district_jobs.index, fill_value=0)

fig, ax = plt.subplots(figsize=(10, 6))

bar_clrs = COLORS[:len(district_jobs)]
bars = ax.barh(
    range(len(district_jobs) - 1, -1, -1),
    district_jobs.values,
    color=bar_clrs, alpha=0.85, height=0.68
)

for i, (district, cnt) in enumerate(zip(district_jobs.index, district_jobs.values)):
    pct = cnt / len(df) * 100
    firm_cnt = district_firms[district]
    ax.text(
        cnt + 10, len(district_jobs) - 1 - i,
        f'{cnt:,}  ({pct:.1f}%)  [{firm_cnt}家]',
        va='center', fontsize=9
    )

ax.set_yticks(range(len(district_jobs)))
ax.set_yticklabels(district_jobs.index[::-1], fontsize=10.5)
ax.set_xlabel('招聘条数', fontsize=11)
ax.set_title(
    f'{PROJ_TITLE}区县分布（Top 12）',
    fontsize=14, fontweight='bold', pad=12
)
ax.set_xlim(0, max(district_jobs.values) * 1.3)
ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f'{int(x):,}'))

ax.text(
    0.99, 0.01,
    '注：括号内为招聘条数占比，方括号内为该区企业数量',
    transform=ax.transAxes, fontsize=8, ha='right', va='bottom', color=COLOR_NEUTRAL
)

plt.tight_layout()
save_fig('fig14_district_bar')

# ============================================================
# 运行摘要
# ============================================================
print('\n===== 运行摘要 =====')
print(f'分析样本：{len(df):,} 条招聘记录')
print(f'唯一企业：{n_firms} 家')
print(f'主要行业：制造业 {industry_counts.get("制造业", 0)/len(df):.1%}')
print(f'入选批次覆盖：{batch_order[0]} 至 {batch_order[-1]}')
print(f'输出图表：Figures/fig11 \u2013 fig14')
print('====================')
