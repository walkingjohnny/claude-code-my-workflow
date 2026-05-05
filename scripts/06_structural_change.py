# ============================================================
# 06_structural_change.py
# 用途：历年岗位类别构成变迁分析（核心分析）
# 依赖：scripts/job_classified_data.csv（由 05 生成）
# 输出：Figures/fig17_category_stacked_area.png/.pdf
#        Figures/fig18_category_heatmap_year.png/.pdf
#        Figures/fig19_top_categories_trend.png/.pdf
#        Figures/fig20_education_by_category.png/.pdf
# ============================================================

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from _common import COLORS, COLOR_PRIMARY, COLOR_NEUTRAL, setup_style, save_fig

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import matplotlib.patches as mpatches

# --- 初始化 ---
setup_style()

PROJ = '深圳市专精特新\u201c小巨人\u201d企业'
DATA_FILE = os.path.join(os.path.dirname(__file__), 'job_classified_data.csv')

print(f'加载分类数据：{DATA_FILE}')
df = pd.read_csv(DATA_FILE, encoding='utf-8-sig', low_memory=False)
df['招聘发布年份'] = pd.to_numeric(df['招聘发布年份'], errors='coerce').fillna(0).astype(int)
df = df[df['招聘发布年份'] > 0]
print(f'  加载完成：{len(df):,} 条')

# 年份与类别配置
ALL_YEARS = list(range(2016, 2026))
MISSING_YEARS = [2019]   # 无数据
SPARSE_YEARS = [2020]    # 极少（2条）
PARTIAL_YEARS = [2025]   # 数据未完整

# 展示顺序（从大到小，按整体频次）
CAT_ORDER = ['研发技术', '销售市场', '信息技术', '生产制造',
             '行政人力', '供应链采购', '质量检验', '管理运营', '财务会计', '其他']

# 配色：9类+其他
CAT_COLORS = {
    '研发技术':   COLORS[0],   # 深蓝
    '销售市场':   COLORS[1],   # 橙
    '信息技术':   COLORS[2],   # 绿
    '生产制造':   COLORS[3],   # 红橙
    '行政人力':   COLORS[4],   # 紫
    '供应链采购': COLORS[5],   # 浅蓝
    '质量检验':   '#8B4513',   # 棕
    '管理运营':   COLORS[6],   # 黄
    '财务会计':   '#2E8B57',   # 深绿
    '其他':       COLOR_NEUTRAL,
}

# 构建年份×类别交叉表（绝对值）
pivot_abs = (
    df.groupby(['招聘发布年份', '岗位类别'])
    .size()
    .unstack(fill_value=0)
    .reindex(ALL_YEARS, fill_value=0)
)
# 补充缺失列
for cat in CAT_ORDER:
    if cat not in pivot_abs.columns:
        pivot_abs[cat] = 0
pivot_abs = pivot_abs[CAT_ORDER]

# 相对占比
pivot_pct = pivot_abs.div(pivot_abs.sum(axis=1).replace(0, np.nan), axis=0) * 100


def annotate_special_years(ax, y_top, fontsize=8):
    """在图上标注缺失/稀少/不完整年份。"""
    for yr in MISSING_YEARS:
        ax.axvline(x=ALL_YEARS.index(yr), color='#888', linestyle=':', linewidth=1, alpha=0.7)
        ax.text(ALL_YEARS.index(yr), y_top * 0.97, '数据\n缺失',
                ha='center', va='top', fontsize=fontsize, color='#666')
    for yr in SPARSE_YEARS:
        ax.axvline(x=ALL_YEARS.index(yr), color=COLORS[3], linestyle=':', linewidth=1, alpha=0.5)
        ax.text(ALL_YEARS.index(yr), y_top * 0.97, f'{yr}\n极少',
                ha='center', va='top', fontsize=fontsize, color=COLORS[3])
    for yr in PARTIAL_YEARS:
        ax.text(ALL_YEARS.index(yr), y_top * 0.97, '截至\n7月',
                ha='center', va='top', fontsize=fontsize, color='#888')


# ============================================================
# 图 17：岗位类别构成堆积面积图（绝对值）
# ============================================================
print('\n生成图17：堆积面积图 ...')

x = list(range(len(ALL_YEARS)))
x_labels = [str(y) for y in ALL_YEARS]

fig, ax = plt.subplots(figsize=(13, 6))

bottom = np.zeros(len(ALL_YEARS))
for cat in CAT_ORDER:
    vals = pivot_abs[cat].values.astype(float)
    ax.fill_between(x, bottom, bottom + vals,
                    color=CAT_COLORS[cat], alpha=0.82, label=cat, step=None)
    bottom += vals

annotate_special_years(ax, y_top=max(pivot_abs.sum(axis=1)) * 1.05)

ax.set_xticks(x)
ax.set_xticklabels(x_labels, fontsize=10)
ax.set_xlabel('年份', fontsize=11)
ax.set_ylabel('招聘条数', fontsize=11)
ax.set_ylim(0, max(pivot_abs.sum(axis=1)) * 1.15)
ax.set_title(
    f'{PROJ}招聘岗位类别构成变迁（2016\u20132025）',
    fontsize=14, fontweight='bold', pad=12
)
ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x_, _: f'{int(x_):,}'))
ax.legend(loc='upper left', fontsize=9, ncol=2, framealpha=0.9)

plt.tight_layout()
save_fig('fig17_category_stacked_area')

# ============================================================
# 图 18：类别×年份热力图（相对占比）
# ============================================================
print('\n生成图18：类别×年份热力图 ...')

# 只用有效年份（>5条）
valid_years = [y for y in ALL_YEARS if pivot_abs.loc[y].sum() > 5]
heat_data = pivot_pct.loc[valid_years][CAT_ORDER].T  # 行=类别，列=年份

fig, ax = plt.subplots(figsize=(13, 6))
im = ax.imshow(heat_data.values, aspect='auto', cmap='YlOrRd', vmin=0, vmax=40)

for i in range(len(CAT_ORDER)):
    for j in range(len(valid_years)):
        val = heat_data.values[i, j]
        if not np.isnan(val) and val > 1.5:
            ax.text(j, i, f'{val:.0f}%', ha='center', va='center',
                    fontsize=8, color='white' if val > 28 else '#1a1a1a',
                    fontweight='bold' if val > 20 else 'normal')

ax.set_xticks(range(len(valid_years)))
ax.set_xticklabels([str(y) for y in valid_years], fontsize=10)
ax.set_yticks(range(len(CAT_ORDER)))
ax.set_yticklabels(CAT_ORDER, fontsize=10)
ax.set_xlabel('年份', fontsize=11)
ax.set_title(
    f'{PROJ}各岗位类别历年招聘占比热力图（%）',
    fontsize=14, fontweight='bold', pad=12
)
plt.colorbar(im, ax=ax, label='占当年总招聘条数（%）', shrink=0.9)
ax.text(0.99, 0.01, '注：2019年数据缺失，2020年极少（2条），均不列入',
        transform=ax.transAxes, fontsize=8, ha='right', va='bottom', color=COLOR_NEUTRAL)
plt.tight_layout()
save_fig('fig18_category_heatmap_year')

# ============================================================
# 图 19：主要类别历年招聘条数折线图
# ============================================================
print('\n生成图19：主要类别趋势折线图 ...')

# 展示前 6 大类别（排除其他）
top6_cats = [c for c in CAT_ORDER if c != '其他'][:6]

fig, ax = plt.subplots(figsize=(13, 6))

for cat in top6_cats:
    vals = pivot_abs[cat].values.astype(float)
    # 2019 设为 NaN 以产生断线
    vals_plot = vals.copy()
    vals_plot[ALL_YEARS.index(2019)] = np.nan

    color = CAT_COLORS[cat]
    ax.plot(x, vals_plot, color=color, linewidth=2.2,
            marker='o', markersize=6, markerfacecolor='white',
            markeredgewidth=2, label=cat, zorder=4)

# 2019 断线标注
ax.axvspan(ALL_YEARS.index(2019) - 0.4, ALL_YEARS.index(2019) + 0.4,
           alpha=0.08, color='grey')
ax.text(ALL_YEARS.index(2019), ax.get_ylim()[1] if ax.get_ylim()[1] > 0 else 2000,
        '2019\n无数据', ha='center', va='top', fontsize=8, color='#777')

# 2025 标注
ax.text(ALL_YEARS.index(2025) - 0.1, pivot_abs.loc[2025, '研发技术'] + 30,
        '2025截至7月', fontsize=7.5, color='#888', va='bottom')

ax.set_xticks(x)
ax.set_xticklabels(x_labels, fontsize=10)
ax.set_xlabel('年份', fontsize=11)
ax.set_ylabel('招聘条数', fontsize=11)
ax.set_title(
    f'{PROJ}主要岗位类别招聘条数趋势（2016\u20132025）',
    fontsize=14, fontweight='bold', pad=12
)
ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x_, _: f'{int(x_):,}'))
ax.legend(fontsize=10, loc='upper left', ncol=2, framealpha=0.9)
plt.tight_layout()
save_fig('fig19_top_categories_trend')

# ============================================================
# 图 20：各岗位类别学历要求分布（分组条形图）
# ============================================================
print('\n生成图20：各类别学历要求分布 ...')

edu_map = {
    '本科': '本科', '大专': '大专',
    '中专/中技': '中专/技校', '中专': '中专/技校', '技校': '中专/技校',
    '高中': '高中及以下', '初中及以下': '高中及以下',
    '硕士': '硕士及以上', '博士': '硕士及以上',
    '不限': '学历不限', '学历不限': '学历不限',
}
df['学历分类'] = df['学历要求'].map(edu_map).fillna('其他')

EDU_ORDER = ['大专', '本科', '中专/技校', '高中及以下', '硕士及以上', '学历不限']
EDU_COLORS = COLORS[:len(EDU_ORDER)]

# 只取主要功能类别（排除"其他"）
main_cats = [c for c in CAT_ORDER if c != '其他']

# 计算各类别内的学历构成（百分比）
edu_cross = (
    df[df['岗位类别'].isin(main_cats)]
    .groupby(['岗位类别', '学历分类'])
    .size()
    .unstack(fill_value=0)
)
for edu in EDU_ORDER:
    if edu not in edu_cross.columns:
        edu_cross[edu] = 0
edu_cross = edu_cross[EDU_ORDER]
edu_pct = edu_cross.div(edu_cross.sum(axis=1), axis=0) * 100
edu_pct = edu_pct.reindex(main_cats)

fig, ax = plt.subplots(figsize=(13, 6))

n_cats = len(main_cats)
n_edu = len(EDU_ORDER)
bar_width = 0.75 / n_edu
x_pos = np.arange(n_cats)

for j, (edu, color) in enumerate(zip(EDU_ORDER, EDU_COLORS)):
    offset = (j - n_edu / 2 + 0.5) * bar_width
    vals = edu_pct[edu].values
    ax.bar(x_pos + offset, vals, width=bar_width * 0.88,
           color=color, alpha=0.82, label=edu)

ax.set_xticks(x_pos)
ax.set_xticklabels(main_cats, fontsize=10)
ax.set_ylabel('占该类别招聘比例（%）', fontsize=11)
ax.set_ylim(0, 65)
ax.set_title(
    f'{PROJ}各岗位类别学历要求构成对比（2016\u20132025）',
    fontsize=14, fontweight='bold', pad=12
)
ax.legend(fontsize=9, loc='upper right', ncol=3, framealpha=0.9)
ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda y, _: f'{y:.0f}%'))

# 标注深信大主要层次（大专）
ax.axhline(y=38.2, color='#888', linestyle='--', linewidth=0.8, alpha=0.5)
ax.text(n_cats - 0.5, 39.5, '整体大专均值38.2%', fontsize=7.5, color='#888', ha='right')

plt.tight_layout()
save_fig('fig20_education_by_category')

# ============================================================
# 运行摘要
# ============================================================
print('\n===== 运行摘要 =====')
print(f'分析样本：{len(df):,} 条（含有效年份）')
print(f'年份范围：{min(valid_years)} \u2013 {max(valid_years)}（2019/2020 标注缺失）')
print(f'最大类别：研发技术（{pivot_abs["研发技术"].sum():,}条）')
print(f'增长最快类别（2016→2024）：')
for cat in top6_cats:
    v16 = pivot_abs.loc[2016, cat]
    v24 = pivot_abs.loc[2024, cat]
    chg = (v24 - v16) / (v16 + 1) * 100
    print(f'  {cat}: {v16} → {v24}（{chg:+.0f}%）')
print(f'输出图表：Figures/fig17 \u2013 fig20')
print('====================')
