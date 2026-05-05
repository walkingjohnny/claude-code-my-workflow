# ============================================================
# 07_skills_analysis.py
# 用途：技术关键词与技能需求趋势分析（产教对接视角）
# 依赖：scripts/job_classified_data.csv（由 05 生成）
# 输出：Figures/fig21_top_tech_keywords.png/.pdf
#        Figures/fig22_tech_trend_heatmap.png/.pdf
#        Figures/fig23_tech_category_matrix.png/.pdf
#        Figures/fig24_edu_trend_area.png/.pdf
# ============================================================

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from _common import COLORS, COLOR_PRIMARY, COLOR_NEUTRAL, setup_style, save_fig

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
from collections import Counter

# --- 初始化 ---
setup_style()

PROJ = '深圳市专精特新\u201c小巨人\u201d企业'
DATA_FILE = os.path.join(os.path.dirname(__file__), 'job_classified_data.csv')

print(f'加载分类数据：{DATA_FILE}')
df = pd.read_csv(DATA_FILE, encoding='utf-8-sig', low_memory=False)
df['招聘发布年份'] = pd.to_numeric(df['招聘发布年份'], errors='coerce').fillna(0).astype(int)
df = df[df['招聘发布年份'] > 0]
print(f'  加载完成：{len(df):,} 条')

ALL_YEARS = list(range(2016, 2026))
VALID_YEARS = [y for y in ALL_YEARS if y not in [2019] and df[df['招聘发布年份'] == y].shape[0] > 5]

# ============================================================
# 技术关键词解析
# ============================================================

def parse_keywords(series: pd.Series) -> Counter:
    """解析逗号分隔的关键词列，返回词频统计。"""
    counter = Counter()
    for val in series.dropna():
        val = str(val).strip()
        if val and val != 'nan':
            for kw in val.split(','):
                kw = kw.strip()
                if kw and len(kw) >= 2:  # 过滤单字符
                    counter[kw] += 1
    return counter

print('\n解析技术关键词 ...')
all_kw_counter = parse_keywords(df['技术关键词'])
top50_kws = [kw for kw, _ in all_kw_counter.most_common(50)]
print(f'  唯一关键词数：{len(all_kw_counter):,}')
print(f'  Top 5：{[kw for kw, _ in all_kw_counter.most_common(5)]}')

# ============================================================
# 图 21：技术关键词 Top 30
# ============================================================
print('\n生成图21：技术关键词 Top 30 ...')

top30 = all_kw_counter.most_common(30)
kw_names = [x[0] for x in top30][::-1]
kw_counts = [x[1] for x in top30][::-1]

# 按关键词长度/类型着色：长词/英文词用不同色
def color_for_kw(kw):
    if any(c.isascii() and c.isalpha() for c in kw):
        return COLORS[2]   # 绿：英文/技术缩写
    elif len(kw) <= 3:
        return COLORS[1]   # 橙：短关键词（通常是材料/工艺名）
    else:
        return COLORS[0]   # 蓝：长关键词

bar_clrs = [color_for_kw(kw) for kw in kw_names]

fig, ax = plt.subplots(figsize=(11, 10))
bars = ax.barh(range(len(kw_names)), kw_counts, color=bar_clrs, alpha=0.85, height=0.7)

for i, (name, cnt) in enumerate(zip(kw_names, kw_counts)):
    n_firms = df[df['技术关键词'].str.contains(name, na=False)]['企业名称'].nunique()
    ax.text(cnt + 5, i, f'{cnt:,}  ({n_firms}家)', va='center', fontsize=9)

ax.set_yticks(range(len(kw_names)))
ax.set_yticklabels(kw_names, fontsize=10)
ax.set_xlabel('出现次数（招聘条数）', fontsize=11)
ax.set_title(
    f'{PROJ}技术关键词频次 Top 30\n（2016\u20132025，括号内为涉及企业数）',
    fontsize=13, fontweight='bold', pad=12
)
ax.set_xlim(0, max(kw_counts) * 1.25)

# 图例
import matplotlib.patches as mpatches
legend_patches = [
    mpatches.Patch(color=COLORS[0], alpha=0.85, label='中文技术词（4字及以上）'),
    mpatches.Patch(color=COLORS[1], alpha=0.85, label='短技术词（材料/工艺）'),
    mpatches.Patch(color=COLORS[2], alpha=0.85, label='英文/缩写技术词'),
]
ax.legend(handles=legend_patches, fontsize=9, loc='lower right')
plt.tight_layout()
save_fig('fig21_top_tech_keywords')

# ============================================================
# 图 22：Top 技术词 × 年份热力图（相对频次）
# ============================================================
print('\n生成图22：技术词×年份热力图 ...')

# 选 Top 20 词（排除过于通用的词）
EXCLUDE_GENERIC = {'技术', '产品', '制造', '系统', '工程', '设计', '应用', '材料', '设备'}
top20_filtered = [kw for kw, _ in all_kw_counter.most_common(60)
                  if kw not in EXCLUDE_GENERIC][:20]

# 构建关键词×年份矩阵（每万条招聘中出现次数）
kw_year_matrix = {}
year_totals = df.groupby('招聘发布年份').size()

for kw in top20_filtered:
    row = {}
    for yr in VALID_YEARS:
        df_yr = df[df['招聘发布年份'] == yr]
        cnt = df_yr['技术关键词'].str.contains(kw, na=False).sum()
        total_yr = year_totals.get(yr, 1)
        row[yr] = cnt / total_yr * 1000  # 每千条中出现次数
    kw_year_matrix[kw] = row

heat_df = pd.DataFrame(kw_year_matrix).T  # 行=关键词，列=年份

# 按整体频次排序
heat_df['total'] = heat_df.sum(axis=1)
heat_df = heat_df.sort_values('total', ascending=False).drop(columns='total')

fig, ax = plt.subplots(figsize=(14, 7))
im = ax.imshow(heat_df.values, aspect='auto', cmap='Blues', vmin=0)

for i in range(len(heat_df)):
    for j in range(len(VALID_YEARS)):
        val = heat_df.values[i, j]
        if val > 5:
            ax.text(j, i, f'{val:.0f}', ha='center', va='center',
                    fontsize=7.5, color='white' if val > 60 else '#1a1a1a')

ax.set_xticks(range(len(VALID_YEARS)))
ax.set_xticklabels([str(y) for y in VALID_YEARS], fontsize=10)
ax.set_yticks(range(len(heat_df)))
ax.set_yticklabels(heat_df.index, fontsize=9.5)
ax.set_xlabel('年份', fontsize=11)
ax.set_title(
    f'{PROJ}技术关键词需求热度变化（每千条招聘中出现次数）',
    fontsize=13, fontweight='bold', pad=12
)
plt.colorbar(im, ax=ax, label='每千条招聘出现次数', shrink=0.9)
ax.text(0.99, 0.01, '注：2019年缺失，2020年极少，均不列入',
        transform=ax.transAxes, fontsize=8, ha='right', va='bottom', color=COLOR_NEUTRAL)
plt.tight_layout()
save_fig('fig22_tech_trend_heatmap')

# ============================================================
# 图 23：技术词 × 岗位类别矩阵（产教对接视角）
# ============================================================
print('\n生成图23：技术词×岗位类别矩阵 ...')

MAIN_CATS = ['研发技术', '信息技术', '生产制造', '质量检验', '销售市场', '供应链采购']
top15_kws = [kw for kw, _ in all_kw_counter.most_common(40)
             if kw not in EXCLUDE_GENERIC][:15]

cat_kw_matrix = {}
for cat in MAIN_CATS:
    df_cat = df[df['岗位类别'] == cat]
    row = {}
    for kw in top15_kws:
        cnt = df_cat['技术关键词'].str.contains(kw, na=False).sum()
        total_cat = len(df_cat)
        row[kw] = cnt / total_cat * 100  # 该类别中含此关键词的比例
    cat_kw_matrix[cat] = row

matrix_df = pd.DataFrame(cat_kw_matrix)  # 行=关键词，列=类别

fig, ax = plt.subplots(figsize=(12, 7))
im = ax.imshow(matrix_df.values, aspect='auto', cmap='Greens', vmin=0, vmax=25)

for i in range(len(top15_kws)):
    for j in range(len(MAIN_CATS)):
        val = matrix_df.values[i, j]
        if val > 1:
            ax.text(j, i, f'{val:.1f}%', ha='center', va='center',
                    fontsize=8, color='white' if val > 15 else '#1a1a1a',
                    fontweight='bold' if val > 8 else 'normal')

ax.set_xticks(range(len(MAIN_CATS)))
ax.set_xticklabels(MAIN_CATS, fontsize=11)
ax.set_yticks(range(len(top15_kws)))
ax.set_yticklabels(top15_kws, fontsize=10)
ax.set_xlabel('岗位功能类别', fontsize=11)
ax.set_ylabel('技术关键词', fontsize=11)
ax.set_title(
    f'{PROJ}技术关键词与岗位类别关联矩阵\n（产教对接视角，数字为该类别中含此技术词的招聘占比）',
    fontsize=13, fontweight='bold', pad=12
)
plt.colorbar(im, ax=ax, label='含该技术词的招聘占比（%）', shrink=0.9)
plt.tight_layout()
save_fig('fig23_tech_category_matrix')

# ============================================================
# 图 24：学历要求构成历年变化（堆积面积图）
# ============================================================
print('\n生成图24：学历要求历年变化 ...')

edu_map = {
    '本科': '本科', '大专': '大专',
    '中专/中技': '中专/技校', '中专': '中专/技校', '技校': '中专/技校',
    '高中': '高中及以下', '初中及以下': '高中及以下',
    '硕士': '硕士及以上', '博士': '硕士及以上',
    '不限': '学历不限', '学历不限': '学历不限',
}
df['学历分类'] = df['学历要求'].map(edu_map).fillna('其他')

EDU_ORDER = ['大专', '本科', '中专/技校', '高中及以下', '硕士及以上', '学历不限']
EDU_COLORS = {
    '大专':     COLORS[0],
    '本科':     COLORS[1],
    '中专/技校': COLORS[2],
    '高中及以下': COLORS[3],
    '硕士及以上': COLORS[4],
    '学历不限':  COLOR_NEUTRAL,
}

edu_pivot = (
    df.groupby(['招聘发布年份', '学历分类'])
    .size()
    .unstack(fill_value=0)
    .reindex(ALL_YEARS, fill_value=0)
)
for edu in EDU_ORDER:
    if edu not in edu_pivot.columns:
        edu_pivot[edu] = 0
edu_pivot = edu_pivot[EDU_ORDER]
edu_pct_pivot = edu_pivot.div(edu_pivot.sum(axis=1).replace(0, np.nan), axis=0) * 100

x = list(range(len(ALL_YEARS)))
x_labels = [str(y) for y in ALL_YEARS]

fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(13, 10), sharex=True)

# 上图：绝对值
bottom = np.zeros(len(ALL_YEARS))
for edu in EDU_ORDER:
    vals = edu_pivot[edu].values.astype(float)
    ax1.fill_between(x, bottom, bottom + vals,
                     color=EDU_COLORS[edu], alpha=0.82, label=edu)
    bottom += vals

ax1.set_ylabel('招聘条数', fontsize=11)
ax1.set_ylim(0, edu_pivot.sum(axis=1).max() * 1.12)
ax1.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f'{int(v):,}'))
ax1.legend(fontsize=9, loc='upper left', ncol=3, framealpha=0.9)
ax1.set_title(f'{PROJ}历年学历要求构成变化（上：绝对值；下：相对占比）',
              fontsize=13, fontweight='bold', pad=12)

# 下图：相对占比
bottom = np.zeros(len(ALL_YEARS))
for edu in EDU_ORDER:
    vals = edu_pct_pivot[edu].fillna(0).values
    ax2.fill_between(x, bottom, bottom + vals,
                     color=EDU_COLORS[edu], alpha=0.82, label=edu)
    bottom += vals

ax2.set_ylabel('占比（%）', fontsize=11)
ax2.set_ylim(0, 105)
ax2.set_xticks(x)
ax2.set_xticklabels(x_labels, fontsize=10)
ax2.set_xlabel('年份', fontsize=11)

# 标注缺失年份
for ax in [ax1, ax2]:
    ax.axvline(x=ALL_YEARS.index(2019), color='#999', linestyle=':', linewidth=1, alpha=0.6)
    ax.text(ALL_YEARS.index(2019), ax.get_ylim()[1] * 0.95,
            '2019\n无数据', ha='center', fontsize=7.5, color='#777', va='top')

plt.tight_layout()
save_fig('fig24_edu_trend_area')

# ============================================================
# 运行摘要
# ============================================================
print('\n===== 运行摘要 =====')
print(f'技术关键词唯一数：{len(all_kw_counter):,}')
print(f'Top 5 技术词：{[kw for kw, _ in all_kw_counter.most_common(5)]}')
print(f'分析的热门词（图22/23）：{len(top20_filtered)} 个')
# 学历变化摘要
for yr in [2016, 2017, 2022, 2024]:
    if yr in edu_pct_pivot.index and edu_pct_pivot.loc[yr].sum() > 0:
        dz = edu_pct_pivot.loc[yr, '大专']
        bk = edu_pct_pivot.loc[yr, '本科']
        print(f'  {yr}年：大专 {dz:.1f}%，本科 {bk:.1f}%')
print(f'输出图表：Figures/fig21 \u2013 fig24')
print('====================')
