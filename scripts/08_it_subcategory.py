# ============================================================
# 08_it_subcategory.py
# 用途：信息技术类岗位内部子类别细分分析
# 依赖：scripts/job_classified_data.csv
# 输出：Figures/fig25_it_subcategory_dist.png/.pdf
#        Figures/fig26_it_subcategory_trend.png/.pdf
#        Figures/fig27_it_subcategory_salary.png/.pdf
#        Figures/fig28_it_subcategory_edu.png/.pdf
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
df_all = pd.read_csv(DATA_FILE, encoding='utf-8-sig', low_memory=False)
df_all['招聘发布年份'] = pd.to_numeric(df_all['招聘发布年份'], errors='coerce').fillna(0).astype(int)

# 过滤出信息技术类
df = df_all[df_all['岗位类别'] == '信息技术'].copy()
print(f'  信息技术类记录：{len(df):,} 条')

ALL_YEARS = list(range(2016, 2026))
VALID_YEARS = [y for y in ALL_YEARS if y not in [2019] and
               df_all[df_all['招聘发布年份'] == y].shape[0] > 5]

# ============================================================
# 1. IT 子类别定义与分类
# ============================================================

IT_RULES = [
    ('数据/AI/算法', [
        '数据分析', '数据工程', '数据挖掘', '算法', '机器学习', '深度学习',
        'AI', '人工智能', '大数据', '数据科学', 'NLP', '计算机视觉',
        '推荐系统', '数据仓库', 'BI', '商业智能',
    ]),
    ('IT基础设施', [
        '运维', '网络安全', '信息安全', '云计算', '系统管理', '数据库管理',
        '网络工程', 'DevOps', 'Linux', '容器', 'K8s', 'Docker',
        '网络管理', '服务器', '系统集成',
    ]),
    ('产品与设计', [
        '产品经理', 'UI', 'UX', '交互设计', '视觉设计', '用户体验',
        '产品运营', '产品设计', '界面设计',
    ]),
    ('软件开发', [
        '软件', '前端', '后端', '全栈', '程序员', 'Java', 'Python',
        'C++', 'C#', 'Go', 'iOS', 'Android', '小程序', 'Web',
        '开发工程师', '应用开发', 'PHP', 'Vue', 'React', 'Spring',
    ]),
]

def classify_it_sub(job_title: str) -> str:
    if not isinstance(job_title, str):
        return '其他IT'
    title_upper = job_title.upper()
    for cat_name, keywords in IT_RULES:
        for kw in keywords:
            if kw in job_title or kw.upper() in title_upper:
                return cat_name
    return '其他IT'

df['IT子类别'] = df['招聘岗位'].apply(classify_it_sub)

IT_ORDER = ['软件开发', '数据/AI/算法', '产品与设计', 'IT基础设施', '其他IT']
IT_COLORS = {
    '软件开发':    COLORS[0],
    '数据/AI/算法': COLORS[1],
    '产品与设计':  COLORS[2],
    'IT基础设施':  COLORS[3],
    '其他IT':     COLOR_NEUTRAL,
}

sub_counts = df['IT子类别'].value_counts().reindex(IT_ORDER, fill_value=0)
n_it = len(df)
coverage = (n_it - sub_counts.get('其他IT', 0)) / n_it

print(f'\nIT子类别分布：')
for cat, cnt in sub_counts.items():
    print(f'  {cat}: {cnt:,}  ({cnt/n_it:.1%})')
print(f'子类别覆盖率：{coverage:.1%}')

# ============================================================
# 图 25：IT 子类别分布（条形 + 饼图组合）
# ============================================================
print('\n生成图25：IT子类别分布 ...')

sub_pcts = sub_counts / n_it * 100

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

# 左：条形图
bar_clrs = [IT_COLORS[c] for c in IT_ORDER]
bars = ax1.bar(range(len(IT_ORDER)), sub_counts.values,
               color=bar_clrs, alpha=0.85, width=0.6)
for i, (cnt, pct) in enumerate(zip(sub_counts.values, sub_pcts.values)):
    ax1.text(i, cnt + 5, f'{cnt:,}\n({pct:.1f}%)', ha='center', va='bottom', fontsize=9.5)
ax1.set_xticks(range(len(IT_ORDER)))
ax1.set_xticklabels(IT_ORDER, fontsize=10)
ax1.set_ylabel('招聘条数', fontsize=11)
ax1.set_title(f'信息技术类各子方向招聘量\n（N={n_it:,}，子类别覆盖率{coverage:.1%}）',
              fontsize=12, fontweight='bold')
ax1.set_ylim(0, max(sub_counts.values) * 1.25)

# 右：饼图
wedges, texts, autotexts = ax2.pie(
    sub_pcts.values,
    labels=IT_ORDER,
    colors=bar_clrs,
    autopct='%1.1f%%',
    startangle=120,
    pctdistance=0.72,
)
for text in texts: text.set_fontsize(10)
for at in autotexts: at.set_fontsize(9); at.set_fontweight('bold')
ax2.set_title('信息技术类子方向构成', fontsize=12, fontweight='bold')

fig.suptitle(f'{PROJ}信息技术类岗位细分（2016\u20132025）',
             fontsize=14, fontweight='bold', y=1.02)
plt.tight_layout()
save_fig('fig25_it_subcategory_dist')

# ============================================================
# 图 26：IT 子类别历年趋势
# ============================================================
print('\n生成图26：IT子类别历年趋势 ...')

df_valid = df[df['招聘发布年份'].isin(VALID_YEARS)]
pivot = (df_valid.groupby(['招聘发布年份', 'IT子类别']).size()
         .unstack(fill_value=0)
         .reindex(VALID_YEARS, fill_value=0))
for cat in IT_ORDER:
    if cat not in pivot.columns:
        pivot[cat] = 0

fig, ax = plt.subplots(figsize=(12, 5))
x = list(range(len(VALID_YEARS)))

for cat in IT_ORDER:
    if cat == '其他IT':
        continue
    vals = pivot[cat].values.astype(float)
    ax.plot(x, vals, color=IT_COLORS[cat], linewidth=2.2,
            marker='o', markersize=6, markerfacecolor='white',
            markeredgewidth=2, label=cat)
    # 标注终点值
    ax.text(x[-1] + 0.1, vals[-1], f'{int(vals[-1])}', va='center', fontsize=8.5,
            color=IT_COLORS[cat])

ax.set_xticks(x)
ax.set_xticklabels([str(y) for y in VALID_YEARS], fontsize=10)
ax.set_xlabel('年份', fontsize=11)
ax.set_ylabel('招聘条数', fontsize=11)
ax.set_title(f'{PROJ}信息技术类各子方向历年招聘趋势（2016\u20132025）',
             fontsize=13, fontweight='bold', pad=12)
ax.legend(fontsize=10, loc='upper left', framealpha=0.9)
ax.set_xlim(-0.3, len(VALID_YEARS) - 0.5)

# 增长率标注（2016→2024）
yr_2016_idx = VALID_YEARS.index(2016) if 2016 in VALID_YEARS else None
yr_2024_idx = VALID_YEARS.index(2024) if 2024 in VALID_YEARS else None
if yr_2016_idx is not None and yr_2024_idx is not None:
    for cat in [c for c in IT_ORDER if c != '其他IT']:
        v16 = pivot.loc[2016, cat] if 2016 in pivot.index else 0
        v24 = pivot.loc[2024, cat] if 2024 in pivot.index else 0
        if v16 > 0:
            growth = (v24 - v16) / v16 * 100
            print(f'  {cat}: {v16} → {v24}（{growth:+.0f}%）')

plt.tight_layout()
save_fig('fig26_it_subcategory_trend')

# ============================================================
# 图 27：IT 子类别薪资对比（箱线图）
# ============================================================
print('\n生成图27：IT子类别薪资对比 ...')

df['最低月薪'] = pd.to_numeric(df['最低月薪'], errors='coerce')
df['最高月薪'] = pd.to_numeric(df['最高月薪'], errors='coerce')
df['平均月薪'] = (df['最低月薪'] + df['最高月薪']) / 2
df_sal = df.dropna(subset=['平均月薪'])
df_sal = df_sal[(df_sal['平均月薪'] > 0) & (df_sal['平均月薪'] < 100000)]

cats_for_box = [c for c in IT_ORDER if c != '其他IT']
box_data = [df_sal[df_sal['IT子类别'] == c]['平均月薪'].values for c in cats_for_box]
n_labels = [f'{c}\n(n={len(d):,})' for c, d in zip(cats_for_box, box_data)]

fig, ax = plt.subplots(figsize=(11, 5))
bp = ax.boxplot(
    box_data,
    tick_labels=n_labels,
    patch_artist=True,
    medianprops=dict(color='white', linewidth=2.5),
    whiskerprops=dict(linewidth=1.2),
    capprops=dict(linewidth=1.2),
    flierprops=dict(marker='o', markersize=3, alpha=0.3),
    widths=0.55,
)
for patch, cat in zip(bp['boxes'], cats_for_box):
    patch.set_facecolor(IT_COLORS[cat])
    patch.set_alpha(0.78)

# 标注中位数
for i, d in enumerate(box_data):
    if len(d) > 0:
        median = np.median(d)
        ax.text(i + 1, median + 400, f'{median:,.0f}元',
                ha='center', fontsize=9, color='#333')

ax.set_ylabel('平均月薪（元）', fontsize=11)
ax.set_title(f'{PROJ}信息技术类各子方向薪资对比（2016\u20132025）',
             fontsize=13, fontweight='bold', pad=12)
ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f'{int(v):,}'))
ax.text(0.99, 0.01, '注：已剔除平均月薪≤0或>10万的异常值',
        transform=ax.transAxes, fontsize=8, ha='right', va='bottom', color=COLOR_NEUTRAL)

# 与研发技术类整体均值对比线
overall_it_median = df_sal['平均月薪'].median()
ax.axhline(y=overall_it_median, color='#888', linestyle='--', linewidth=1, alpha=0.7)
ax.text(len(cats_for_box) + 0.5, overall_it_median + 200,
        f'IT类整体\n中位数\n{overall_it_median:,.0f}', fontsize=7.5, color='#888', ha='left')

plt.tight_layout()
save_fig('fig27_it_subcategory_salary')

# ============================================================
# 图 28：IT 子类别学历要求对比
# ============================================================
print('\n生成图28：IT子类别学历要求对比 ...')

edu_map = {
    '本科': '本科', '大专': '大专',
    '中专/中技': '中专/技校', '中专': '中专/技校', '技校': '中专/技校',
    '高中': '高中及以下', '初中及以下': '高中及以下',
    '硕士': '硕士及以上', '博士': '硕士及以上',
    '不限': '学历不限', '学历不限': '学历不限',
}
df['学历分类'] = df['学历要求'].map(edu_map).fillna('其他')
EDU_ORDER = ['大专', '本科', '硕士及以上', '中专/技校', '学历不限']
EDU_COLORS = COLORS[:len(EDU_ORDER)]

edu_cross = (
    df[df['IT子类别'].isin(cats_for_box)]
    .groupby(['IT子类别', '学历分类'])
    .size().unstack(fill_value=0)
)
for edu in EDU_ORDER:
    if edu not in edu_cross.columns:
        edu_cross[edu] = 0
edu_cross = edu_cross[EDU_ORDER].reindex(cats_for_box, fill_value=0)
edu_pct = edu_cross.div(edu_cross.sum(axis=1).replace(0, 1), axis=0) * 100

fig, ax = plt.subplots(figsize=(12, 5))
n_cat = len(cats_for_box)
n_edu = len(EDU_ORDER)
bw = 0.7 / n_edu
xpos = np.arange(n_cat)

for j, (edu, clr) in enumerate(zip(EDU_ORDER, EDU_COLORS)):
    offset = (j - n_edu / 2 + 0.5) * bw
    vals = edu_pct[edu].values
    ax.bar(xpos + offset, vals, width=bw * 0.88, color=clr, alpha=0.85, label=edu)

ax.set_xticks(xpos)
ax.set_xticklabels(cats_for_box, fontsize=11)
ax.set_ylabel('占该子类别招聘比例（%）', fontsize=11)
ax.set_ylim(0, 75)
ax.set_title(f'{PROJ}信息技术类各子方向学历要求构成对比',
             fontsize=13, fontweight='bold', pad=12)
ax.legend(fontsize=9, loc='upper right', ncol=3, framealpha=0.9)
ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f'{v:.0f}%'))

# 大专参考线（深信大主要层次）
ax.axhline(y=38.2, color='#555', linestyle='--', linewidth=0.9, alpha=0.5)
ax.text(n_cat - 0.5, 39.5, '整体大专均值38.2%',
        fontsize=7.5, color='#555', ha='right')

plt.tight_layout()
save_fig('fig28_it_subcategory_edu')

# ============================================================
# 运行摘要
# ============================================================
print('\n===== 运行摘要 =====')
print(f'信息技术类样本：{n_it:,} 条')
print(f'IT子类别覆盖率：{coverage:.1%}')
for cat in cats_for_box:
    d = df_sal[df_sal['IT子类别'] == cat]['平均月薪']
    print(f'  {cat}: {sub_counts[cat]:,}条，中位薪资 {d.median():,.0f}元，'
          f'本科占比 {edu_pct.loc[cat,"本科"]:.0f}%，大专占比 {edu_pct.loc[cat,"大专"]:.0f}%')
print(f'输出图表：Figures/fig25 \u2013 fig28')
print('====================')
