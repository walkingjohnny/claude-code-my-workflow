# ============================================================
# 05_job_classification.py
# 用途：基于关键词优先级匹配，为每条招聘记录分配岗位功能类别
# 输出：scripts/job_classified_data.csv（带分类标签的数据集）
#        Figures/fig15_classification_coverage.png/.pdf
#        Figures/fig16_classification_validation.png/.pdf
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

# ============================================================
# 1. 岗位功能分类体系定义（9 大类）
# 匹配顺序即优先级：先匹配到的类别优先
# ============================================================

CATEGORY_RULES = [
    # (类别编号, 类别名称, 关键词列表)
    # 优先级 1：销售市场（销售工程师→销售市场，非研发技术）
    (5, '销售市场', [
        '销售', '市场', '外贸', '业务员', '业务代表', '大客户', 'BD', '商务',
        '客户经理', '渠道', '营销', '推广', '展会', '电商', '品牌',
    ]),
    # 优先级 2：质量检验
    (4, '质量检验', [
        '质量', '品质', 'QA', 'QC', '检验', '品管', '可靠性', '认证',
        '测量', '计量', '失效分析', '8D', '体系',
    ]),
    # 优先级 3：供应链采购
    (6, '供应链采购', [
        '采购', '供应链', '仓管', '仓库', '库管', '物流', '配送', 'PMC',
        '计划员', '生产计划', '跟单', '报关', '货代', '仓储',
    ]),
    # 优先级 4：财务会计
    (8, '财务会计', [
        '财务', '会计', '审计', '出纳', '成本', '税务', '资金', '核算',
        '预算', '报税', '总账', '应收', '应付',
    ]),
    # 优先级 5：行政人力
    (9, '行政人力', [
        '行政', '人力', '人事', 'HR', '招聘', '秘书', '前台', '法务',
        '知识产权', '专利', '合规', '总助', '文员', '内勤',
    ]),
    # 优先级 6：信息技术（软件/数字化）
    (2, '信息技术', [
        '软件', '程序', '前端', '后端', '全栈', '数据库', '运维', '网络安全',
        '信息安全', '云计算', '大数据', '人工智能', 'AI', '机器学习', '深度学习',
        'Java', 'Python', 'C++', 'C#', 'Go', 'iOS', 'Android', '小程序',
        'UI设计', 'UX', '产品经理', '算法工程师', '数据分析',
    ]),
    # 优先级 7：生产制造
    (3, '生产制造', [
        '工艺', '生产', '制造', '车间', '操作工', '装配', '焊接', '调试',
        '机修', '模具', '注塑', '冲压', '喷涂', '电镀', '设备维修',
        '维修工', '保全', '生产线', '流水线', '点检',
    ]),
    # 优先级 8：研发技术（工程师类，已排除销售/质量/采购工程师）
    (1, '研发技术', [
        '研发', '工程师', '工程技术', '硬件', '嵌入式', '电子', '电气',
        '机械', '结构', '光学', '声学', '热学', '射频', '天线', '芯片',
        '半导体', 'PCB', '单片机', 'ARM', 'FPGA', 'DSP',
        '技术员', '开发工程师', '设计工程师', '应用工程师', '测试工程师',
        '项目工程师', '技术支持', '售后工程师', '现场工程师',
        '光伏', '新能源', '储能', '医疗器械', '自动化', '机器人',
    ]),
    # 优先级 9：管理运营（经理/总监，已排除财务经理/行政经理等）
    (7, '管理运营', [
        '总监', '副总', '总经理', '运营', '主管', '项目管理', '项目经理',
        '厂长', '部长', '负责人', '总裁',
    ]),
]

CATEGORY_NAMES = {
    0: '其他',
    1: '研发技术',
    2: '信息技术',
    3: '生产制造',
    4: '质量检验',
    5: '销售市场',
    6: '供应链采购',
    7: '管理运营',
    8: '财务会计',
    9: '行政人力',
}

# 排序显示用的顺序（按规模大小，后续动态调整）
DISPLAY_ORDER = ['研发技术', '销售市场', '生产制造', '管理运营',
                 '供应链采购', '质量检验', '信息技术', '财务会计', '行政人力', '其他']


# ============================================================
# 2. 分类函数
# ============================================================

def classify_job(job_title: str) -> tuple:
    """
    根据优先级关键词匹配，返回 (类别编号, 类别名称, 匹配关键词)。
    """
    if not isinstance(job_title, str) or not job_title.strip():
        return (0, '其他', '')

    title_upper = job_title.upper()  # 英文关键词大写匹配

    for cat_id, cat_name, keywords in CATEGORY_RULES:
        for kw in keywords:
            if kw in job_title or kw.upper() in title_upper:
                return (cat_id, cat_name, kw)

    return (0, '其他', '')


# ============================================================
# 3. 应用分类
# ============================================================

print('\n应用岗位分类规则 ...')
results = df['招聘岗位'].apply(classify_job)
df['岗位类别编号'] = results.apply(lambda x: x[0])
df['岗位类别'] = results.apply(lambda x: x[1])
df['匹配关键词'] = results.apply(lambda x: x[2])

# 统计结果
cat_counts = df['岗位类别'].value_counts()
total = len(df)
coverage = (total - cat_counts.get('其他', 0)) / total

print(f'\n分类结果：')
for cat_name in DISPLAY_ORDER:
    cnt = cat_counts.get(cat_name, 0)
    pct = cnt / total * 100
    bar = '█' * int(pct / 2)
    print(f'  {cat_name:<8} {cnt:5,}  ({pct:5.1f}%)  {bar}')
print(f'\n分类覆盖率（非"其他"）：{coverage:.1%}')

# 校验：各年份总数
df['招聘发布年份'] = pd.to_numeric(df['招聘发布年份'], errors='coerce').fillna(0).astype(int)
year_check = df[df['招聘发布年份'] > 0].groupby('招聘发布年份').size()
print(f'\n各年份条数（应与 EDA 一致）：')
for yr, cnt in year_check.items():
    print(f'  {yr}: {cnt:,}')

# ============================================================
# 4. 保存分类结果
# ============================================================

output_path = os.path.join(os.path.dirname(__file__), 'job_classified_data.csv')
df.to_csv(output_path, index=False, encoding='utf-8-sig')
print(f'\n分类结果已保存：{output_path}')

# ============================================================
# 图 15：分类覆盖率与类别分布
# ============================================================
print('\n生成图15：分类覆盖率与类别分布 ...')

# 按计划顺序排列，实际频次从高到低
ordered_cats = [c for c in DISPLAY_ORDER if c in cat_counts.index]
counts_ordered = cat_counts.reindex(ordered_cats, fill_value=0)
pcts_ordered = counts_ordered / total * 100

fig, ax = plt.subplots(figsize=(11, 6))

bar_clrs = [COLORS[i % (len(COLORS) - 1)] if cat != '其他' else COLOR_NEUTRAL
            for i, cat in enumerate(ordered_cats)]
bars = ax.barh(
    range(len(ordered_cats) - 1, -1, -1),
    counts_ordered.values,
    color=bar_clrs, alpha=0.85, height=0.68
)

for i, (cat, cnt, pct) in enumerate(zip(ordered_cats, counts_ordered.values, pcts_ordered.values)):
    ax.text(cnt + 20, len(ordered_cats) - 1 - i,
            f'{cnt:,}  ({pct:.1f}%)', va='center', fontsize=9.5)

ax.set_yticks(range(len(ordered_cats)))
ax.set_yticklabels(ordered_cats[::-1], fontsize=11)
ax.set_xlabel('招聘条数', fontsize=11)
ax.set_title(
    f'深圳市专精特新\u201c小巨人\u201d企业招聘岗位功能类别分布\n'
    f'（分类覆盖率 {coverage:.1%}，N=22,022）',
    fontsize=13, fontweight='bold', pad=12
)
ax.set_xlim(0, max(counts_ordered.values) * 1.28)
ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f'{int(x):,}'))

# 覆盖率注释
ax.text(
    0.99, 0.03,
    f'注：基于关键词优先级匹配；9大功能类别，\u201c其他\u201d为未匹配项',
    transform=ax.transAxes, fontsize=8.5, ha='right', va='bottom', color=COLOR_NEUTRAL
)

plt.tight_layout()
save_fig('fig15_classification_coverage')

# ============================================================
# 图 16：分类验证——有初级分类记录的交叉热力图
# ============================================================
print('\n生成图16：分类验证矩阵 ...')

df_valid_cat = df[(df['初级分类'].notna()) & (df['初级分类'] != '')].copy()
n_validate = len(df_valid_cat)

# 取 初级分类 Top 8 和 岗位类别 Top 8 做交叉
top_chuji = df_valid_cat['初级分类'].value_counts().head(8).index.tolist()
top_func = [c for c in ordered_cats if c != '其他']

cross_df = df_valid_cat[
    df_valid_cat['初级分类'].isin(top_chuji)
].groupby(['初级分类', '岗位类别']).size().unstack(fill_value=0)

# 只保留有数据的功能类别列
func_cols = [c for c in top_func if c in cross_df.columns]
cross_df = cross_df[func_cols]

# 行归一化（百分比）
cross_pct = cross_df.div(cross_df.sum(axis=1), axis=0) * 100

fig, ax = plt.subplots(figsize=(12, 5.5))

im = ax.imshow(cross_pct.values, aspect='auto', cmap='Blues', vmin=0, vmax=80)

# 标注数值
for i in range(len(cross_pct)):
    for j in range(len(func_cols)):
        val = cross_pct.values[i, j]
        if val > 3:
            ax.text(j, i, f'{val:.0f}%', ha='center', va='center',
                    fontsize=8.5, color='white' if val > 45 else '#1a1a1a',
                    fontweight='bold' if val > 20 else 'normal')

ax.set_xticks(range(len(func_cols)))
ax.set_xticklabels(func_cols, fontsize=10, rotation=20, ha='right')
ax.set_yticks(range(len(top_chuji)))
ax.set_yticklabels(top_chuji, fontsize=9)
ax.set_xlabel('本研究功能类别', fontsize=11)
ax.set_ylabel('原始行业分类（初级分类）', fontsize=11)
ax.set_title(
    f'分类方法验证：原始行业分类 vs 本研究功能类别（行百分比，N={n_validate:,}条）',
    fontsize=12, fontweight='bold', pad=12
)

plt.colorbar(im, ax=ax, label='行内占比（%）', shrink=0.8)
plt.tight_layout()
save_fig('fig16_classification_validation')

# ============================================================
# 运行摘要
# ============================================================
print('\n===== 运行摘要 =====')
print(f'分析样本：{total:,} 条')
print(f'分类覆盖率：{coverage:.1%}（非"其他"类）')
print(f'"其他"类数量：{cat_counts.get("其他", 0):,} 条（{cat_counts.get("其他", 0)/total:.1%}）')
print(f'分类数据已缓存：scripts/job_classified_data.csv')
print(f'输出图表：Figures/fig15, fig16')
print('====================')
