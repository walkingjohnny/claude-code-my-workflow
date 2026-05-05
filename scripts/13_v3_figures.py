# ============================================================
# 13_v3_figures.py
# 用途：V3综合版 - 按V3论文和研究报告中的确切图表文件名重新绘制完整图表集
#
# 文件名命名规则：与V3文档中的引用保持一致，保存到 Figures/v3/
# V3文档引用 Figures/fig*.png → 对应文件保存为 Figures/v3/fig*.png
#
# 覆盖图表：
#   fig03  年度招聘条数趋势
#   fig05  企业规模分布（新增，原V1无对应）
#   fig07  入选批次分布（新增，原V1无对应）
#   fig08  入选批次招聘量趋势（新增，原V1无对应）
#   fig11  行业分布
#   fig15  岗位类别分布
#   fig17  类别堆积面积图
#   fig18  类别×年份热力图
#   fig19  主要类别趋势折线图
#   fig21  技术关键词Top20
#   fig22  技术关键词历年趋势折线图（新增，原V1是热力图）
#   fig24  学历要求历年趋势
#   fig27  IT子类别薪资分布
#   fig28  IT子类别学历构成
#   fig29  软技能Top20
#   fig30  软技能×类别热力图
#   fig31  软技能历年趋势
#   fig32  数字化评分历年趋势
#   fig33  数字化评分×类别箱线图
#   fig34  数字化程度×薪资散点图
#   fig35  本科vs大专差异条形图
#   fig36  本科vs大专差异矩阵
#   fig37  技术工具频次Top30
#   fig38  工具×类别热力图
#   fig39  工具历年趋势
#   fig40  C/C++ vs Python编程工具对比（V3新增）
#   fig41  关键词热度vs工具频次落差（V3新增）
#
# 依赖：scripts/job_classified_data.csv
#       data/v2_soft_skills.parquet
#       data/v2_digitalization.parquet
#       data/v2_tech_tools.parquet
#       data/v2_edu_comparison.json
# ============================================================

import os, sys, json, pathlib, warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import matplotlib.patches as mpatches
import seaborn as sns

sys.path.insert(0, ".")
from scripts._common import setup_style, COLORS, COLOR_PRIMARY, COLOR_SECONDARY, COLOR_NEUTRAL, RANDOM_SEED

np.random.seed(RANDOM_SEED)

V3_DIR = pathlib.Path("Figures/v3")
V3_DIR.mkdir(parents=True, exist_ok=True)
PROJ = '深圳市专精特新\u201c小巨人\u201d企业'


def save_v3(name, fig=None):
    """保存 PNG（300dpi）+ PDF 到 Figures/v3/。name 不含扩展名。"""
    kw = dict(bbox_inches="tight")
    target = fig if fig else plt
    target.savefig(V3_DIR / f"{name}.png", dpi=300, **kw)
    target.savefig(V3_DIR / f"{name}.pdf", **kw)
    plt.close("all")
    print(f"  ✓ {name}")


def footnote(ax, txt, y=-0.14):
    ax.annotate(txt, xy=(0, y), xycoords="axes fraction",
                fontsize=7.5, color="#666", ha="left", va="top")


# ============================================================
# 0. 数据加载
# ============================================================
print("=" * 60)
print("V3 图表生成（按V3文档确切文件名）")
print("=" * 60)

setup_style()

print("\n[0] 加载数据...")
df = pd.read_csv("scripts/job_classified_data.csv", encoding="utf-8-sig", low_memory=False)
df["招聘发布年份"] = pd.to_numeric(df["招聘发布年份"], errors="coerce").fillna(0).astype(int)
print(f"  分类数据：{len(df):,} 条")

VALID_YEARS = [y for y in range(2016, 2025) if y != 2019]
df_v = df[df["招聘发布年份"].isin(VALID_YEARS)].copy()

skills_df = pd.read_parquet("data/v2_soft_skills.parquet")
digi_df   = pd.read_parquet("data/v2_digitalization.parquet")
tools_df  = pd.read_parquet("data/v2_tech_tools.parquet")
edu_json  = json.loads(pathlib.Path("data/v2_edu_comparison.json").read_text())
print(f"  V2 数据加载完成")

# 软技能标准化
NORM = {
    "沟通协调能力":"沟通协调","沟通能力":"沟通协调","沟通协调":"沟通协调",
    "团队协作能力":"团队协作","团队合作":"团队协作","协作精神":"团队协作",
    "执行力":"执行力","计划与执行能力":"执行力",
    "学习能力":"学习能力","学习意愿":"学习能力","持续学习":"学习能力",
    "责任心":"责任心","责任感":"责任心",
    "细心":"细心严谨","严谨":"细心严谨","细致":"细心严谨","细心严谨":"细心严谨",
    "服务意识":"服务意识","客户服务意识":"服务意识",
    "抗压能力":"抗压能力","压力管理":"抗压能力",
    "领导力":"领导力","领导能力":"领导力","管理能力":"领导力",
    "问题解决能力":"问题解决","分析问题能力":"问题解决",
    "判断与决策能力":"判断决策","决策能力":"判断决策",
    "创新能力":"创新思维","创新思维":"创新思维",
    "积极主动":"主动性","主动性":"主动性","自我驱动":"主动性",
}
def norm_skill(s): return NORM.get(str(s).strip(), str(s).strip())

# IT子类别规则
IT_RULES = [
    ("数据/AI/算法",  ["数据分析","数据工程","算法","机器学习","深度学习","AI","人工智能","大数据","数据科学","NLP","计算机视觉","数据仓库","BI","商业智能"]),
    ("IT基础设施",   ["运维","网络安全","信息安全","云计算","系统管理","数据库管理","网络工程","DevOps","Linux","容器","K8s","Docker","网络管理","服务器","系统集成"]),
    ("产品与设计",   ["产品经理","UI","UX","交互设计","视觉设计","用户体验","产品运营","产品设计","界面设计"]),
    ("软件开发",     ["软件","前端","后端","全栈","程序员","Java","Python","C++","C#","Go","iOS","Android","小程序","Web","开发工程师","应用开发","PHP","Vue","React","Spring"]),
]
def classify_it(t):
    if not isinstance(t, str): return "其他IT"
    for name, kws in IT_RULES:
        for k in kws:
            if k in t or k.upper() in t.upper(): return name
    return "其他IT"

CAT_ORDER = ["研发技术","销售市场","信息技术","生产制造","行政人力","供应链采购","质量检验","管理运营","财务会计"]
CAT_C = dict(zip(CAT_ORDER, COLORS[:9]))
EDU_GROUPS = {"大专":["大专","大专及以上","专科"],"本科":["本科","本科及以上"],"硕士及以上":["硕士","硕士及以上","博士"]}
EDU_C = {"大专":COLORS[1],"本科":COLORS[0],"硕士及以上":COLORS[3]}

print("  数据加载完成\n")


# ============================================================
# A. 规模与企业画像
# ============================================================
print("[A] 规模与企业画像...")

# ── fig03：年度招聘条数趋势 ──────────────────────────────
yr_cnt = df.groupby("招聘发布年份").size()
yr_plt = yr_cnt[(yr_cnt.index >= 2016) & (yr_cnt.index <= 2024)]
fig, ax = plt.subplots(figsize=(11, 5.5))
ax.fill_between(yr_plt.index, yr_plt.values, alpha=0.15, color=COLOR_PRIMARY)
ax.plot(yr_plt.index, yr_plt.values, "o-", lw=2.5, color=COLOR_PRIMARY, ms=7, zorder=3)
for yr, v in yr_plt.items():
    if yr != 2019:
        ax.text(yr, v + 90, f"{v:,}", ha="center", fontsize=8.5, color="#333")
ax.text(2019, 200, "2019年\n数据缺失", ha="center", fontsize=8.5, color="#999", style="italic")
ax.annotate("2022年历史峰值\n5,389条", xy=(2022, 5389), xytext=(2020.8, 5650),
            fontsize=9, color=COLOR_SECONDARY,
            arrowprops=dict(arrowstyle="->", color=COLOR_SECONDARY, lw=1.2))
ax.set_xlabel("年份", fontsize=11); ax.set_ylabel("招聘条数", fontsize=11)
ax.set_title(f"{PROJ}历年招聘条数变化（2016—2024）", fontsize=13, pad=14)
ax.set_xticks(range(2016, 2025))
ax.set_ylim(0, yr_plt.max() * 1.22)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
plt.xticks(rotation=30)
footnote(ax, f"数据来源：智联招聘；有效样本 {len(df):,} 条；2019年数据缺失，2020年仅2条记录")
plt.tight_layout(); save_v3("fig03_annual_job_postings")

# ── fig05：企业规模分布（横向条形，新增）─────────────────
SIZE_MAP = {
    "S(小型)":"小型（<100人）",
    "M(中型)":"中型（100-999人）",
    "L(大型)":"大型（≥1000人）",
}
df_sz = df.copy()
df_sz["规模组"] = df_sz["企业规模"].map(SIZE_MAP).fillna("其他")
sz_cnt = df_sz[df_sz["规模组"] != "其他"]["规模组"].value_counts()
sz_order = ["小型（<100人）","中型（100-999人）","大型（≥1000人）"]
sz_cnt = sz_cnt.reindex(sz_order).fillna(0)
sz_pct = sz_cnt / len(df_sz[df_sz["规模组"] != "其他"]) * 100

fig, ax = plt.subplots(figsize=(7, 6))
pie_colors = [COLORS[1], COLORS[0], COLORS[2]]
wedges, texts, autotexts = ax.pie(
    sz_cnt.values,
    labels=sz_order,
    colors=pie_colors,
    autopct="%1.1f%%",
    startangle=140,
    pctdistance=0.65,
    wedgeprops=dict(linewidth=1.2, edgecolor="white"),
)
for t in texts:
    t.set_fontsize(11)
for at in autotexts:
    at.set_fontsize(10.5)
    at.set_color("white")
    at.set_fontweight("bold")
# 在饼图下方添加招聘条数注释
legend_labels = [f"{s}：{int(v):,}条" for s, v in zip(sz_order, sz_cnt.values)]
ax.legend(wedges, legend_labels, loc="lower center", bbox_to_anchor=(0.5, -0.12),
          fontsize=10, framealpha=0.9, ncol=1)
ax.set_title(f"{PROJ}招聘条数企业规模分布", fontsize=13, pad=14)
footnote(ax, "中型企业（100-999人）贡献最多招聘条数，约57.6%；小型企业占25.9%")
plt.tight_layout(); save_v3("fig05_company_size_bar")

# ── fig07：入选批次分布（新增）──────────────────────────
batch_cnt = df[df["入选批次"].notna()]["入选批次"].value_counts().sort_index()
fig, ax = plt.subplots(figsize=(9, 4.5))
bars = ax.bar(range(len(batch_cnt)), batch_cnt.values,
              color=plt.cm.Blues(np.linspace(0.35, 0.8, len(batch_cnt))), width=0.65)
ax.set_xticks(range(len(batch_cnt)))
ax.set_xticklabels([str(b) for b in batch_cnt.index], fontsize=10)
ax.set_ylabel("招聘条数", fontsize=11)
ax.set_title(f"{PROJ}各认定批次企业招聘条数分布", fontsize=13, pad=12)
for i, v in enumerate(batch_cnt.values):
    ax.text(i, v + 20, f"{v:,}", ha="center", fontsize=9, color="#333")
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
footnote(ax, "第四至第七批企业贡献超过80%招聘量，近年新入选企业扩张势头更强")
plt.tight_layout(); save_v3("fig07_batch_bar")

# ── fig08：入选批次历年招聘趋势（新增）──────────────────
df_batch = df[df["入选批次"].notna() & df["招聘发布年份"].isin(VALID_YEARS)].copy()
# 入选批次已是"第X批"格式，直接使用
batch_year = df_batch.groupby(["招聘发布年份", "入选批次"]).size().unstack(fill_value=0)
top_batches = batch_year.sum().sort_values(ascending=False).head(5).index.tolist()
batch_year = batch_year[top_batches]

fig, ax = plt.subplots(figsize=(11, 5.5))
for i, b in enumerate(top_batches):
    if b in batch_year.columns:
        ax.plot(batch_year.index, batch_year[b], "o-", lw=2, color=COLORS[i % len(COLORS)], label=b, ms=5)
ax.set_xlabel("年份", fontsize=11); ax.set_ylabel("招聘条数", fontsize=11)
ax.set_title(f"{PROJ}各认定批次企业历年招聘条数趋势", fontsize=13, pad=12)
ax.legend(fontsize=9, loc="upper left")
ax.set_xticks(VALID_YEARS); plt.xticks(rotation=30)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
plt.tight_layout(); save_v3("fig08_batch_trend")

# ── fig11：行业分布条形图 ─────────────────────────────
IMAP = {
    "制造业":"制造业",
    "批发和零售业":"批发零售业",
    "科学研究和技术服务业":"科学研究/技术服务",
    "信息传输、软件和信息技术服务业":"信息传输/软件/IT服务",
    "租赁和商务服务业":"租赁/商务服务",
}
df["行业简称"] = df["国标行业门类"].map(IMAP).fillna("其他行业")
ind_pct = (df["行业简称"].value_counts() / len(df) * 100).round(1).head(7)
fig, ax = plt.subplots(figsize=(9, 5))
bars = ax.barh(range(len(ind_pct)), ind_pct.values,
               color=[COLOR_PRIMARY] + [COLORS[i % len(COLORS)] for i in range(1, len(ind_pct))],
               height=0.65)
ax.set_yticks(range(len(ind_pct))); ax.set_yticklabels(ind_pct.index, fontsize=10)
ax.invert_yaxis()
ax.set_xlabel("占总招聘条数（%）", fontsize=11)
ax.set_title(f"{PROJ}招聘条数行业分布", fontsize=13, pad=12)
for i, v in enumerate(ind_pct.values):
    ax.text(v + 0.2, i, f"{v}%", va="center", fontsize=9.5)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
footnote(ax, "制造业贡献64.0%招聘条数，是专精特新企业的产业主体")
plt.tight_layout(); save_v3("fig11_industry_bar")


# ============================================================
# B. 岗位结构与纵向变迁
# ============================================================
print("[B] 岗位结构...")

cat_yr = df[df["岗位类别"].isin(CAT_ORDER) & df["招聘发布年份"].isin(VALID_YEARS)].groupby(
    ["招聘发布年份","岗位类别"]).size().unstack(fill_value=0).reindex(columns=CAT_ORDER, fill_value=0)

# ── fig15：岗位类别分布 ──────────────────────────────────
cat_cnt = df[df["岗位类别"].isin(CAT_ORDER)]["岗位类别"].value_counts().reindex(CAT_ORDER).dropna().sort_values()
cat_pct = cat_cnt / len(df) * 100
fig, ax = plt.subplots(figsize=(9, 6.5))
clrs = [CAT_C.get(c, COLOR_NEUTRAL) for c in cat_cnt.index]
ax.barh(range(len(cat_cnt)), cat_cnt.values, color=clrs, height=0.7)
ax.set_yticks(range(len(cat_cnt))); ax.set_yticklabels(cat_cnt.index, fontsize=10.5)
ax.set_xlabel("招聘条数", fontsize=11)
ax.set_title(f"{PROJ}招聘岗位功能类别分布", fontsize=13, pad=12)
for i, (v, p) in enumerate(zip(cat_cnt.values, cat_pct.values)):
    ax.text(v + 15, i, f"{v:,}（{p:.1f}%）", va="center", fontsize=9)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
footnote(ax, "研发技术+信息技术合计35.2%，与深信大ICT定位高度重合；岗位分类覆盖率84.9%")
plt.tight_layout(); save_v3("fig15_classification_coverage")

# ── fig17：类别堆积面积图 ─────────────────────────────
fig, ax = plt.subplots(figsize=(12, 6))
ax.stackplot(cat_yr.index, [cat_yr[c] for c in CAT_ORDER],
             labels=CAT_ORDER, colors=[CAT_C.get(c, COLOR_NEUTRAL) for c in CAT_ORDER], alpha=0.85)
ax.set_xlabel("年份", fontsize=11); ax.set_ylabel("招聘条数", fontsize=11)
ax.set_title(f"{PROJ}各岗位类别招聘条数历年变迁（堆积面积图）", fontsize=13, pad=12)
ax.legend(loc="upper left", fontsize=9, ncol=3, framealpha=0.85)
ax.set_xticks(VALID_YEARS); plt.xticks(rotation=30)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
footnote(ax, "各类别均呈正增长；生产制造+629%增幅最大；整体是规模扩大的同步体现")
plt.tight_layout(); save_v3("fig17_category_stacked_area")

# ── fig18：类别×年份热力图（占比）────────────────────────
cat_yr_pct = cat_yr.div(cat_yr.sum(axis=1), axis=0) * 100
fig, ax = plt.subplots(figsize=(12, 6))
sns.heatmap(cat_yr_pct[CAT_ORDER].T, cmap="Blues", annot=True, fmt=".0f",
            linewidths=0.4, ax=ax, cbar_kws={"label":"占当年总量（%）"})
ax.set_title(f"{PROJ}各岗位类别历年招聘占比热力图", fontsize=13, pad=12)
ax.set_xlabel("年份", fontsize=11); ax.set_ylabel("岗位类别", fontsize=11)
plt.xticks(rotation=30); plt.tight_layout(); save_v3("fig18_category_heatmap_year")

# ── fig19：主要类别趋势折线图 ─────────────────────────
TOP5 = ["研发技术","销售市场","信息技术","生产制造","行政人力"]
fig, ax = plt.subplots(figsize=(11, 6))
for i, c in enumerate(TOP5):
    if c in cat_yr.columns:
        ax.plot(cat_yr.index, cat_yr[c], "o-", lw=2.2, color=COLORS[i], label=c, ms=6)
ax.set_xlabel("年份", fontsize=11); ax.set_ylabel("招聘条数", fontsize=11)
ax.set_title(f"{PROJ}主要岗位类别招聘条数趋势（2016—2024）", fontsize=13, pad=12)
ax.legend(fontsize=10, loc="upper left")
ax.set_xticks(VALID_YEARS); plt.xticks(rotation=30)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
plt.tight_layout(); save_v3("fig19_top_categories_trend")


# ============================================================
# C. 技术技能与学历
# ============================================================
print("[C] 技术与学历...")

# ── fig21：技术关键词Top20 ──────────────────────────────
kw_all = []
for row in df["技术关键词"].dropna():
    for k in str(row).split(","):
        k = k.strip()
        if k and k != "nan": kw_all.append(k)
kw_cnt = pd.Series(kw_all).value_counts().head(20)

fig, ax = plt.subplots(figsize=(10, 7))
bars = ax.barh(range(len(kw_cnt)), kw_cnt.values,
               color=plt.cm.Blues_r(np.linspace(0.2, 0.75, len(kw_cnt))))
ax.set_yticks(range(len(kw_cnt))); ax.set_yticklabels(kw_cnt.index, fontsize=10)
ax.invert_yaxis()
ax.set_xlabel("出现频次", fontsize=11)
ax.set_title(f"{PROJ}招聘技术关键词频次 Top20", fontsize=13, pad=12)
for i, v in enumerate(kw_cnt.values):
    ax.text(v + 1, i, str(v), va="center", fontsize=9)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
footnote(ax, "物联网、人工智能、智能制造等新一代信息技术词汇高度集聚（来自平台结构化标签字段）")
plt.tight_layout(); save_v3("fig21_top_tech_keywords")

# ── fig22：技术关键词历年趋势折线图（新增，非热力图）───────
TOP_KWS = ["物联网","人工智能","自动化","智能制造","大数据"]
kw_yr_data = {}
for kw in TOP_KWS:
    yr_d = {}
    for yr in VALID_YEARS:
        yr_total = (df_v["招聘发布年份"] == yr).sum()
        count = df_v[df_v["招聘发布年份"] == yr]["技术关键词"].dropna().apply(
            lambda x: kw in str(x)).sum()
        yr_d[yr] = count / max(yr_total, 1) * 1000
    kw_yr_data[kw] = yr_d
kw_yr_df = pd.DataFrame(kw_yr_data)

fig, ax = plt.subplots(figsize=(11, 5.5))
for i, kw in enumerate(TOP_KWS):
    ax.plot(kw_yr_df.index, kw_yr_df[kw], "o-", lw=2.2, color=COLORS[i], label=kw, ms=5)
ax.set_xlabel("年份", fontsize=11); ax.set_ylabel("每千条出现率", fontsize=11)
ax.set_title("主要技术关键词历年出现趋势（每千条出现率）", fontsize=13, pad=12)
ax.legend(fontsize=10, loc="upper left")
ax.set_xticks(VALID_YEARS); plt.xticks(rotation=30)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
footnote(ax, "技术热词出现率上升不等于岗位实际数字化程度提升（见fig32对比）")
plt.tight_layout(); save_v3("fig22_tech_keywords_trend")

# ── fig24：学历要求历年趋势 ─────────────────────────────
df_e = df_v.copy()
df_e["学历组"] = "其他"
for g, lbls in EDU_GROUPS.items():
    df_e.loc[df_e["学历要求"].isin(lbls), "学历组"] = g
edu_yr = df_e[df_e["学历组"] != "其他"].groupby(["招聘发布年份","学历组"]).size().unstack(fill_value=0)
yr_tot = df_e.groupby("招聘发布年份").size()
edu_yr_pct = edu_yr.div(yr_tot, axis=0) * 100

fig, ax = plt.subplots(figsize=(11, 5.5))
for g in ["大专","本科","硕士及以上"]:
    if g in edu_yr_pct.columns:
        ax.plot(edu_yr_pct.index, edu_yr_pct[g], "o-", lw=2.5, color=EDU_C[g], label=g, ms=6)
        ax.fill_between(edu_yr_pct.index, edu_yr_pct[g], alpha=0.1, color=EDU_C[g])
for g in ["大专","本科"]:
    if 2024 in edu_yr_pct.index and g in edu_yr_pct.columns:
        v = edu_yr_pct.loc[2024, g]
        ax.annotate(f"2024: {v:.1f}%", (2024, v), textcoords="offset points",
                    xytext=(6, 5 if g == "本科" else -14), fontsize=9, color=EDU_C[g])
ax.set_xlabel("年份", fontsize=11); ax.set_ylabel("占当年招聘总量（%）", fontsize=11)
ax.set_title(f"{PROJ}历年学历要求结构变化（2016—2024）", fontsize=13, pad=12)
ax.legend(fontsize=10); ax.set_xticks(VALID_YEARS); plt.xticks(rotation=30)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
footnote(ax, "2024年本科（47.4%）首次超越大专（34.6%），发生结构性倒置；大专空间持续收窄")
plt.tight_layout(); save_v3("fig24_edu_trend_area")

# ── fig27 & fig28：IT子类别薪资 & 学历 ──────────────────
IT_ORDER = ["软件开发","数据/AI/算法","产品与设计","IT基础设施"]
IT_C = dict(zip(IT_ORDER, COLORS[:4]))
df_it = df[df["岗位类别"] == "信息技术"].copy()
df_it["IT子类别"] = df_it["招聘岗位"].apply(classify_it)
df_it["平均月薪"] = (df_it["最低月薪"].fillna(0) + df_it["最高月薪"].fillna(0)) / 2
df_it["学历组"] = "其他"
for g, lbls in EDU_GROUPS.items():
    df_it.loc[df_it["学历要求"].isin(lbls), "学历组"] = g

# fig27 薪资箱线图
it_sal = [df_it[(df_it["IT子类别"] == c) & (df_it["平均月薪"] > 0)]["平均月薪"].values for c in IT_ORDER]
fig, ax = plt.subplots(figsize=(9, 5))
bp = ax.boxplot(it_sal, patch_artist=True,
                medianprops=dict(color="white", lw=2.5),
                flierprops=dict(marker=".", ms=3, alpha=0.35))
for p, c in zip(bp["boxes"], IT_ORDER):
    p.set_facecolor(IT_C[c]); p.set_alpha(0.8)
ax.set_xticks(range(1, 5)); ax.set_xticklabels(IT_ORDER, fontsize=10.5)
ax.set_ylabel("平均月薪（元）", fontsize=11)
ax.set_title("信息技术类各子方向薪资分布（箱线图）", fontsize=13, pad=12)
for i, d in enumerate(it_sal):
    if len(d):
        m = np.median(d)
        ax.text(i+1, m+300, f"{m/1000:.1f}K", ha="center", fontsize=9, color="#333")
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
footnote(ax, "数据/AI/算法中位薪资22,500元（最高）；IT基础设施约8,250元；大专竞争优势最高的是IT基础设施")
plt.tight_layout(); save_v3("fig27_it_subcategory_salary")

# fig28 学历构成堆叠条形
it_edu = df_it[df_it["IT子类别"].isin(IT_ORDER) & (df_it["学历组"] != "其他")].groupby(
    ["IT子类别","学历组"]).size().unstack(fill_value=0).reindex(IT_ORDER)
it_edu_pct = it_edu.div(it_edu.sum(axis=1), axis=0) * 100
it_edu_pct = it_edu_pct.reindex(columns=["大专","本科","硕士及以上"], fill_value=0)
fig, ax = plt.subplots(figsize=(9, 5))
btm = np.zeros(len(IT_ORDER))
for g in ["大专","本科","硕士及以上"]:
    v = it_edu_pct[g].values
    ax.bar(range(len(IT_ORDER)), v, bottom=btm, color=EDU_C[g], label=g, width=0.6)
    for i, (vv, bb) in enumerate(zip(v, btm)):
        if vv > 5:
            ax.text(i, bb + vv/2, f"{vv:.0f}%", ha="center", va="center",
                    fontsize=9.5, color="white", fontweight="bold")
    btm += v
ax.set_xticks(range(len(IT_ORDER))); ax.set_xticklabels(IT_ORDER, fontsize=10.5)
ax.set_ylabel("占比（%）", fontsize=11); ax.set_ylim(0, 115)
ax.set_title("信息技术类各子方向学历要求构成对比", fontsize=13, pad=12)
ax.legend(fontsize=10, loc="upper right")
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
footnote(ax, "IT基础设施大专占比40%（最高）；数据/AI/算法大专仅5%（最低），不宜正面竞争")
plt.tight_layout(); save_v3("fig28_it_subcategory_edu")


# ============================================================
# D. 软技能（V2）
# ============================================================
print("[D] 软技能...")

skill_recs = []
for _, row in skills_df.iterrows():
    sk = row["soft_skills"]
    if not isinstance(sk, (list, np.ndarray)): continue
    for s in sk:
        skill_recs.append({"year": row.get("招聘发布年份"), "cat": row.get("岗位类别",""), "skill": norm_skill(s)})
sk_df = pd.DataFrame(skill_recs)
sk_cnt = sk_df["skill"].value_counts()
top4 = sk_cnt.head(4).index.tolist()
N = len(df)

# fig29 Top20
top20_sk = sk_cnt.head(20)
fig, ax = plt.subplots(figsize=(10, 8))
ax.barh(range(len(top20_sk)), top20_sk.values,
        color=plt.cm.Blues_r(np.linspace(0.25, 0.8, len(top20_sk))))
ax.set_yticks(range(len(top20_sk))); ax.set_yticklabels(top20_sk.index, fontsize=10)
ax.invert_yaxis()
ax.set_xlabel("出现频次（条次）", fontsize=11)
ax.set_title(f"{PROJ}招聘软技能需求频次 Top20", fontsize=13, pad=12)
for i, v in enumerate(top20_sk.values):
    ax.text(v + 30, i, f"{v:,}（{v/N*1000:.0f}/千条）", va="center", fontsize=8.5)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
footnote(ax, f"共提取软技能58,519条次（2,447种原始表达）；覆盖率75.9%；沟通协调每千条433次遥遥领先")
plt.tight_layout(); save_v3("fig29_soft_skills_top20")

# fig30 软技能×类别热力图
top15_sk = sk_cnt.head(15).index.tolist()
main_cats = [c for c in CAT_ORDER if c in sk_df["cat"].unique()]
mat = []
for sk in top15_sk:
    row_d = {c: round(((sk_df["cat"]==c)&(sk_df["skill"]==sk)).sum() /
                       max((skills_df["岗位类别"]==c).sum(), 1) * 1000, 1)
             for c in main_cats}
    mat.append(row_d)
mat_df = pd.DataFrame(mat, index=top15_sk)[main_cats]
fig, ax = plt.subplots(figsize=(13, 8))
sns.heatmap(mat_df, cmap="YlOrRd", annot=True, fmt=".0f", linewidths=0.4, ax=ax,
            cbar_kws={"label":"每千条出现率"})
ax.set_title("各岗位类别软技能需求热力图（每千条出现率）", fontsize=13, pad=12)
ax.set_xlabel("岗位类别", fontsize=11); ax.set_ylabel("软技能", fontsize=11)
plt.xticks(rotation=30, ha="right", fontsize=9); plt.yticks(fontsize=9)
plt.tight_layout(); save_v3("fig30_soft_skills_category_heatmap")

# fig31 四大软技能历年趋势
sk_trend = {}
for sk in top4:
    sk_trend[sk] = {yr: ((sk_df["skill"]==sk)&(sk_df["year"]==yr)).sum() /
                         max((skills_df["招聘发布年份"]==yr).sum(), 1) * 1000
                    for yr in VALID_YEARS}
sk_trend_df = pd.DataFrame(sk_trend)
fig, ax = plt.subplots(figsize=(11, 5.5))
for i, sk in enumerate(top4):
    ax.plot(sk_trend_df.index, sk_trend_df[sk], "o-", lw=2.2, color=COLORS[i], label=sk, ms=6)
ax.set_xlabel("年份", fontsize=11); ax.set_ylabel("每千条出现率", fontsize=11)
ax.set_title("核心软技能需求历年变化趋势", fontsize=13, pad=12)
ax.legend(fontsize=10, loc="upper left")
ax.set_xticks(VALID_YEARS); plt.xticks(rotation=30)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
footnote(ax, "四大核心软技能历年高度稳定，不同于技术技能的快速迭代，是可持续聚焦的课程培养目标")
plt.tight_layout(); save_v3("fig31_soft_skills_trend")


# ============================================================
# E. 数字化程度（V2）
# ============================================================
print("[E] 数字化程度...")

DIMS = ["数字化程度","AI相关性","技术复杂度"]
DIM_C = dict(zip(DIMS, [COLORS[0],COLORS[1],COLORS[2]]))
digi_v = digi_df[digi_df["招聘发布年份"].isin(VALID_YEARS) & (digi_df["招聘发布年份"]!=2020)].copy()

# fig32 历年趋势
yr_means = digi_v.groupby("招聘发布年份")[DIMS].mean()
fig, ax = plt.subplots(figsize=(11, 5.5))
for dim in DIMS:
    ax.plot(yr_means.index, yr_means[dim], "o-", lw=2.2, color=DIM_C[dim], label=dim, ms=6)
ax.set_xlabel("年份", fontsize=11); ax.set_ylabel("平均评分（0—100）", fontsize=11)
ax.set_ylim(0, 80)
ax.set_title(f"{PROJ}岗位数字化指标历年均值趋势", fontsize=13, pad=12)
ax.legend(fontsize=10)
ax.set_xticks([y for y in VALID_YEARS if y!=2020]); plt.xticks(rotation=30)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
footnote(ax, "AI相关性全样本均值仅8.6分；数字化程度均值36.0分；2020年（仅2条）已排除；历年评分平稳无明显上升")
plt.tight_layout(); save_v3("fig32_digitalization_trend")

# fig33 类别箱线图
main_cats_d = [c for c in CAT_ORDER if c in digi_df["岗位类别"].unique()]
fig, axes = plt.subplots(1, 2, figsize=(15, 5.5))
for ax_i, (dim, title) in enumerate([("数字化程度","数字化程度分布"),("AI相关性","AI相关性分布")]):
    ax = axes[ax_i]
    data = [digi_df[digi_df["岗位类别"]==c][dim].dropna().values for c in main_cats_d]
    bp = ax.boxplot(data, patch_artist=True,
                    medianprops=dict(color="white", lw=2),
                    flierprops=dict(marker=".", ms=2, alpha=0.3))
    for p, c in zip(bp["boxes"], main_cats_d):
        p.set_facecolor(CAT_C.get(c, COLOR_NEUTRAL)); p.set_alpha(0.8)
    ax.set_xticks(range(1, len(main_cats_d)+1))
    ax.set_xticklabels(main_cats_d, rotation=30, ha="right", fontsize=9)
    ax.set_ylabel("评分（0—100）", fontsize=11)
    ax.set_title(f"各岗位类别{title}", fontsize=12, pad=10)
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
fig.suptitle(f"{PROJ}岗位数字化程度与AI相关性分类别分布", fontsize=13, y=1.02)
footnote(axes[0], "信息技术类数字化程度均值约72分；生产制造类约22分；行政人力约18分")
plt.tight_layout(); save_v3("fig33_digitalization_category_boxplot")

# fig34 数字化×薪资散点
digi_s = digi_df.copy()
digi_s["平均月薪"] = (digi_s["最低月薪"].fillna(0)+digi_s["最高月薪"].fillna(0))/2
digi_s = digi_s[(digi_s["平均月薪"]>0)&digi_s["数字化程度"].notna()&digi_s["岗位类别"].isin(main_cats_d)]
fig, ax = plt.subplots(figsize=(10, 6.5))
for c in main_cats_d[:6]:
    sub = digi_s[digi_s["岗位类别"]==c]
    ax.scatter(sub["数字化程度"], sub["平均月薪"]/1000,
               color=CAT_C.get(c, COLOR_NEUTRAL), alpha=0.25, s=16, label=c)
x = digi_s["数字化程度"].values; y = digi_s["平均月薪"].values/1000
ax.plot(np.linspace(0,100,100), np.polyval(np.polyfit(x,y,1), np.linspace(0,100,100)),
        "k--", lw=1.5, alpha=0.55, label="趋势线")
ax.set_xlabel("数字化程度评分（0—100）", fontsize=11)
ax.set_ylabel("平均月薪（千元）", fontsize=11)
ax.set_title("岗位数字化程度与薪资水平的关系", fontsize=13, pad=12)
ax.legend(fontsize=8.5, loc="upper left", ncol=2)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
footnote(ax, "数字化程度越高薪资越高；但多数岗位集中于低数字化区间（0—40分），工具应用层为主")
plt.tight_layout(); save_v3("fig34_digitalization_salary_scatter")


# ============================================================
# F. 本科vs大专文本差异（V2）
# ============================================================
print("[F] 本科vs大专差异...")

# fig35 特征数量对比条形图
cats_e, b_cnt, a_cnt = [], [], []
for item in edu_json:
    cat = item.get("category","")
    b = item.get("bachelor_more",{})
    a = item.get("associate_more",{})
    if not cat or not isinstance(b, dict): continue
    cats_e.append(cat)
    b_cnt.append(len(b.get("skills",[])) + len(b.get("responsibilities",[])))
    a_cnt.append(len(a.get("skills",[])) + len(a.get("responsibilities",[])))

x = np.arange(len(cats_e)); w = 0.38
fig, ax = plt.subplots(figsize=(11, 6))
ax.bar(x-w/2, b_cnt, w, color=COLORS[0], label="本科专属特征（设计者/管理者）", alpha=0.85)
ax.bar(x+w/2, a_cnt, w, color=COLORS[1], label="大专专属特征（执行者/操作者）", alpha=0.85)
for i, (b, a) in enumerate(zip(b_cnt, a_cnt)):
    ax.text(i-w/2, b+0.2, str(b), ha="center", fontsize=8.5, color=COLORS[0])
    ax.text(i+w/2, a+0.2, str(a), ha="center", fontsize=8.5, color=COLORS[1])
ax.set_xticks(x); ax.set_xticklabels(cats_e, rotation=30, ha="right", fontsize=9.5)
ax.set_ylabel("职位描述中专属特征条目数", fontsize=11)
ax.set_title("本科与大专岗位职位描述特征数量对比（LLM分析，10个类别）", fontsize=12, pad=12)
ax.legend(fontsize=10)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
footnote(ax, "基于分层随机抽样（各类别各60条）；全部10类别一致呈现\u201c本科=设计者/大专=执行者\u201d系统性分层")
plt.tight_layout(); save_v3("fig35_edu_diff_bars")

# fig36 差异矩阵热力图
mat_rows = []
for item in edu_json:
    cat = item.get("category","")
    b = item.get("bachelor_more",{})
    a = item.get("associate_more",{})
    if not cat or not isinstance(b, dict): continue
    mat_rows.append({
        "类别": cat,
        "技能深度差异": len(b.get("skills",[]))-len(a.get("skills",[])),
        "职责范围差异": len(b.get("responsibilities",[]))-len(a.get("responsibilities",[])),
        "复杂度信号差异": len(b.get("complexity_signals",[]))-len(a.get("complexity_signals",[])),
    })
mat_df = pd.DataFrame(mat_rows).set_index("类别")
fig, ax = plt.subplots(figsize=(9, 5.5))
sns.heatmap(mat_df.T, cmap="RdYlBu_r", center=0, annot=True, fmt=".0f",
            linewidths=0.4, ax=ax,
            cbar_kws={"label":"本科专属数 − 大专专属数（正值=本科更多）"})
ax.set_title("本科与大专岗位职位描述差异矩阵", fontsize=12, pad=12)
ax.set_xlabel("岗位类别", fontsize=11); ax.set_ylabel("差异维度", fontsize=11)
plt.xticks(rotation=30, ha="right", fontsize=9)
plt.tight_layout(); save_v3("fig36_edu_diff_matrix")


# ============================================================
# G. 技术工具（V2）
# ============================================================
print("[G] 技术工具...")

TNORM = {
    "python":"Python","python3":"Python","c++":"C++","c语言":"C","c":"C",
    "java":"Java","excel":"Excel","EXCEL":"Excel","word":"Word","WORD":"Word",
    "office":"Office","MS Office":"Office","linux":"Linux","LINUX":"Linux",
    "autocad":"AutoCAD","solidworks":"SolidWorks","erp":"ERP","ERP系统":"ERP",
    "cad":"CAD","ppt":"PPT","powerpoint":"PPT","plc":"PLC",
    "vue.js":"Vue.js","vue":"Vue.js","Vue":"Vue.js","react":"React",
    "arm":"ARM","matlab":"MATLAB","proe":"Pro/E","ug":"UG/NX","nx":"UG/NX",
}
TTYPE = {
    "CAD":"工程设计","SolidWorks":"工程设计","AutoCAD":"工程设计","MATLAB":"工程设计","Pro/E":"工程设计","UG/NX":"工程设计",
    "ERP":"企业管理","SAP":"企业管理","Oracle":"企业管理",
    "Excel":"办公工具","Office":"办公工具","Word":"办公工具","PPT":"办公工具",
    "C++":"编程语言","C":"编程语言","Java":"编程语言","Python":"编程语言","C#":"编程语言",
    "Linux":"系统平台","ARM":"系统平台","Android":"系统平台",
    "PLC":"工业控制","万用表":"电子仪器","示波器":"电子仪器",
    "Vue.js":"前端框架","React":"前端框架",
}
TTYPE_C = {
    "工程设计":COLORS[0],"企业管理":COLORS[1],"办公工具":COLORS[2],
    "编程语言":COLORS[3],"系统平台":COLORS[4],"工业控制":COLORS[5],
    "电子仪器":COLORS[6],"前端框架":"#888",
}
tool_recs = []
for _, row in tools_df.iterrows():
    tl = row["tools"]
    if not isinstance(tl, (list, np.ndarray)): continue
    yr = row.get("招聘发布年份"); cat = row.get("岗位类别","")
    for t in tl:
        tn = str(t).strip()
        tn = TNORM.get(tn, TNORM.get(tn.lower(), tn))
        if tn and len(tn) > 1:
            tool_recs.append({"year":yr,"cat":cat,"tool":tn})
tl_df = pd.DataFrame(tool_recs)
tl_cnt = tl_df["tool"].value_counts()

# fig37 Top30
top30 = tl_cnt.head(30)
fig, ax = plt.subplots(figsize=(10, 10))
bar_clrs = [TTYPE_C.get(TTYPE.get(t,""), COLOR_NEUTRAL) for t in top30.index]
ax.barh(range(len(top30)), top30.values, color=bar_clrs, height=0.72)
ax.set_yticks(range(len(top30))); ax.set_yticklabels(top30.index, fontsize=9.5)
ax.invert_yaxis()
ax.set_xlabel("出现频次（条次）", fontsize=11)
ax.set_title(f"{PROJ}职位描述中具体技术工具频次 Top30", fontsize=13, pad=12)
for i, v in enumerate(top30.values):
    ax.text(v+3, i, str(v), va="center", fontsize=8.5)
patches = [mpatches.Patch(color=c, label=t) for t,c in TTYPE_C.items() if t!="前端框架"]
ax.legend(handles=patches, fontsize=8.5, loc="lower right", ncol=2)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
footnote(ax, "C/C++合计1,007次（最高频编程语言）；ERP 732次（第二）；Python仅201次；AI框架未进Top30")
plt.tight_layout(); save_v3("fig37_tech_tools_top30")

# fig38 工具×类别热力图
top10_t = tl_cnt.head(10).index.tolist()
main_cats_t = [c for c in CAT_ORDER if c in tl_df["cat"].unique()]
tmat = pd.DataFrame(
    {c: {t: ((tl_df["cat"]==c)&(tl_df["tool"]==t)).sum() /
              max((tools_df["岗位类别"]==c).sum(),1)*1000
         for t in top10_t}
     for c in main_cats_t}
).T.T  # tool×cat
fig, ax = plt.subplots(figsize=(12, 6))
sns.heatmap(tmat[main_cats_t], cmap="Blues", annot=True, fmt=".0f",
            linewidths=0.4, ax=ax, cbar_kws={"label":"每千条出现率"})
ax.set_title("各岗位类别技术工具需求热力图（每千条出现率）", fontsize=12, pad=12)
ax.set_xlabel("岗位类别", fontsize=11); ax.set_ylabel("技术工具", fontsize=11)
plt.xticks(rotation=30, ha="right", fontsize=9)
plt.tight_layout(); save_v3("fig38_tools_category_heatmap")

# fig39 主要工具历年趋势
TOP6_T = ["C++","ERP","Excel","Python","Linux","CAD"]
t_trend = {}
for t in TOP6_T:
    t_trend[t] = {yr: ((tl_df["tool"]==t)&(tl_df["year"]==yr)).sum() /
                       max((tools_df["招聘发布年份"]==yr).sum(),1)*1000
                  for yr in VALID_YEARS}
t_trend_df = pd.DataFrame(t_trend)
fig, ax = plt.subplots(figsize=(11, 5.5))
for i, t in enumerate(TOP6_T):
    ax.plot(t_trend_df.index, t_trend_df[t], "o-", lw=2.2, color=COLORS[i%len(COLORS)], label=t, ms=5)
ax.set_xlabel("年份", fontsize=11); ax.set_ylabel("每千条出现率", fontsize=11)
ax.set_title("主要技术工具历年出现趋势（每千条出现率）", fontsize=13, pad=12)
ax.legend(fontsize=10, loc="upper left", ncol=2)
ax.set_xticks(VALID_YEARS); plt.xticks(rotation=30)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
plt.tight_layout(); save_v3("fig39_tools_trend")


# ============================================================
# H. V3专属综合对比图（新增，fig40/fig41）
# ============================================================
print("[H] V3综合对比图...")

# 合并C/C++计数
cc_count = tl_cnt.get("C++",0) + tl_cnt.get("C",0)
DISP_TOOLS = ["C/C++\n（合计）","Java","Linux","Python","ARM","PLC","TensorFlow","PyTorch"]
DISP_VALS  = [cc_count, tl_cnt.get("Java",0), tl_cnt.get("Linux",0),
              tl_cnt.get("Python",0), tl_cnt.get("ARM",0), tl_cnt.get("PLC",0),
              tl_cnt.get("TensorFlow",0), tl_cnt.get("PyTorch",0)]
BAR_CLR = ([COLORS[0]]*3 + [COLORS[1]] + [COLORS[0]]*2 + [COLOR_NEUTRAL]*2)

# fig40 C/C++ vs Python
fig, ax = plt.subplots(figsize=(10, 5.5))
bars = ax.bar(range(len(DISP_TOOLS)), DISP_VALS, color=BAR_CLR, width=0.65, zorder=3)
ax.set_xticks(range(len(DISP_TOOLS))); ax.set_xticklabels(DISP_TOOLS, fontsize=10.5)
ax.set_ylabel("出现频次（条次）", fontsize=11)
ax.set_title("编程/系统工具频次对比：嵌入式方向 vs Python vs AI框架", fontsize=12, pad=12)
ax.yaxis.grid(True, alpha=0.3, zorder=0)
for i, v in enumerate(DISP_VALS):
    ax.text(i, v+5, str(v), ha="center", fontsize=9.5, color="#333")
if DISP_VALS[0] and DISP_VALS[3]:
    r = DISP_VALS[0] / max(DISP_VALS[3],1)
    ax.annotate(f"C/C++是Python的\n{r:.1f}倍",
                xy=(0, DISP_VALS[0]), xytext=(1.2, DISP_VALS[0]+30),
                fontsize=9.5, color=COLORS[0], fontweight="bold",
                arrowprops=dict(arrowstyle="->", color=COLORS[0], lw=1.3))
legend_patches = [
    mpatches.Patch(color=COLORS[0], label="嵌入式/系统方向（C/C++、Linux、ARM、PLC）"),
    mpatches.Patch(color=COLORS[1], label="Python"),
    mpatches.Patch(color=COLOR_NEUTRAL, label="AI框架（TensorFlow、PyTorch）"),
]
ax.legend(handles=legend_patches, fontsize=9, loc="upper right")
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
footnote(ax, "面向专精特新制造业就业的课程工具选型关键依据：C/C++嵌入式技术栈实际需求是Python数据科学的5倍")
plt.tight_layout(); save_v3("fig40_cpp_vs_python")

# fig41 关键词热度 vs 工具频次落差
kw_d = pd.Series(kw_all).value_counts().to_dict()
GAP_LABELS = ["\u7269\u8054\u7f51\n(\u5173\u952e\u8bcd)","\u4eba\u5de5\u667a\u80fd\n(\u5173\u952e\u8bcd)",
              "\u5927\u6570\u636e\n(\u5173\u952e\u8bcd)","ERP\n(\u5de5\u5177)",
              "C/C++\u5408\u8ba1\n(\u5de5\u5177)","Python\n(\u5de5\u5177)",
              "TensorFlow\n(\u5de5\u5177)"]
GAP_VALS = [kw_d.get("物联网",0), kw_d.get("人工智能",0), kw_d.get("大数据",0),
            tl_cnt.get("ERP",0), cc_count, tl_cnt.get("Python",0), tl_cnt.get("TensorFlow",0)]
GAP_CLRS = [COLORS[0]]*3 + [COLORS[1]]*4

fig, ax = plt.subplots(figsize=(11, 5.5))
bars = ax.bar(range(len(GAP_LABELS)), GAP_VALS, color=GAP_CLRS, width=0.65, zorder=3)
ax.set_xticks(range(len(GAP_LABELS))); ax.set_xticklabels(GAP_LABELS, fontsize=10)
ax.set_ylabel("频次（条次）", fontsize=11)
ax.set_title("技术关键词热度（标签字段）vs 工具实际频次（职位描述文本）对比", fontsize=12, pad=12)
ax.yaxis.grid(True, alpha=0.3, zorder=0)
ax.axvline(2.5, color="#bbb", ls="--", lw=1.5)
ax.text(1, max(GAP_VALS)*0.88, "招聘标签中\n技术热词",  ha="center", fontsize=10, color=COLORS[0], style="italic")
ax.text(4.5, max(GAP_VALS)*0.88, "职位描述中\n实际工具", ha="center", fontsize=10, color=COLORS[1], style="italic")
for i, v in enumerate(GAP_VALS):
    ax.text(i, v+5, str(v), ha="center", fontsize=9, color="#333")
legend_patches2 = [mpatches.Patch(color=COLORS[0], label="结构化标签技术关键词"),
                   mpatches.Patch(color=COLORS[1], label="职位描述文本工具频次")]
ax.legend(handles=legend_patches2, fontsize=9.5)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
footnote(ax, "\u201c人工智能\u201d热词热度高但TensorFlow工具频次极低——话语繁荣与工具滞后并存；LLM评分AI相关性均值仅8.6分与此一致")
plt.tight_layout(); save_v3("fig41_keyword_vs_tool_gap")


# ============================================================
# 完成
# ============================================================
all_png = sorted(V3_DIR.glob("*.png"))
print(f"\n{'='*60}")
print(f"V3图表生成完成！共 {len(all_png)} 张图表")
print(f"输出目录：{V3_DIR.resolve()}")
print(f"{'='*60}")
for f in all_png:
    print(f"  {f.name}")
