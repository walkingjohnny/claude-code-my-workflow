# ============================================================
# 14_journal_2021_2024.py
# 用途：面向《中国大学生就业》投稿论文的数据分析与图表生成
#       仅使用2021-2024年数据（16,501条），生成7张配套图表
# 输出：Figures/journal/fig_j01-j07.png/.pdf
#       控制台打印全部论文所需统计量
# 依赖：scripts/_common.py, job_classified_data.csv, V2 parquets
# ============================================================

import os
import sys
import json
import pathlib

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import seaborn as sns

sys.path.insert(0, ".")
from scripts._common import setup_style, COLORS, COLOR_PRIMARY, COLOR_SECONDARY, COLOR_NEUTRAL, RANDOM_SEED

np.random.seed(RANDOM_SEED)

# --- 常量 ---
PROJ = "\u6df1\u5733\u5e02\u4e13\u7cbe\u7279\u65b0\u201c\u5c0f\u5de8\u4eba\u201d\u4f01\u4e1a"
YEAR_RANGE = [2021, 2022, 2023, 2024]
JOURNAL_FIG_DIR = "Figures/journal/"
os.makedirs(JOURNAL_FIG_DIR, exist_ok=True)

# 软技能标准化映射（与V3保持一致）
SOFT_SKILL_MAP = {
    "\u6c9f\u901a\u80fd\u529b": "\u6c9f\u901a\u534f\u8c03",
    "\u6c9f\u901a\u8868\u8fbe": "\u6c9f\u901a\u534f\u8c03",
    "\u6c9f\u901a\u6280\u5de7": "\u6c9f\u901a\u534f\u8c03",
    "\u534f\u8c03\u80fd\u529b": "\u6c9f\u901a\u534f\u8c03",
    "\u4eba\u9645\u6c9f\u901a": "\u6c9f\u901a\u534f\u8c03",
    "\u6c9f\u901a\u534f\u8c03\u80fd\u529b": "\u6c9f\u901a\u534f\u8c03",
    "\u56e2\u961f\u5408\u4f5c": "\u56e2\u961f\u534f\u4f5c",
    "\u56e2\u961f\u7cbe\u795e": "\u56e2\u961f\u534f\u4f5c",
    "\u56e2\u961f\u534f\u4f5c\u80fd\u529b": "\u56e2\u961f\u534f\u4f5c",
    "\u62b1\u538b": "\u6297\u538b\u80fd\u529b",
    "\u538b\u529b\u627f\u53d7": "\u6297\u538b\u80fd\u529b",
    "\u81ea\u4e3b\u5b66\u4e60": "\u5b66\u4e60\u80fd\u529b",
    "\u5feb\u901f\u5b66\u4e60": "\u5b66\u4e60\u80fd\u529b",
    "\u8d23\u4efb\u611f": "\u8d23\u4efb\u5fc3",
    "\u7ec6\u5fc3": "\u7ec6\u5fc3\u4e25\u8c28",
    "\u4e25\u8c28": "\u7ec6\u5fc3\u4e25\u8c28",
    "\u79ef\u6781\u4e3b\u52a8": "\u4e3b\u52a8\u6027",
}


def save_journal(fig_name):
    """保存到 Figures/journal/"""
    png = f"{JOURNAL_FIG_DIR}{fig_name}.png"
    pdf = f"{JOURNAL_FIG_DIR}{fig_name}.pdf"
    plt.savefig(png, dpi=300, bbox_inches="tight")
    plt.savefig(pdf, bbox_inches="tight")
    plt.close()
    print(f"  \u2713 {fig_name}")


def footnote(ax, text, y=-0.12):
    ax.annotate(text, xy=(0.5, y), xycoords="axes fraction",
                ha="center", fontsize=8, color="#888")


# ============================================================
# 0. 加载数据
# ============================================================
print("=" * 60)
print("\u300a\u4e2d\u56fd\u5927\u5b66\u751f\u5c31\u4e1a\u300b\u6295\u7a3f\u8bba\u6587\u6570\u636e\u5206\u6790\uff082021\u20132024\uff09")
print("=" * 60)

print("\n[0] \u52a0\u8f7d\u6570\u636e...")
df_all = pd.read_csv("scripts/job_classified_data.csv", low_memory=False)
df = df_all[(df_all["\u62db\u8058\u53d1\u5e03\u5e74\u4efd"] >= 2021) & (df_all["\u62db\u8058\u53d1\u5e03\u5e74\u4efd"] <= 2024)].copy()
print(f"  \u5168\u91cf\u6570\u636e\uff1a{len(df_all):,} \u6761\uff0c2021-2024\u5b50\u96c6\uff1a{len(df):,} \u6761")
print(f"  \u4f01\u4e1a\u6570\uff1a{df['\u4f01\u4e1a\u540d\u79f0'].nunique()}")

# V2数据
df_soft = pd.read_parquet("data/v2_soft_skills.parquet")
df_soft = df_soft[df_soft["\u62db\u8058\u53d1\u5e03\u5e74\u4efd"].isin(YEAR_RANGE)]

df_digi = pd.read_parquet("data/v2_digitalization.parquet")
df_digi = df_digi[df_digi["\u62db\u8058\u53d1\u5e03\u5e74\u4efd"].isin(YEAR_RANGE)]

df_tools = pd.read_parquet("data/v2_tech_tools.parquet")
df_tools = df_tools[df_tools["\u62db\u8058\u53d1\u5e03\u5e74\u4efd"].isin(YEAR_RANGE)]

with open("data/v2_edu_comparison.json", "r", encoding="utf-8") as f:
    edu_comp = json.load(f)

print(f"  V2\u6570\u636e\uff1a\u8f6f\u6280\u80fd {len(df_soft):,}\uff0c\u6570\u5b57\u5316 {len(df_digi):,}\uff0c\u5de5\u5177 {len(df_tools):,}")

setup_style()

# ============================================================
# 1. 基础统计量（控制台输出）
# ============================================================
print("\n" + "=" * 60)
print("\u57fa\u7840\u7edf\u8ba1\u91cf")
print("=" * 60)

# 1.1 年度招聘条数
yr_cnt = df.groupby("\u62db\u8058\u53d1\u5e03\u5e74\u4efd").size()
print("\n\u5e74\u5ea6\u62db\u8058\u6761\u6570\uff1a")
for y in YEAR_RANGE:
    print(f"  {y}: {yr_cnt.get(y, 0):,}")
growth = (yr_cnt[2024] - yr_cnt[2021]) / yr_cnt[2021] * 100
print(f"  2021\u21922024\u589e\u5e45\uff1a{growth:.1f}%")

# 1.2 岗位类别
cat_cnt = df["\u5c97\u4f4d\u7c7b\u522b"].value_counts()
print("\n\u5c97\u4f4d\u7c7b\u522b\u5206\u5e03\uff1a")
for c, v in cat_cnt.items():
    print(f"  {c}: {v:,} ({v/len(df)*100:.1f}%)")

# 1.3 企业规模
SIZE_MAP = {"S(\u5c0f\u578b)": "\u5c0f\u578b\uff08<100\u4eba\uff09", "M(\u4e2d\u578b)": "\u4e2d\u578b\uff08100-999\u4eba\uff09", "L(\u5927\u578b)": "\u5927\u578b\uff08\u22651000\u4eba\uff09"}
df["\u89c4\u6a21\u7ec4"] = df["\u4f01\u4e1a\u89c4\u6a21"].map(SIZE_MAP).fillna("\u5176\u4ed6")
sz_cnt = df[df["\u89c4\u6a21\u7ec4"] != "\u5176\u4ed6"]["\u89c4\u6a21\u7ec4"].value_counts()
print("\n\u4f01\u4e1a\u89c4\u6a21\uff1a")
for s, v in sz_cnt.items():
    print(f"  {s}: {v:,} ({v/sz_cnt.sum()*100:.1f}%)")

# 1.4 行业
if "\u56fd\u6807\u884c\u4e1a\u95e8\u7c7b" in df.columns:
    ind_cnt = df["\u56fd\u6807\u884c\u4e1a\u95e8\u7c7b"].value_counts().head(5)
    print("\n\u884c\u4e1aTop5\uff08\u56fd\u6807\u95e8\u7c7b\uff09\uff1a")
    for i, v in ind_cnt.items():
        print(f"  {i}: {v:,} ({v/len(df)*100:.1f}%)")

# 1.5 学历
if "\u5b66\u5386\u8981\u6c42" in df.columns:
    print("\n\u5404\u5e74\u5ea6\u5b66\u5386\u5206\u5e03\uff1a")
    for y in YEAR_RANGE:
        sub = df[df["\u62db\u8058\u53d1\u5e03\u5e74\u4efd"] == y]
        edu = sub["\u5b66\u5386\u8981\u6c42"].value_counts(normalize=True).head(4)
        parts = ", ".join([f"{e}={v:.1%}" for e, v in edu.items()])
        print(f"  {y}: {parts}")

# 1.6 技术关键词
if "\u6280\u672f\u5173\u952e\u8bcd" in df.columns:
    from collections import Counter
    tech_counter = Counter()
    for val in df["\u6280\u672f\u5173\u952e\u8bcd"].dropna():
        for kw in str(val).split(","):
            kw = kw.strip()
            if kw and kw != "-":
                tech_counter[kw] += 1
    print("\n\u6280\u672f\u5173\u952e\u8bcdTop15\uff1a")
    for kw, cnt in tech_counter.most_common(15):
        print(f"  {kw}: {cnt}")

# 1.7 软技能
print("\n\u8f6f\u6280\u80fdTop10\uff082021-2024\uff09\uff1a")
from collections import Counter as C2
skill_counter = C2()
for skills_val in df_soft["soft_skills"].dropna():
    if hasattr(skills_val, '__iter__') and not isinstance(skills_val, str):
        skills = list(skills_val)
    elif isinstance(skills_val, str):
        skills = [s.strip() for s in skills_val.split(",") if s.strip()]
    else:
        continue
    for s in skills:
        s = SOFT_SKILL_MAP.get(s, s)
        skill_counter[s] += 1
print(f"  \u8f6f\u6280\u80fd\u603b\u6761\u6b21\uff1a{sum(skill_counter.values()):,}")
for sk, cnt in skill_counter.most_common(10):
    rate = cnt / len(df_soft) * 1000
    print(f"  {sk}: {cnt:,} ({rate:.0f}/\u5343\u6761)")

# 1.8 数字化评分
dims = ["\u6570\u5b57\u5316\u7a0b\u5ea6", "AI\u76f8\u5173\u6027", "\u6280\u672f\u590d\u6742\u5ea6"]
print("\n\u6570\u5b57\u5316\u8bc4\u5206\uff082021-2024\u5747\u503c\uff09\uff1a")
for d in dims:
    if d in df_digi.columns:
        print(f"  {d}: {df_digi[d].mean():.1f} (\u4e2d\u4f4d\u6570 {df_digi[d].median():.0f})")

# 1.9 技术工具
tool_counter = C2()
for tools_val in df_tools["tools"].dropna():
    if hasattr(tools_val, '__iter__') and not isinstance(tools_val, str):
        tools = list(tools_val)
    elif isinstance(tools_val, str):
        tools = [t.strip() for t in tools_val.split(",") if t.strip()]
    else:
        continue
    for t in tools:
        tool_counter[t] += 1
print("\n\u6280\u672f\u5de5\u5177Top15\uff082021-2024\uff09\uff1a")
for t, cnt in tool_counter.most_common(15):
    print(f"  {t}: {cnt}")


# ============================================================
# 2. 图表生成
# ============================================================
print("\n" + "=" * 60)
print("\u56fe\u8868\u751f\u6210")
print("=" * 60)

# --- fig_j01: 年度招聘条数趋势 ---
fig, ax = plt.subplots(figsize=(8, 4.5))
bars = ax.bar(YEAR_RANGE, [yr_cnt.get(y, 0) for y in YEAR_RANGE],
              color=[COLORS[0], COLORS[1], COLORS[2], COLORS[3]], width=0.6, edgecolor="white", linewidth=1.2)
for bar in bars:
    h = bar.get_height()
    ax.text(bar.get_x() + bar.get_width()/2, h + 60, f"{int(h):,}",
            ha="center", fontsize=11, fontweight="bold", color="#333")
ax.set_xlabel("\u5e74\u4efd", fontsize=11)
ax.set_ylabel("\u62db\u8058\u6761\u6570", fontsize=11)
ax.set_title(f"{PROJ}\u62db\u8058\u89c4\u6a21\uff082021\u20142024\uff09", fontsize=13, pad=12)
ax.set_xticks(YEAR_RANGE)
ax.set_ylim(0, max(yr_cnt.values) * 1.18)
footnote(ax, f"\u6570\u636e\u6765\u6e90\uff1a\u667a\u8054\u62db\u8058\uff1b\u6709\u6548\u6837\u672c {len(df):,} \u6761\uff0c\u6db5\u76d6 {df['\u4f01\u4e1a\u540d\u79f0'].nunique()} \u5bb6\u4f01\u4e1a")
plt.tight_layout()
save_journal("fig_j01_annual_trend")

# --- fig_j02: 岗位类别分布 ---
cat_order = cat_cnt.index.tolist()
cat_order = [c for c in cat_order if c != "\u5176\u4ed6"] + (["\u5176\u4ed6"] if "\u5176\u4ed6" in cat_order else [])
cat_vals = [cat_cnt[c] for c in cat_order]
cat_colors = [COLORS[i % len(COLORS)] for i in range(len(cat_order))]

fig, ax = plt.subplots(figsize=(10, 5))
bars = ax.barh(range(len(cat_order)), cat_vals, color=cat_colors, height=0.6, edgecolor="white")
ax.set_yticks(range(len(cat_order)))
ax.set_yticklabels(cat_order, fontsize=10)
for bar, v in zip(bars, cat_vals):
    ax.text(v + 30, bar.get_y() + bar.get_height()/2, f"{v:,} ({v/len(df)*100:.1f}%)",
            va="center", fontsize=9, color="#333")
ax.set_xlabel("\u62db\u8058\u6761\u6570", fontsize=11)
ax.set_title(f"{PROJ}\u5c97\u4f4d\u529f\u80fd\u7c7b\u522b\u5206\u5e03\uff082021\u20142024\uff09", fontsize=13, pad=12)
ax.invert_yaxis()
plt.tight_layout()
save_journal("fig_j02_category_bar")

# --- fig_j03: 企业规模饼图 ---
sz_order = ["\u5c0f\u578b\uff08<100\u4eba\uff09", "\u4e2d\u578b\uff08100-999\u4eba\uff09", "\u5927\u578b\uff08\u22651000\u4eba\uff09"]
sz_vals = [sz_cnt.get(s, 0) for s in sz_order]
pie_colors = [COLORS[1], COLORS[0], COLORS[2]]

fig, ax = plt.subplots(figsize=(7, 6))
wedges, texts, autotexts = ax.pie(
    sz_vals, labels=sz_order, colors=pie_colors,
    autopct="%1.1f%%", startangle=140, pctdistance=0.65,
    wedgeprops=dict(linewidth=1.2, edgecolor="white"),
)
for t in texts:
    t.set_fontsize(11)
for at in autotexts:
    at.set_fontsize(10.5)
    at.set_color("white")
    at.set_fontweight("bold")
legend_labels = [f"{s}\uff1a{int(v):,}\u6761" for s, v in zip(sz_order, sz_vals)]
ax.legend(wedges, legend_labels, loc="lower center", bbox_to_anchor=(0.5, -0.12),
          fontsize=10, framealpha=0.9, ncol=1)
ax.set_title(f"{PROJ}\u62db\u8058\u6761\u6570\u4f01\u4e1a\u89c4\u6a21\u5206\u5e03", fontsize=13, pad=14)
plt.tight_layout()
save_journal("fig_j03_company_size_pie")

# --- fig_j04: 学历要求年度变化 ---
edu_col = "\u5b66\u5386\u8981\u6c42"
edu_levels = ["\u672c\u79d1", "\u5927\u4e13", "\u4e2d\u4e13/\u4e2d\u6280", "\u9ad8\u4e2d", "\u7855\u58eb"]
edu_colors = {"本科": COLORS[0], "大专": COLORS[1], "中专/中技": COLORS[2], "高中": COLORS[3], "硕士": COLORS[4]}

fig, ax = plt.subplots(figsize=(9, 5))
for level in edu_levels:
    pcts = []
    for y in YEAR_RANGE:
        sub = df[df["\u62db\u8058\u53d1\u5e03\u5e74\u4efd"] == y]
        pct = (sub[edu_col] == level).sum() / len(sub) * 100
        pcts.append(pct)
    ax.plot(YEAR_RANGE, pcts, "o-", lw=2.2, ms=7, label=level, color=edu_colors.get(level, COLOR_NEUTRAL))
    # 标注首尾
    ax.text(2021, pcts[0] + 0.8, f"{pcts[0]:.1f}%", ha="center", fontsize=8.5, color="#555")
    ax.text(2024, pcts[-1] + 0.8, f"{pcts[-1]:.1f}%", ha="center", fontsize=8.5, color="#555")

ax.set_xlabel("\u5e74\u4efd", fontsize=11)
ax.set_ylabel("\u5360\u6bd4\uff08%\uff09", fontsize=11)
ax.set_title(f"{PROJ}\u5b66\u5386\u8981\u6c42\u5e74\u5ea6\u53d8\u5316\uff082021\u20142024\uff09", fontsize=13, pad=12)
ax.set_xticks(YEAR_RANGE)
ax.legend(loc="upper right", fontsize=10)
ax.set_ylim(0, 55)
plt.tight_layout()
save_journal("fig_j04_edu_trend")

# --- fig_j05: 软技能Top10 ---
top10_skills = skill_counter.most_common(10)
sk_names = [s[0] for s in top10_skills][::-1]
sk_vals = [s[1] for s in top10_skills][::-1]

fig, ax = plt.subplots(figsize=(9, 5))
bars = ax.barh(range(len(sk_names)), sk_vals, color=COLORS[0], height=0.6, edgecolor="white")
ax.set_yticks(range(len(sk_names)))
ax.set_yticklabels(sk_names, fontsize=10)
for bar, v in zip(bars, sk_vals):
    rate = v / len(df_soft) * 1000
    ax.text(v + 30, bar.get_y() + bar.get_height()/2, f"{v:,} ({rate:.0f}/\u5343\u6761)",
            va="center", fontsize=9, color="#333")
ax.set_xlabel("\u51fa\u73b0\u9891\u6b21", fontsize=11)
ax.set_title(f"{PROJ}\u8f6f\u6280\u80fd\u9700\u6c42Top10\uff082021\u20142024\uff09", fontsize=13, pad=12)
plt.tight_layout()
save_journal("fig_j05_soft_skills_top10")

# --- fig_j06: 技术工具Top15 ---
top15_tools = tool_counter.most_common(15)
t_names = [t[0] for t in top15_tools][::-1]
t_vals = [t[1] for t in top15_tools][::-1]

fig, ax = plt.subplots(figsize=(9, 6))
bars = ax.barh(range(len(t_names)), t_vals, color=COLORS[1], height=0.6, edgecolor="white")
ax.set_yticks(range(len(t_names)))
ax.set_yticklabels(t_names, fontsize=10)
for bar, v in zip(bars, t_vals):
    ax.text(v + 8, bar.get_y() + bar.get_height()/2, f"{v:,}",
            va="center", fontsize=9, color="#333")
ax.set_xlabel("\u51fa\u73b0\u9891\u6b21", fontsize=11)
ax.set_title(f"{PROJ}\u804c\u4f4d\u63cf\u8ff0\u4e2d\u6280\u672f\u5de5\u5177Top15\uff082021\u20142024\uff09", fontsize=13, pad=12)
plt.tight_layout()
save_journal("fig_j06_tech_tools_top15")

# --- fig_j07: 各类别数字化评分箱线图 ---
cat_col = "\u5c97\u4f4d\u7c7b\u522b"
if cat_col in df_digi.columns:
    valid = df_digi[[cat_col, "\u6570\u5b57\u5316\u7a0b\u5ea6"]].dropna()
    cat_order_digi = valid.groupby(cat_col)["\u6570\u5b57\u5316\u7a0b\u5ea6"].median().sort_values(ascending=False).index.tolist()

    fig, ax = plt.subplots(figsize=(10, 5.5))
    data_by_cat = [valid[valid[cat_col] == cat]["\u6570\u5b57\u5316\u7a0b\u5ea6"].dropna().values for cat in cat_order_digi]
    bp = ax.boxplot(data_by_cat, vert=True, patch_artist=True,
                    medianprops=dict(color="white", linewidth=2))
    for i, patch in enumerate(bp["boxes"]):
        patch.set_facecolor(COLORS[i % len(COLORS)])
        patch.set_alpha(0.7)
    ax.set_xticklabels(cat_order_digi, rotation=35, ha="right", fontsize=9)
    ax.set_ylabel("\u6570\u5b57\u5316\u7a0b\u5ea6\u8bc4\u5206\uff080-100\uff09", fontsize=11)
    ax.set_title(f"{PROJ}\u5404\u5c97\u4f4d\u7c7b\u522b\u6570\u5b57\u5316\u7a0b\u5ea6\u5206\u5e03\uff082021\u20142024\uff09", fontsize=13, pad=12)
    ax.set_ylim(0, 105)
    footnote(ax, f"\u5168\u6837\u672c\u6570\u5b57\u5316\u7a0b\u5ea6\u5747\u503c {df_digi['\u6570\u5b57\u5316\u7a0b\u5ea6'].mean():.1f}\uff0cAI\u76f8\u5173\u6027\u5747\u503c {df_digi['AI\u76f8\u5173\u6027'].mean():.1f}")
    plt.tight_layout()
    save_journal("fig_j07_digitalization_boxplot")

print("\n" + "=" * 60)
print(f"\u56fe\u8868\u751f\u6210\u5b8c\u6210\uff01\u8f93\u51fa\u76ee\u5f55\uff1a{JOURNAL_FIG_DIR}")
print("=" * 60)
