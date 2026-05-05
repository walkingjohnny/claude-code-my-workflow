# ============================================================
# 19_industry_layer.py
# 用途：V5 — Step B（无 LLM）
#       1,337 家深圳专精特新"小巨人"企业的行业分布基础统计
#       + 与 597 家含招聘活动企业的对照
#       + 行业-学院映射初稿
# 输出：data/v5_demand_industry_base.parquet（1,337 家全样本）
#       data/v5_demand_industry_active.parquet（597 家招聘活跃子集）
#       data/v5_industry_to_college_mapping.csv（行业 ↔ 学院映射初稿）
#       Figures/journal/v5/fig_v5_a01—a04.png/.pdf
# 依赖：scripts/_common.py
# ============================================================

import os
import sys
import pathlib
import json
from collections import Counter

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.insert(0, ".")
from scripts._common import setup_style, COLORS, RANDOM_SEED

np.random.seed(RANDOM_SEED)
setup_style()

DATA_DIR = pathlib.Path("data")
FIG_DIR = pathlib.Path("Figures/journal/v5")
FIG_DIR.mkdir(parents=True, exist_ok=True)
RAW_XLSX = pathlib.Path("源数据/企业画像完整数据_带来源.xlsx")


# 行业-学院映射初稿（基于企查查门类与院校学院的领域对应；带"信心度"标注）
# 信心度：3=强对应，2=部分对应，1=弱/边缘对应
INDUSTRY_COLLEGE_MAP = [
    # 信息技术（805家）拆分到多个学院
    ("信息技术", "信息技术", "计算机与软件学院", 3, "软件/网络/互联网应用为主"),
    ("信息技术", "信息技术", "信息与通信学院", 3, "通信、IoT、车联网为主"),
    ("信息技术", "信息技术", "微电子学院", 3, "集成电路、电子产品方向"),
    ("信息技术", "信息技术", "人工智能学院", 3, "AI、大数据、云计算"),
    ("信息技术", "信息技术", "数字媒体学院", 2, "数字媒体技术、虚拟现实"),
    ("信息技术", "信息技术", "中德机器人学院", 2, "工业互联、智能机器人软件层"),

    # 机械设备（219家）
    ("机械设备", "机械设备", "智能制造与装备学院", 3, "机械、自动化主战场"),
    ("机械设备", "机械设备", "中德机器人学院", 3, "工业机器人、智能控制"),
    ("机械设备", "机械设备", "微电子学院", 1, "智能光电制造方向"),

    # 电力设备（78家）
    ("电力设备", "电力设备", "智能制造与装备学院", 2, "工业电气、自动化"),
    ("电力设备", "电力设备", "中德机器人学院", 1, "电气控制相关"),

    # 医药生物（77家）
    ("医药生物", "医药生物", "（暂无对应专业）", 0, "院校未开设医药/生物专业"),

    # 基础化工（38家）
    ("基础化工", "基础化工", "交通与环境学院", 1, "环境工程/环境监测可部分覆盖"),

    # 商贸零售（33家）+ 商业服务（17家）= 50 家
    ("商贸零售", "商贸零售", "管理学院", 3, "电子商务、国际商务、关务等"),
    ("商业服务", "商业服务", "管理学院", 3, "工商企业管理、文化产业经营"),
    ("商业服务", "商业服务", "应用外语学院", 2, "商务英语、现代文秘"),

    # 汽车（17家）
    ("汽车", "汽车", "信息与通信学院", 3, "汽车智能技术专业"),
    ("汽车", "汽车", "中德机器人学院", 2, "汽车制造工艺方向"),

    # 环保（11家）
    ("环保", "环保", "交通与环境学院", 3, "环境工程、环境监测主战场"),

    # 轻工制造（10家）
    ("轻工制造", "轻工制造", "数字媒体学院", 2, "工业设计、艺术设计"),
    ("轻工制造", "轻工制造", "智能制造与装备学院", 2, "工业设计专业"),

    # 航空航天与国防（9家）
    ("航空航天与国防", "航空航天与国防", "中德机器人学院", 2, "无人机应用技术"),

    # 建筑业（5家）+ 建材及非金属（3家）
    ("建筑业", "建筑业", "交通与环境学院", 3, "智能建造技术、园林工程"),
    ("建材及非金属", "建材及非金属", "交通与环境学院", 1, "建材类边缘"),

    # 其他
    ("家用电器", "家用电器", "智能制造与装备学院", 2, "家电制造"),
    ("公用事业", "公用事业", "交通与环境学院", 1, "环境/公共设施"),
    ("金属及金属矿", "金属及金属矿", "（暂无对应专业）", 0, "院校未对应"),
    ("文化传媒", "文化传媒", "数字媒体学院", 3, "广播影视、数字媒体艺术"),
    ("文化传媒", "文化传媒", "管理学院", 2, "文化产业经营与管理"),
    ("农林牧渔", "农林牧渔", "交通与环境学院", 1, "园林工程相关"),
    ("房地产", "房地产", "交通与环境学院", 2, "智能建造、园林"),
    ("石油石化", "石油石化", "（暂无对应专业）", 0, ""),
    ("交通运输", "交通运输", "交通与环境学院", 3, "城市轨道交通运营管理"),
    ("交通运输", "交通运输", "信息与通信学院", 1, "汽车智能技术"),
]


def load_and_filter():
    df = pd.read_excel(RAW_XLSX, engine="openpyxl")
    n0 = len(df)
    df = df[df["复核结果"] != "未见信息"].copy()
    df = df[df["目前所属城市"] == "深圳市"].copy()
    print(f"  原始 {n0} 行 → 过滤后 1,337 家深圳专精特新企业（剔除'未见信息'+非深圳市），实际：{len(df)}")
    return df


def industry_distribution(df: pd.DataFrame) -> dict:
    out = {}
    for col in ["国标行业门类", "企查查行业门类", "企查查行业大类", "企查查行业中类"]:
        if col in df.columns:
            counts = df[col].fillna("(空)").value_counts()
            out[col] = counts
    return out


def cross_tabs(df: pd.DataFrame) -> dict:
    """企查查行业门类 × {企业规模, 入选批次, 区县}"""
    out = {}
    for col, name in [
        ("企业规模", "industry_x_size"),
        ("入选批次", "industry_x_batch"),
        ("目前所属区县", "industry_x_district"),
    ]:
        if col in df.columns:
            out[name] = pd.crosstab(df["企查查行业门类"].fillna("(空)"), df[col].fillna("(空)"))
    return out


def cross_recruit_active(df_base: pd.DataFrame) -> pd.DataFrame:
    """对照：1,337 家全样本 vs 597 家有招聘记录的子集，按企查查行业门类。"""
    # 加载 597 家含招聘记录的企业名单（来自 V2 已分类的招聘数据）
    df_jobs = pd.read_csv("scripts/job_classified_data.csv", low_memory=False)
    df_jobs = df_jobs[df_jobs["招聘发布年份"].between(2021, 2024)].copy()
    active_companies = df_jobs["企业名称"].unique()
    print(f"  招聘活跃企业（2021—2024）：{len(active_companies)} 家")

    df_base["有招聘活动"] = df_base["企业名称"].isin(active_companies)
    base_dist = df_base["企查查行业门类"].fillna("(空)").value_counts()
    active_dist = df_base[df_base["有招聘活动"]]["企查查行业门类"].fillna("(空)").value_counts()

    cmp = pd.DataFrame({
        "1,337家_企业数": base_dist,
        "招聘活跃_企业数": active_dist,
    }).fillna(0).astype(int)
    cmp["招聘活跃率"] = (cmp["招聘活跃_企业数"] / cmp["1,337家_企业数"] * 100).round(1)
    cmp = cmp.sort_values("1,337家_企业数", ascending=False)
    return cmp


# ===== 可视化 =====
def fig_industry_pie(dist: pd.Series, title: str, fname: str, top_n: int = 8):
    """企查查行业门类 Top N + 其他 的饼图。"""
    top = dist.head(top_n)
    other = dist.iloc[top_n:].sum()
    if other > 0:
        top = pd.concat([top, pd.Series({"其他": other})])
    fig, ax = plt.subplots(figsize=(8, 7))
    cmap_colors = [COLORS[i % len(COLORS)] for i in range(len(top))]
    wedges, texts, autotexts = ax.pie(
        top.values, labels=top.index, colors=cmap_colors,
        autopct="%1.1f%%", startangle=120, pctdistance=0.78,
        wedgeprops=dict(linewidth=1.2, edgecolor="white"),
    )
    for t in texts:
        t.set_fontsize(10)
    for at in autotexts:
        at.set_fontsize(9.5)
        at.set_color("white")
        at.set_fontweight("bold")
    ax.set_title(title, fontsize=12, pad=12)
    legend_labels = [f"{k}: {v}家" for k, v in top.items()]
    ax.legend(wedges, legend_labels, loc="lower center",
              bbox_to_anchor=(0.5, -0.18), fontsize=9, ncol=2)
    plt.tight_layout()
    plt.savefig(FIG_DIR / f"{fname}.png", dpi=300, bbox_inches="tight")
    plt.savefig(FIG_DIR / f"{fname}.pdf", bbox_inches="tight")
    plt.close()
    print(f"  ✓ {fname}")


def fig_industry_compare(cmp: pd.DataFrame):
    """1,337 vs 597 招聘活跃 企业按行业门类对比柱图。"""
    cmp_top = cmp.head(15)
    fig, ax = plt.subplots(figsize=(10, 7))
    x = range(len(cmp_top))
    w = 0.4
    ax.barh([i + w/2 for i in x], cmp_top["1,337家_企业数"], w,
            color=COLORS[0], label=f"全样本 1,337 家", edgecolor="white")
    ax.barh([i - w/2 for i in x], cmp_top["招聘活跃_企业数"], w,
            color=COLORS[1], label=f"招聘活跃子集", edgecolor="white")
    ax.set_yticks(list(x))
    ax.set_yticklabels(cmp_top.index, fontsize=9)
    ax.invert_yaxis()
    for i, (n_all, n_act, rate) in enumerate(zip(
        cmp_top["1,337家_企业数"], cmp_top["招聘活跃_企业数"], cmp_top["招聘活跃率"]
    )):
        ax.text(n_all + 4, i + w/2, f"{int(n_all)}", va="center", fontsize=8)
        ax.text(n_act + 4, i - w/2, f"{int(n_act)} ({rate}%)", va="center", fontsize=8)
    ax.set_xlabel("企业数")
    ax.set_title("企查查行业门类：全样本 vs 招聘活跃子集", fontsize=12, pad=10)
    ax.legend(loc="lower right", fontsize=9)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "fig_v5_a02_industry_compare.png", dpi=300, bbox_inches="tight")
    plt.savefig(FIG_DIR / "fig_v5_a02_industry_compare.pdf", bbox_inches="tight")
    plt.close()
    print("  ✓ fig_v5_a02_industry_compare")


def fig_industry_size_heatmap(ct: pd.DataFrame):
    """企查查行业门类 × 企业规模 热力图。"""
    fig, ax = plt.subplots(figsize=(10, 7))
    sns.heatmap(ct, cmap="YlOrRd", annot=True, fmt="d",
                cbar_kws={"label": "企业数"}, ax=ax,
                linewidths=0.4, linecolor="white")
    ax.set_title("企查查行业门类 × 企业规模分布", fontsize=12, pad=10)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "fig_v5_a03_industry_size.png", dpi=300, bbox_inches="tight")
    plt.savefig(FIG_DIR / "fig_v5_a03_industry_size.pdf", bbox_inches="tight")
    plt.close()
    print("  ✓ fig_v5_a03_industry_size")


def fig_district(df: pd.DataFrame):
    """深圳各区分布。"""
    if "目前所属区县" not in df.columns:
        return
    dist = df["目前所属区县"].fillna("(空)").value_counts()
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.barh(range(len(dist)), dist.values, color=COLORS[2], edgecolor="white")
    ax.set_yticks(range(len(dist)))
    ax.set_yticklabels(dist.index, fontsize=10)
    ax.invert_yaxis()
    for i, v in enumerate(dist.values):
        ax.text(v + 4, i, f"{int(v)}", va="center", fontsize=9)
    ax.set_xlabel("企业数")
    ax.set_title("1,337 家深圳专精特新企业的区县分布", fontsize=12, pad=10)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "fig_v5_a04_district.png", dpi=300, bbox_inches="tight")
    plt.savefig(FIG_DIR / "fig_v5_a04_district.pdf", bbox_inches="tight")
    plt.close()
    print("  ✓ fig_v5_a04_district")


def main():
    print("=" * 60)
    print("V5 Step 19 — 行业层基础统计")
    print("=" * 60)

    df = load_and_filter()

    # 1. 各分类系统的分布
    dists = industry_distribution(df)
    print("\n=== 国标行业门类（13 门类） ===")
    print(dists["国标行业门类"].head(15).to_string())

    print("\n=== 企查查行业门类（21 门类） ===")
    print(dists["企查查行业门类"].head(25).to_string())

    print("\n=== 企查查行业大类（Top20） ===")
    print(dists["企查查行业大类"].head(20).to_string())

    print("\n=== 企查查行业中类（Top20） ===")
    print(dists["企查查行业中类"].head(20).to_string())

    # 保存基础分布
    base_qcc = df["企查查行业门类"].fillna("(空)").value_counts().rename_axis("行业").reset_index(name="企业数")
    base_qcc.to_parquet(DATA_DIR / "v5_demand_industry_base.parquet", index=False)
    base_qcc.to_csv(DATA_DIR / "v5_demand_industry_base.csv", index=False, encoding="utf-8-sig")

    # 2. 与招聘活跃子集对比
    print("\n=== 全样本 vs 招聘活跃子集（按企查查行业门类） ===")
    cmp = cross_recruit_active(df)
    print(cmp.to_string())
    cmp.to_parquet(DATA_DIR / "v5_demand_industry_active.parquet", index=True)
    cmp.to_csv(DATA_DIR / "v5_demand_industry_active.csv", index=True, encoding="utf-8-sig")

    # 3. 行业 × 企业规模 交叉表
    cts = cross_tabs(df)
    print("\n=== 企查查行业门类 × 企业规模 ===")
    print(cts["industry_x_size"].head(15).to_string())

    # 4. 行业-学院映射初稿
    map_df = pd.DataFrame(INDUSTRY_COLLEGE_MAP, columns=[
        "企查查行业门类", "企查查行业门类_拷贝", "对应学院", "信心度", "说明"
    ])
    map_df = map_df.drop(columns=["企查查行业门类_拷贝"])
    # 加上行业的企业数
    map_df = map_df.merge(base_qcc, left_on="企查查行业门类", right_on="行业", how="left").drop(columns=["行业"])
    map_df = map_df.rename(columns={"企业数": "行业基数"})
    map_df = map_df.sort_values(["行业基数", "信心度"], ascending=[False, False])
    map_df.to_csv(DATA_DIR / "v5_industry_to_college_mapping.csv", index=False, encoding="utf-8-sig")
    print(f"\n=== 行业-学院映射初稿（共 {len(map_df)} 条对应关系） ===")
    print(map_df.head(20).to_string(index=False))

    # 5. 可视化
    print("\n=== 生成可视化 ===")
    fig_industry_pie(dists["企查查行业门类"], "1,337 家深圳专精特新企业 · 企查查行业门类分布",
                     "fig_v5_a01_industry_pie")
    fig_industry_compare(cmp)
    fig_industry_size_heatmap(cts["industry_x_size"].head(12))
    fig_district(df)

    print("\n=== Step 19 完成 ===")


if __name__ == "__main__":
    main()
