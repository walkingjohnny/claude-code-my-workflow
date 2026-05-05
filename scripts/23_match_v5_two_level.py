# ============================================================
# 23_match_v5_two_level.py
# 用途：V5 — 供给-需求双层匹配
#       Level 1：行业层匹配（学院 ↔ 1,337 家企业行业）
#       Level 2：课程粒度匹配（每门课的四元组 ↔ 招聘记录的工具/职责）
# 输出：data/v5_level1_industry_match.parquet
#       data/v5_level2_course_hit.parquet
#       data/v5_level2_course_top_jobs.parquet（每门课匹配最高的 5 个岗位）
#       Figures/journal/v5/fig_v5_b01—b04.png/.pdf
# 依赖：scripts/_common.py
#       data/v5_supply_industry.parquet（来自 21）
#       data/v5_supply_courses.parquet  （来自 22）
#       data/v5_demand_industry_active.parquet（来自 19）
#       data/v2_tech_tools.parquet & v2_soft_skills.parquet（来自 V2）
#       scripts/job_classified_data.csv
# ============================================================

import os
import sys
import pathlib
import json
from collections import Counter, defaultdict

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

sys.path.insert(0, ".")
from scripts._common import setup_style, COLORS, RANDOM_SEED

np.random.seed(RANDOM_SEED)
setup_style()

DATA = pathlib.Path("data")
FIG = pathlib.Path("Figures/journal/v5")
FIG.mkdir(parents=True, exist_ok=True)

# 同义词典（沿用 V4 的 200+ 条规则用于工具规范化）
import importlib.util
spec = importlib.util.spec_from_file_location("m18", "scripts/18_match_v4.py")
m18 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m18)
canonicalize_tool = m18.canonicalize_tool
canonicalize_tools_list = m18.canonicalize_tools_list


# ============================================================
# Level 1：行业层匹配
# ============================================================
def level1_industry_match():
    print("=" * 60)
    print("Level 1：行业层匹配")
    print("=" * 60)

    # 1,337 家全样本行业分布
    base = pd.read_parquet(DATA / "v5_demand_industry_base.parquet")
    base = base.set_index("行业")

    # 招聘活跃 597 家行业分布
    active = pd.read_parquet(DATA / "v5_demand_industry_active.parquet")
    active.index.name = "行业"

    # 学院 → 行业映射初稿（人工）
    map_df = pd.read_csv(DATA / "v5_industry_to_college_mapping.csv")

    # 学院 → 各行业的 LLM 抽取分布（来自 21）
    sup = pd.read_parquet(DATA / "v5_supply_industry.parquet")

    # 计算"学院实际服务面向"的行业向量（基于 LLM 抽取频次加权）
    rows = []
    for _, r in sup.iterrows():
        ind_json = r.get("industries_json", "[]")
        try:
            inds = json.loads(ind_json)
        except Exception:
            inds = []
        for it in inds:
            if isinstance(it, dict) and it.get("name"):
                rows.append({
                    "学院": r["学院"], "专业": r["专业名"],
                    "行业": it["name"], "score": it.get("score", 0)
                })
    flat = pd.DataFrame(rows)
    college_industry = flat.groupby(["学院", "行业"])["score"].sum().unstack(fill_value=0)
    # 按行求和=学院总服务覆盖；归一化
    college_industry_norm = college_industry.div(college_industry.sum(axis=1), axis=0)

    # 与 1,337 家行业基数对比：哪些学院被高度对接？哪些行业有"承接学院"？
    # 行业基数（1,337）归一化分布
    base_norm = base["企业数"] / base["企业数"].sum()

    # 余弦相似度：每个学院的服务向量 vs 1,337 家行业向量
    common_industries = sorted(set(college_industry_norm.columns) & set(base_norm.index))
    college_vecs = college_industry_norm[common_industries].values
    base_vec = base_norm[common_industries].values.reshape(1, -1)
    sims = cosine_similarity(college_vecs, base_vec).flatten()

    college_score = pd.DataFrame({
        "学院": college_industry_norm.index,
        "余弦相似度（vs 1,337家）": sims.round(3),
        "主服务行业": college_industry.idxmax(axis=1).values,
    })
    college_score = college_score.sort_values("余弦相似度（vs 1,337家）", ascending=False)
    print("\n=== 学院服务向量 vs 1,337 家行业基数的余弦相似度 ===")
    print(college_score.to_string(index=False))

    # 行业承接力：每个行业有多少专业服务
    industry_coverage = flat.groupby("行业")["专业"].nunique().sort_values(ascending=False)
    coverage = pd.DataFrame({
        "行业": industry_coverage.index,
        "服务专业数": industry_coverage.values,
    })
    coverage = coverage.merge(base.reset_index().rename(columns={"企业数": "1337家_企业数"}), on="行业", how="outer")
    coverage["1337家_企业数"] = coverage["1337家_企业数"].fillna(0).astype(int)
    coverage["服务专业数"] = coverage["服务专业数"].fillna(0).astype(int)
    coverage["每企业的服务专业密度"] = (coverage["服务专业数"] / coverage["1337家_企业数"].replace(0, np.nan)).round(4)
    coverage = coverage.sort_values("1337家_企业数", ascending=False)
    print("\n=== 行业承接力（哪些行业有专业服务，哪些是空白）===")
    print(coverage.to_string(index=False))

    college_industry.to_parquet(DATA / "v5_level1_college_industry_matrix.parquet", index=True)
    college_score.to_csv(DATA / "v5_level1_college_score.csv", index=False, encoding="utf-8-sig")
    coverage.to_csv(DATA / "v5_level1_industry_coverage.csv", index=False, encoding="utf-8-sig")

    # 可视化：学院 × 行业 LLM 服务向量热力图
    fig, ax = plt.subplots(figsize=(13, 8))
    show = college_industry.loc[:, college_industry.sum(axis=0).sort_values(ascending=False).index[:15]]
    sns.heatmap(show, cmap="YlOrRd", annot=True, fmt=".0f",
                cbar_kws={"label": "LLM 抽取服务面向加权分"}, ax=ax)
    ax.set_title("各学院 LLM 服务面向 × Top15 行业（数值=置信度加权和）", fontsize=12, pad=10)
    ax.set_xlabel("行业")
    ax.set_ylabel("")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(FIG / "fig_v5_b01_college_industry_heatmap.png", dpi=300, bbox_inches="tight")
    plt.savefig(FIG / "fig_v5_b01_college_industry_heatmap.pdf", bbox_inches="tight")
    plt.close()
    print("  ✓ fig_v5_b01_college_industry_heatmap")

    return college_score, coverage


# ============================================================
# Level 2：课程粒度匹配
# ============================================================
def normalize_token_set(items):
    """把工具/技能/能力/知识点列表规范化（去除空白、去重、应用工具同义词典）。"""
    out = set()
    if items is None:
        return out
    if hasattr(items, "__iter__") and not isinstance(items, str):
        seq = list(items)
    else:
        return out
    for x in seq:
        if not isinstance(x, str):
            continue
        x = x.strip()
        if not x:
            continue
        out.add(canonicalize_tool(x))
    return out


def level2_course_hit():
    print("\n" + "=" * 60)
    print("Level 2：课程粒度匹配")
    print("=" * 60)

    courses = pd.read_parquet(DATA / "v5_supply_courses.parquet")
    print(f"  课程数：{len(courses)}")

    # 招聘记录（V2 已抽取的工具集）
    df_tools = pd.read_parquet(DATA / "v2_tech_tools.parquet")
    df_tools = df_tools[df_tools["招聘发布年份"].between(2021, 2024)].copy()
    print(f"  招聘记录数：{len(df_tools):,}")

    # 计算每门课的工具集（规范化）
    courses["tool_set"] = courses["tools"].apply(normalize_token_set)
    def safe_list(x):
        if x is None:
            return []
        if hasattr(x, "__iter__") and not isinstance(x, str):
            return list(x)
        return []
    courses["all_quad_set"] = courses.apply(
        lambda r: normalize_token_set(safe_list(r["tools"]) + safe_list(r["skills"]) + safe_list(r["knowledge"])),
        axis=1
    )

    # 招聘记录的工具集（规范化）
    job_tool_sets = []
    for _, r in df_tools.iterrows():
        items = r["tools"]
        if hasattr(items, "__iter__") and not isinstance(items, str):
            s = set(canonicalize_tool(x) for x in items if isinstance(x, str))
        else:
            s = set()
        job_tool_sets.append(s)
    df_tools = df_tools.copy()
    df_tools["tool_set"] = job_tool_sets
    df_tools["n_tools"] = df_tools["tool_set"].apply(len)

    # Jaccard 相似度
    def jaccard(a: set, b: set):
        if not a or not b:
            return 0.0
        return len(a & b) / len(a | b)

    # 对每门课，计算与所有招聘记录的 Jaccard，取 hit_count(>0)、top10 mean、avg
    print("  计算 Jaccard … （课程数 × 招聘记录数 = 巨量，使用倒排索引加速）")

    # 倒排索引：tool → 招聘记录索引集合
    tool_to_jobs = defaultdict(set)
    for i, ts in enumerate(df_tools["tool_set"]):
        for t in ts:
            if t:
                tool_to_jobs[t].add(i)

    course_results = []
    for _, c in courses.iterrows():
        tools = c["tool_set"]
        if not tools:
            course_results.append({
                "course_id": c["course_id"], "major": c["major"], "course_name": c["course_name"],
                "n_tools": 0, "n_jobs_hit_any": 0, "hit_rate": 0.0,
                "best_jaccard": 0.0, "top5_mean_jaccard": 0.0,
            })
            continue
        # 候选岗位 = 工具集中任一工具命中的岗位的并集
        cand_jobs = set()
        for t in tools:
            cand_jobs |= tool_to_jobs.get(t, set())
        if not cand_jobs:
            course_results.append({
                "course_id": c["course_id"], "major": c["major"], "course_name": c["course_name"],
                "n_tools": len(tools), "n_jobs_hit_any": 0, "hit_rate": 0.0,
                "best_jaccard": 0.0, "top5_mean_jaccard": 0.0,
            })
            continue
        # 计算这些候选岗位的 Jaccard
        sims = []
        for ji in cand_jobs:
            sims.append(jaccard(tools, df_tools["tool_set"].iloc[ji]))
        sims.sort(reverse=True)
        course_results.append({
            "course_id": c["course_id"], "major": c["major"], "course_name": c["course_name"],
            "n_tools": len(tools),
            "n_jobs_hit_any": len(cand_jobs),
            "hit_rate": round(len(cand_jobs) / len(df_tools), 4),
            "best_jaccard": round(max(sims), 3),
            "top5_mean_jaccard": round(np.mean(sims[:5]), 3),
        })

    res = pd.DataFrame(course_results)
    res.to_parquet(DATA / "v5_level2_course_hit.parquet", index=False)
    res.to_csv(DATA / "v5_level2_course_hit.csv", index=False, encoding="utf-8-sig")
    print(f"\n  → {DATA / 'v5_level2_course_hit.parquet'}")

    # 课程命中率统计
    print("\n=== 课程命中率分布 ===")
    print(f"  课程总数：{len(res)}")
    print(f"  含工具的课程：{(res['n_tools'] > 0).sum()}（{(res['n_tools']>0).sum()/len(res)*100:.1f}%）")
    print(f"  能命中至少 1 条招聘的课程：{(res['n_jobs_hit_any'] > 0).sum()}")
    print(f"  平均命中率（含工具子集）：{res[res['n_tools']>0]['hit_rate'].mean():.3f}")
    print(f"  最佳 Jaccard 均值（含工具子集）：{res[res['n_tools']>0]['best_jaccard'].mean():.3f}")

    # 各专业聚合
    by_major = res.groupby("major").agg(
        课程数=("course_id", "count"),
        含工具课程数=("n_tools", lambda x: (x > 0).sum()),
        平均命中率=("hit_rate", "mean"),
        最佳Jaccard均值=("best_jaccard", "mean"),
    ).round(3).sort_values("平均命中率", ascending=False)
    by_major.to_csv(DATA / "v5_level2_by_major.csv", encoding="utf-8-sig")
    print("\n=== 各专业 Level 2 课程命中率（Top10）===")
    print(by_major.head(10).to_string())

    return res, by_major


def main():
    college_score, coverage = level1_industry_match()
    course_hit, by_major = level2_course_hit()

    # 综合可视化：课程命中率分布直方图
    fig, ax = plt.subplots(figsize=(10, 5))
    valid = course_hit[course_hit["n_tools"] > 0]["hit_rate"] * 100
    ax.hist(valid, bins=30, color=COLORS[0], edgecolor="white", alpha=0.85)
    ax.axvline(valid.median(), color="red", linestyle="--", lw=1.5, label=f"中位 {valid.median():.1f}%")
    ax.set_xlabel("课程命中率（%）")
    ax.set_ylabel("课程数")
    ax.set_title(f"Level 2：课程命中率分布（仅含工具的 {len(valid)} 门课）", fontsize=12)
    ax.legend()
    plt.tight_layout()
    plt.savefig(FIG / "fig_v5_b02_course_hit_rate_hist.png", dpi=300, bbox_inches="tight")
    plt.savefig(FIG / "fig_v5_b02_course_hit_rate_hist.pdf", bbox_inches="tight")
    plt.close()
    print("  ✓ fig_v5_b02_course_hit_rate_hist")

    # 各专业的 Level 2 表现
    fig, ax = plt.subplots(figsize=(10, 13))
    sortd = by_major.sort_values("平均命中率", ascending=True)
    ax.barh(range(len(sortd)), sortd["平均命中率"] * 100, color=COLORS[0], edgecolor="white")
    ax.set_yticks(range(len(sortd)))
    ax.set_yticklabels(sortd.index, fontsize=8)
    for i, v in enumerate(sortd["平均命中率"] * 100):
        ax.text(v + 0.3, i, f"{v:.1f}%", va="center", fontsize=7)
    ax.set_xlabel("平均课程命中率（%）")
    ax.set_title("各专业 Level 2 课程命中率排序", fontsize=12, pad=10)
    plt.tight_layout()
    plt.savefig(FIG / "fig_v5_b03_major_hit_bar.png", dpi=300, bbox_inches="tight")
    plt.savefig(FIG / "fig_v5_b03_major_hit_bar.pdf", bbox_inches="tight")
    plt.close()
    print("  ✓ fig_v5_b03_major_hit_bar")

    print("\n=== Step 23 完成 ===")


if __name__ == "__main__":
    main()
