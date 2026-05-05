# ============================================================
# 09_soft_skills.py
# 用途：V2研究 - 从职位描述中提取软技能需求，分析其跨岗位分布与历年趋势
# 输出：data/v2_soft_skills.parquet
#       Figures/fig29_soft_skills_top20.png/.pdf
#       Figures/fig30_soft_skills_category_heatmap.png/.pdf
#       Figures/fig31_soft_skills_trend.png/.pdf
# 依赖：scripts/llm_client.py, scripts/_common.py
#       scripts/job_classified_data.csv（V1分类结果）
# ============================================================

import os
import sys
import pathlib
import collections

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import seaborn as sns

sys.path.insert(0, ".")
from scripts._common import setup_style, save_fig, FIGURES_DIR, RANDOM_SEED
from scripts.llm_client import batch_extract

np.random.seed(RANDOM_SEED)

TASK_NAME = "soft_skills"
OUTPUT_PARQUET = pathlib.Path("data/v2_soft_skills.parquet")

SYSTEM_PROMPT = (
    "你是专业的招聘数据分析师。"
    "请从招聘职位描述中提取软技能要求（即非专业技术技能，如沟通、团队协作、领导力、执行力等）。"
    "只返回JSON，不要任何额外说明。"
)

USER_PROMPT_TEMPLATE = (
    "从以下{count}条职位描述中，分别提取每个职位要求的软技能列表。\n\n"
    "软技能定义：非专业技术要求，包括但不限于：沟通能力、团队协作、执行力、学习能力、"
    "责任心、抗压能力、问题解决能力、领导力、客户服务意识、细心/严谨等。\n\n"
    "输出格式（JSON数组）：\n"
    '[{{"id": "记录ID", "soft_skills": ["技能1", "技能2", ...]}}, ...]\n\n'
    "如果职位描述中没有提及任何软技能，输出空列表[]。\n\n"
    "职位描述：\n{texts}"
)

# 软技能标准化映射（将相近表达归一）
NORMALIZE_MAP = {
    "沟通协调能力": "沟通协调",
    "沟通能力": "沟通协调",
    "沟通协调": "沟通协调",
    "沟通指导能力": "沟通协调",
    "团队协作能力": "团队协作",
    "团队合作": "团队协作",
    "协作精神": "团队协作",
    "执行力": "执行力",
    "计划与执行能力": "执行力",
    "学习能力": "学习能力",
    "学习意愿": "学习能力",
    "持续学习": "学习能力",
    "责任心": "责任心",
    "责任感": "责任心",
    "细心": "细心严谨",
    "严谨": "细心严谨",
    "细致": "细心严谨",
    "细心严谨": "细心严谨",
    "服务意识": "服务意识",
    "客户服务意识": "服务意识",
    "抗压能力": "抗压能力",
    "压力管理": "抗压能力",
    "领导力": "领导力",
    "领导能力": "领导力",
    "管理能力": "领导力",
    "问题解决能力": "问题解决",
    "分析问题能力": "问题解决",
    "判断与决策能力": "判断决策",
    "决策能力": "判断决策",
    "创新能力": "创新思维",
    "创新思维": "创新思维",
    "需求分析能力": "需求分析",
    "人际能力": "人际关系",
    "人际沟通": "人际关系",
    "积极主动": "主动性",
    "主动性": "主动性",
    "自我驱动": "主动性",
}


def normalize_skill(skill: str) -> str:
    """软技能标准化。"""
    skill = skill.strip()
    return NORMALIZE_MAP.get(skill, skill)


def run_extraction(df: pd.DataFrame, reset: bool = False) -> pd.DataFrame:
    """运行LLM提取，返回含soft_skills列的DataFrame。"""
    # 添加行索引作为ID
    df = df.copy()
    df["jd_id"] = [f"JD_{i:05d}" for i in range(len(df))]

    result = batch_extract(
        df=df,
        id_column="jd_id",
        text_column="职位描述",
        task_name=TASK_NAME,
        system_prompt=SYSTEM_PROMPT,
        user_prompt_template=USER_PROMPT_TEMPLATE,
        output_field="soft_skills",
        batch_size=20,
        reset=reset,
    )
    return result


def plot_top20_skills(skill_counts: pd.Series, fig_name: str = "fig29_soft_skills_top20"):
    """图29：软技能频率Top20条形图。"""
    top20 = skill_counts.head(20)
    fig, ax = plt.subplots(figsize=(10, 7))
    colors = plt.cm.Blues_r(np.linspace(0.3, 0.8, len(top20)))
    bars = ax.barh(range(len(top20)), top20.values, color=colors)
    ax.set_yticks(range(len(top20)))
    ax.set_yticklabels(top20.index, fontsize=10)
    ax.invert_yaxis()
    ax.set_xlabel("出现频次（条）", fontsize=11)
    ax.set_title(
        '\u6df1\u5733\u5e02\u4e13\u7cbe\u7279\u65b0\u201c\u5c0f\u5de8\u4eba\u201d\u4f01\u4e1a\u62db\u8058\u8f6f\u6280\u80fd\u9700\u6c42\u9891\u6b21 Top20',
        fontsize=13, pad=12
    )
    # 在条形右侧标注数值
    for i, (val, bar) in enumerate(zip(top20.values, bars)):
        ax.text(val + 5, i, str(val), va="center", fontsize=9)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    plt.tight_layout()
    save_fig(fig_name)
    print(f"fig29 已保存")


def plot_category_heatmap(skill_category_matrix: pd.DataFrame, fig_name: str = "fig30_soft_skills_category_heatmap"):
    """图30：软技能×岗位类别热力图（每千条出现率）。"""
    fig, ax = plt.subplots(figsize=(13, 8))
    sns.heatmap(
        skill_category_matrix,
        cmap="YlOrRd",
        annot=True,
        fmt=".0f",
        linewidths=0.5,
        ax=ax,
        cbar_kws={"label": "每千条出现率"},
    )
    ax.set_title(
        '\u5404\u5c97\u4f4d\u7c7b\u522b\u8f6f\u6280\u80fd\u9700\u6c42\u70ed\u529b\u56fe\uff08\u6bcf\u5343\u6761\u51fa\u73b0\u7387\uff09',
        fontsize=13, pad=12
    )
    ax.set_xlabel("岗位类别", fontsize=11)
    ax.set_ylabel("软技能", fontsize=11)
    plt.xticks(rotation=30, ha="right", fontsize=9)
    plt.yticks(fontsize=9)
    plt.tight_layout()
    save_fig(fig_name)
    print("fig30 已保存")


def plot_skill_trend(skill_year_df: pd.DataFrame, top_skills: list, fig_name: str = "fig31_soft_skills_trend"):
    """图31：4大软技能历年趋势折线图（每千条出现率）。"""
    fig, ax = plt.subplots(figsize=(10, 6))
    colors = ["#0072B2", "#E69F00", "#009E73", "#D55E00"]
    for i, skill in enumerate(top_skills[:4]):
        if skill in skill_year_df.columns:
            ax.plot(
                skill_year_df.index,
                skill_year_df[skill],
                marker="o",
                linewidth=2,
                color=colors[i],
                label=skill,
            )
    ax.set_xlabel("年份", fontsize=11)
    ax.set_ylabel("每千条出现率", fontsize=11)
    ax.set_title(
        '\u4e3b\u8981\u8f6f\u6280\u80fd\u9700\u6c42\u5386\u5e74\u53d8\u5316\u8d8b\u52bf',
        fontsize=13, pad=12
    )
    ax.legend(loc="upper left", fontsize=10)
    ax.xaxis.set_major_locator(mticker.MultipleLocator(1))
    plt.xticks(rotation=30)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    plt.tight_layout()
    save_fig(fig_name)
    print("fig31 已保存")


def main():
    setup_style()
    os.makedirs("data", exist_ok=True)

    # 加载V1分类结果（含category列）
    print("加载V1分类数据...")
    classified = pd.read_csv("scripts/job_classified_data.csv", encoding="utf-8-sig", low_memory=False)
    print(f"  V1分类数据：{len(classified):,}条，类别列：{[c for c in classified.columns if 'cat' in c.lower() or '类别' in c]}")

    # 找到类别列名
    cat_col = "岗位类别" if "岗位类别" in classified.columns else None
    if cat_col is None:
        print("  警告：未找到岗位类别列，将跳过分类分析")

    # 运行提取（断点续传：reset=False）
    print("\n开始软技能提取（如有中断会从断点继续）...")
    result_df = run_extraction(classified, reset=False)

    # 合并回原数据
    classified["jd_id"] = [f"JD_{i:05d}" for i in range(len(classified))]
    merged = classified.merge(result_df, on="jd_id", how="left")

    # 保存中间结果
    OUTPUT_PARQUET.parent.mkdir(exist_ok=True)
    merged[["jd_id", "招聘岗位", "招聘发布年份", cat_col if cat_col else "招聘岗位", "soft_skills"]].to_parquet(
        OUTPUT_PARQUET, index=False
    )
    print(f"\n结果已保存：{OUTPUT_PARQUET}")

    # ===== 分析 =====
    # 展开软技能列表
    records = []
    for _, row in merged.iterrows():
        skills = row.get("soft_skills", [])
        if not isinstance(skills, list):
            continue
        year = row.get("招聘发布年份")
        cat = row.get(cat_col) if cat_col else "未知"
        for sk in skills:
            sk_norm = normalize_skill(str(sk))
            records.append({"year": year, "category": cat, "skill": sk_norm})

    skill_df = pd.DataFrame(records)
    print(f"\n提取到软技能记录：{len(skill_df):,}条，唯一软技能：{skill_df['skill'].nunique()}种")

    # 频率统计
    skill_counts = skill_df["skill"].value_counts()
    print("\nTop20软技能：")
    print(skill_counts.head(20).to_string())

    # --- 图29 ---
    plot_top20_skills(skill_counts)

    # --- 图30：软技能×类别热力图 ---
    if cat_col:
        top15_skills = skill_counts.head(15).index.tolist()
        cat_counts = classified[cat_col].value_counts()
        main_cats = cat_counts[cat_counts > 50].index.tolist()

        matrix_data = {}
        for skill in top15_skills:
            row_data = {}
            for cat in main_cats:
                cat_total = (merged[cat_col] == cat).sum()
                count = ((skill_df["category"] == cat) & (skill_df["skill"] == skill)).sum()
                row_data[cat] = round(count / cat_total * 1000, 1) if cat_total > 0 else 0
            matrix_data[skill] = row_data

        heatmap_df = pd.DataFrame(matrix_data).T
        heatmap_df = heatmap_df[main_cats]
        plot_category_heatmap(heatmap_df)

    # --- 图31：历年趋势 ---
    valid_years = sorted([y for y in skill_df["year"].dropna().unique() if 2016 <= int(y) <= 2024])
    top4_skills = skill_counts.head(4).index.tolist()

    year_totals = merged["招聘发布年份"].value_counts()
    trend_data = {}
    for skill in top4_skills:
        year_counts = skill_df[skill_df["skill"] == skill]["year"].value_counts()
        trend_data[skill] = {
            y: round(year_counts.get(y, 0) / year_totals.get(y, 1) * 1000, 1)
            for y in valid_years
        }

    trend_df = pd.DataFrame(trend_data, index=valid_years)
    plot_skill_trend(trend_df, top4_skills)

    # 成功率报告
    non_empty = merged["soft_skills"].apply(lambda x: isinstance(x, list) and len(x) > 0).sum()
    success_rate = non_empty / len(merged)
    print(f"\n===== 运行摘要 =====")
    print(f"分析样本：{len(merged):,}条")
    print(f"成功提取率：{success_rate:.1%}（{non_empty:,}/{len(merged):,}）")
    print(f"软技能总记录：{len(skill_df):,}条")
    print(f"唯一软技能种类：{skill_df['skill'].nunique()}")
    print(f"输出数据：{OUTPUT_PARQUET}")
    print(f"输出图表：fig29–fig31")
    print("====================")


if __name__ == "__main__":
    main()
