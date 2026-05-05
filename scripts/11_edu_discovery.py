# ============================================================
# 11_edu_discovery.py
# 用途：V2研究 - 发现本科 vs 大专岗位在职位描述上的系统性文本差异
#       各岗位类别分别抽样对比，输出可解释的差异摘要
# 输出：data/v2_edu_comparison.json
#       Figures/fig35_edu_diff_bars.png/.pdf
#       Figures/fig36_edu_diff_matrix.png/.pdf
# 依赖：scripts/llm_client.py, scripts/_common.py
#       scripts/job_classified_data.csv
# ============================================================

import os
import sys
import json
import pathlib
import textwrap

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

sys.path.insert(0, ".")
from scripts._common import setup_style, save_fig, RANDOM_SEED, COLORS
from scripts.llm_client import _get_client, _call_llm, _parse_json_from_response

np.random.seed(RANDOM_SEED)

OUTPUT_JSON = pathlib.Path("data/v2_edu_comparison.json")
CHECKPOINT_DIR = pathlib.Path("data/v2_checkpoints")
SAMPLE_PER_GROUP = 60   # 每组（本科/大专）每类别最多取多少条
MODEL = "MiniMax-M2.7-highspeed"

# 本科-only：学历要求=本科
# 大专-friendly：学历要求=大专 或 大专及以上
EDU_BACHELOR = ["本科"]
EDU_ASSOCIATE = ["大专", "大专及以上", "专科"]

SYSTEM_PROMPT = (
    "你是专业的招聘数据分析师。"
    "请分析两组招聘职位描述的系统性差异，输出结构化JSON，不要其他内容。"
)

DISCOVERY_PROMPT_TEMPLATE = """
以下是来自"{category}"岗位类别的两组职位描述：

===== 本科组（{n_bachelor}条） =====
{bachelor_texts}

===== 大专组（{n_associate}条） =====
{associate_texts}

请分析两组之间的系统性差异，找出"本科组"相比"大专组"：
1. 更多要求的能力/技能（写具体词汇，如"独立研发能力"）
2. 更多出现的职责描述（如"负责技术方案设计"）
3. 更多提到的工作复杂度特征（如"跨部门协调"、"项目管理"）

输出格式（JSON）：
{{
  "category": "{category}",
  "bachelor_more": {{
    "skills": ["具体能力1", "具体能力2", ...],
    "responsibilities": ["职责1", "职责2", ...],
    "complexity_signals": ["特征1", "特征2", ...]
  }},
  "associate_more": {{
    "skills": ["具体能力1", ...],
    "responsibilities": ["职责1", ...],
    "complexity_signals": ["特征1", ...]
  }},
  "key_insight": "一句话总结本科与大专岗位的核心区别"
}}
"""


def get_sample_texts(df: pd.DataFrame, n: int = SAMPLE_PER_GROUP) -> str:
    """随机抽取n条，拼接成文本块。"""
    sample = df.sample(min(n, len(df)), random_state=RANDOM_SEED)
    return "\n---\n".join(
        [f"[{i+1}] {str(row['职位描述'])[:300]}" for i, (_, row) in enumerate(sample.iterrows())]
    )


def run_discovery(classified: pd.DataFrame, cat_col: str) -> list[dict]:
    """对每个岗位类别运行本科vs大专发现分析。"""
    client = _get_client()
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

    results = []
    main_cats = classified[cat_col].value_counts()
    main_cats = main_cats[main_cats > 50].index.tolist()

    for cat in main_cats:
        ckpt = CHECKPOINT_DIR / f"edu_discovery_{cat}.json"
        if ckpt.exists():
            with open(ckpt, "r", encoding="utf-8") as f:
                results.append(json.load(f))
            print(f"  [{cat}] 从检查点加载")
            continue

        cat_df = classified[classified[cat_col] == cat].dropna(subset=["职位描述", "学历要求"])
        bachelor_df = cat_df[cat_df["学历要求"].isin(EDU_BACHELOR)]
        associate_df = cat_df[cat_df["学历要求"].isin(EDU_ASSOCIATE)]

        if len(bachelor_df) < 10 or len(associate_df) < 10:
            print(f"  [{cat}] 跳过（本科{len(bachelor_df)}条，大专{len(associate_df)}条，样本不足）")
            continue

        print(f"  [{cat}] 分析（本科{len(bachelor_df)}条，大专{len(associate_df)}条）...")

        bachelor_texts = get_sample_texts(bachelor_df)
        associate_texts = get_sample_texts(associate_df)

        prompt = DISCOVERY_PROMPT_TEMPLATE.format(
            category=cat,
            n_bachelor=min(SAMPLE_PER_GROUP, len(bachelor_df)),
            n_associate=min(SAMPLE_PER_GROUP, len(associate_df)),
            bachelor_texts=bachelor_texts,
            associate_texts=associate_texts,
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]

        try:
            raw = _call_llm(client, messages, MODEL)
            parsed = _parse_json_from_response(raw)
            if isinstance(parsed, dict):
                # 保存检查点
                with open(ckpt, "w", encoding="utf-8") as f:
                    json.dump(parsed, f, ensure_ascii=False, indent=2)
                results.append(parsed)
                print(f"    关键洞察：{parsed.get('key_insight', 'N/A')}")
            else:
                print(f"    [{cat}] 格式异常，跳过")
        except Exception as e:
            print(f"    [{cat}] 出错：{e}")

    return results


def plot_edu_diff_bars(results: list[dict], fig_name: str = "fig35_edu_diff_bars"):
    """图35：各类别本科 vs 大专差异条形图（技能维度）。"""
    n_cats = len(results)
    if n_cats == 0:
        print("没有足够数据绘制fig35")
        return

    cols = 2
    rows = (n_cats + 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(14, rows * 3.5))
    axes = axes.flatten() if n_cats > 1 else [axes]

    for i, (result, ax) in enumerate(zip(results, axes)):
        cat = result.get("category", "未知")
        bachelor_skills = result.get("bachelor_more", {}).get("skills", [])[:6]
        associate_skills = result.get("associate_more", {}).get("skills", [])[:4]

        all_items = [(s, "本科优势") for s in bachelor_skills] + [(s, "大专优势") for s in associate_skills]
        if not all_items:
            ax.text(0.5, 0.5, "数据不足", ha="center", va="center", transform=ax.transAxes)
            ax.set_title(cat, fontsize=10)
            continue

        labels = [item[0] for item in all_items]
        # 截断长标签
        labels = [l[:10] + "…" if len(l) > 10 else l for l in labels]
        colors_bar = [COLORS[0] if item[1] == "本科优势" else COLORS[1] for item in all_items]
        values = [1] * len(all_items)

        ax.barh(range(len(all_items)), values, color=colors_bar, alpha=0.8)
        ax.set_yticks(range(len(all_items)))
        ax.set_yticklabels(labels, fontsize=8)
        ax.invert_yaxis()
        ax.set_xlim(0, 1.5)
        ax.set_xticks([])
        ax.set_title(cat, fontsize=10, fontweight="bold")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["bottom"].set_visible(False)

    # 隐藏多余子图
    for j in range(i + 1, len(axes)):
        axes[j].set_visible(False)

    legend_patches = [
        mpatches.Patch(color=COLORS[0], alpha=0.8, label="本科岗位更多要求"),
        mpatches.Patch(color=COLORS[1], alpha=0.8, label="大专岗位更多要求"),
    ]
    fig.legend(handles=legend_patches, loc="lower center", ncol=2, fontsize=10, bbox_to_anchor=(0.5, 0))
    fig.suptitle(
        '\u5404\u5c97\u4f4d\u7c7b\u522b\u672c\u79d1\u4e0e\u5927\u4e13\u804c\u4f4d\u63cf\u8ff0\u5dee\u5f02\uff08\u8fd0\u8425\u3001\u80fd\u529b\u7ef4\u5ea6\uff09',
        fontsize=13, y=1.01
    )
    plt.tight_layout(rect=[0, 0.05, 1, 1])
    save_fig(fig_name)
    print("fig35 已保存")


def plot_edu_diff_matrix(results: list[dict], fig_name: str = "fig36_edu_diff_matrix"):
    """图36：差异总结矩阵热力图（本科差异维度×类别）。"""
    if not results:
        print("没有足够数据绘制fig36")
        return

    dim_labels = ["技能要求差异", "职责差异", "复杂度差异"]
    cats = [r.get("category", "未知") for r in results]

    # 每个维度计分：本科组有多少项比大专多（量化差异程度）
    matrix = np.zeros((len(dim_labels), len(cats)))
    for j, result in enumerate(results):
        bachelor_more = result.get("bachelor_more", {})
        matrix[0, j] = len(bachelor_more.get("skills", []))
        matrix[1, j] = len(bachelor_more.get("responsibilities", []))
        matrix[2, j] = len(bachelor_more.get("complexity_signals", []))

    df_matrix = pd.DataFrame(matrix, index=dim_labels, columns=cats)

    fig, ax = plt.subplots(figsize=(max(10, len(cats) * 1.2), 5))
    sns.heatmap(
        df_matrix,
        cmap="Oranges",
        annot=True,
        fmt=".0f",
        linewidths=0.5,
        ax=ax,
        cbar_kws={"label": "本科组额外要求项目数"},
    )
    ax.set_title(
        '\u672c\u79d1\u5c97\u4f4d\u76f8\u6bd4\u5927\u4e13\u5c97\u4f4d\u7684\u989d\u5916\u8981\u6c42\u7ef4\u5ea6\uff08\u5404\u7c7b\u522b\uff09',
        fontsize=13, pad=12
    )
    ax.set_ylabel("差异维度", fontsize=11)
    ax.set_xlabel("岗位类别", fontsize=11)
    plt.xticks(rotation=30, ha="right", fontsize=9)
    plt.tight_layout()
    save_fig(fig_name)
    print("fig36 已保存")


def main():
    setup_style()
    os.makedirs("data", exist_ok=True)

    print("加载V1分类数据...")
    classified = pd.read_csv("scripts/job_classified_data.csv", encoding="utf-8-sig", low_memory=False)

    cat_col = "岗位类别" if "岗位类别" in classified.columns else None

    if cat_col is None:
        print("错误：未找到类别列，无法运行分析")
        return

    print(f"类别列：{cat_col}，共{classified[cat_col].nunique()}类")
    print(f"学历字段分布：\n{classified['学历要求'].value_counts().head(10)}")

    print("\n开始本科vs大专差异分析（断点续传）...")
    results = run_discovery(classified, cat_col)

    OUTPUT_JSON.parent.mkdir(exist_ok=True)
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n结果已保存：{OUTPUT_JSON}")

    # 打印摘要
    print("\n===== 各类别关键洞察 =====")
    for r in results:
        print(f"\n[{r.get('category', '?')}]")
        print(f"  {r.get('key_insight', '无')}")

    # --- 图35、36 ---
    plot_edu_diff_bars(results)
    plot_edu_diff_matrix(results)

    print(f"\n===== 运行摘要 =====")
    print(f"分析岗位类别：{len(results)}个")
    print(f"输出数据：{OUTPUT_JSON}")
    print(f"输出图表：fig35–fig36")
    print("====================")


if __name__ == "__main__":
    main()
