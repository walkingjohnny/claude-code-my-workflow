# ============================================================
# 16_match_index.py
# 用途：V3 研究 — 供给-需求双侧匹配
#       基于 15 输出的供给侧画像 + V2 需求侧画像，计算匹配指数与缺口分析
# 输出：data/v4_match_tool_coverage.parquet     —— 每专业 × 每工具的覆盖矩阵
#       data/v4_match_summary.parquet           —— 每专业的综合匹配指标
#       data/v4_gap_high_demand_low_supply.csv  —— 高需求-低覆盖工具清单
#       data/v4_gap_low_demand_high_supply.csv  —— 低需求-高供给工具清单
#       Figures/journal/v4/fig_v4_b*.png/.pdf    —— 可视化
# 依赖：scripts/_common.py
#       data/v4_supply_majors.parquet（来自 15）
#       data/v2_tech_tools.parquet
#       data/v2_soft_skills.parquet
#       data/v2_digitalization.parquet
#       scripts/job_classified_data.csv
# ============================================================

import os
import sys
import pathlib
import json
from collections import Counter

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import seaborn as sns

sys.path.insert(0, ".")
from scripts._common import setup_style, COLORS, COLOR_PRIMARY, COLOR_SECONDARY, COLOR_NEUTRAL, RANDOM_SEED

np.random.seed(RANDOM_SEED)

# --- 常量 ---
YEAR_RANGE = [2021, 2022, 2023, 2024]
TOP_N_TOOLS = 50  # 需求侧关注的 Top 工具数
TOP_N_SOFT = 10   # 需求侧关注的 Top 软技能数
FIG_DIR = pathlib.Path("Figures/journal/v4")
FIG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR = pathlib.Path("data")

# 供给侧软技能映射（与 15 一致，再保险一次）
SOFT_NORMALIZE = {
    "沟通协调能力": "沟通协调", "沟通能力": "沟通协调", "人际沟通": "沟通协调",
    "团队协作能力": "团队协作", "团队合作": "团队协作",
    "学习能力": "学习能力", "自主学习": "学习能力",
    "责任心": "责任心", "责任感": "责任心",
    "细心": "细心严谨", "严谨": "细心严谨",
}

# ===== 工具同义词典（双侧统一）=====
# 把供需两侧抽到的不同写法归一到同一规范名。键为小写，值为规范名。
TOOL_CANONICAL = {
    # CAD 系列（含国产替代品归为 CAD 大类）
    "cad": "CAD", "autocad": "CAD", "auto cad": "CAD", "auto-cad": "CAD",
    "中望cad": "CAD", "中望 cad": "CAD", "浩辰cad": "CAD",
    # 编程语言
    "c": "C/C++", "c++": "C/C++", "c/c++": "C/C++",
    "c语言": "C/C++", "c 语言": "C/C++", "c语言程序设计": "C/C++",
    "python": "Python", "python3": "Python", "python 3": "Python",
    "python语言": "Python", "python 语言": "Python", "python程序设计": "Python",
    "java": "Java", "javase": "Java", "java se": "Java", "java ee": "Java", "javaee": "Java",
    "java语言": "Java", "java程序设计": "Java",
    "javascript": "JavaScript", "js": "JavaScript", "java script": "JavaScript",
    "typescript": "TypeScript", "ts": "TypeScript",
    "c#": "C#", "csharp": "C#", "c#语言": "C#",
    "go": "Go", "golang": "Go",
    "kotlin": "Kotlin", "swift": "Swift", "rust": "Rust", "scala": "Scala",
    "php": "PHP", "ruby": "Ruby", "perl": "Perl", "shell": "Shell",
    "matlab": "MATLAB",
    "html": "HTML", "html5": "HTML", "html 5": "HTML",
    "css": "CSS", "css3": "CSS",
    "asp": ".NET", ".net": ".NET", "asp.net": ".NET",
    "t-sql": "SQL", "tsql": "SQL", "transact-sql": "SQL", "pl/sql": "SQL",
    # Web 框架
    "vue": "Vue.js", "vue.js": "Vue.js", "vue3": "Vue.js", "vue 3": "Vue.js",
    "react": "React", "react.js": "React", "reactjs": "React",
    "angular": "Angular", "angularjs": "Angular",
    # AI 框架
    "tensorflow": "TensorFlow", "tf": "TensorFlow",
    "pytorch": "PyTorch", "torch": "PyTorch",
    "keras": "Keras", "scikit-learn": "scikit-learn", "sklearn": "scikit-learn",
    # 工程设计
    "solidworks": "SolidWorks", "solid works": "SolidWorks",
    "zw solidworks": "SolidWorks", "zwsolidworks": "SolidWorks",
    "proe": "Pro/E", "pro/e": "Pro/E", "pro-e": "Pro/E", "pro e": "Pro/E", "pro/engineer": "Pro/E",
    "catia": "CATIA",
    "ug": "UG/NX", "nx": "UG/NX", "ug/nx": "UG/NX", "ug nx": "UG/NX",
    "ansys": "ANSYS",
    "altium": "Altium Designer", "altium designer": "Altium Designer",
    "protel": "Altium Designer", "altium designer (protel)": "Altium Designer",
    "creo": "Creo",
    "inventor": "Inventor",
    "rhino": "Rhino",
    "keyshot": "KeyShot",
    "revit": "Revit",
    "bim": "BIM",
    "广联达": "广联达", "斯维尔": "斯维尔",
    "comsol": "COMSOL",
    "zemax": "Zemax", "tracepro": "TracePro",
    "eda": "EDA", "eda软件": "EDA",
    # 嵌入式 / 控制
    "plc": "PLC", "s7-1200": "PLC", "s7-200": "PLC", "西门子plc": "PLC",
    "stm32": "STM32", "esp32": "ESP32", "arduino": "Arduino",
    "arm": "ARM", "fpga": "FPGA", "xilinx": "Xilinx", "altera": "Altera",
    "keil": "Keil", "iar": "IAR",
    "labview": "LabVIEW", "lab view": "LabVIEW",
    "ros": "ROS", "ros（机器人操作系统）": "ROS",
    "single chip": "单片机", "单片机": "单片机", "mcu": "单片机",
    "工业机器人": "工业机器人",
    # 企业系统（金蝶/用友各种变体统一）
    "erp": "ERP", "erp系统": "ERP",
    "金蝶": "金蝶", "金蝶软件": "金蝶", "金蝶云": "金蝶", "金蝶k3": "金蝶",
    "用友": "用友", "u8": "用友", "用友新道": "用友", "用友vbse": "用友", "vbse": "用友",
    "sap": "SAP", "oa": "OA",
    "rpa": "RPA", "rpa财务机器人": "RPA", "rpa财税机器人": "RPA",
    "mes": "MES", "mes系统": "MES",
    # 数据库
    "mysql": "MySQL", "postgresql": "PostgreSQL", "postgres": "PostgreSQL",
    "redis": "Redis", "mongodb": "MongoDB", "oracle": "Oracle",
    "sql": "SQL", "sqlserver": "SQL Server", "sql server": "SQL Server",
    # 大数据 / 云
    "hadoop": "Hadoop", "spark": "Spark", "hive": "Hive",
    "kafka": "Kafka", "flink": "Flink",
    "docker": "Docker", "kubernetes": "Kubernetes", "k8s": "Kubernetes",
    "aws": "AWS", "azure": "Azure", "阿里云": "阿里云", "腾讯云": "腾讯云",
    "华为云": "华为云",
    # 操作系统/工具
    "linux": "Linux", "unix": "Unix", "windows": "Windows",
    "git": "Git", "github": "Git", "gitlab": "Git",
    "android": "Android", "ios": "iOS", "鸿蒙": "HarmonyOS",
    "harmonyos": "HarmonyOS", "openharmony": "HarmonyOS",
    # 设计 / 多媒体（注：避免把"AI"歧义为 Illustrator，剔除"ai"键）
    "photoshop": "Photoshop", "ps": "Photoshop",
    "illustrator": "Illustrator", "adobe illustrator": "Illustrator",
    "premiere": "Premiere", "pr": "Premiere", "adobe premiere": "Premiere",
    "after effects": "After Effects", "ae": "After Effects",
    "3dmax": "3ds Max", "3ds max": "3ds Max", "3dsmax": "3ds Max",
    "maya": "Maya", "blender": "Blender",
    "unity": "Unity", "unity3d": "Unity", "unreal": "Unreal Engine",
    "unreal engine": "Unreal Engine", "ue": "Unreal Engine", "ue4": "Unreal Engine", "ue5": "Unreal Engine",
    "虚幻引擎": "Unreal Engine",
    "coreldraw": "CorelDRAW", "corel draw": "CorelDRAW",
    "indesign": "InDesign", "id": "InDesign",
    "flash": "Flash", "adobe flash": "Flash",
    "visio": "Visio",
    # Office
    "excel": "Excel", "word": "Word", "ppt": "PowerPoint", "powerpoint": "PowerPoint",
    "office": "Office", "ms office": "Office", "microsoft office": "Office",
    "wps": "WPS",
    # 测试 / 运维
    "jenkins": "Jenkins", "jira": "Jira",
    "postman": "Postman", "fiddler": "Fiddler",
    "wireshark": "Wireshark",
    # 工业仪器
    "万用表": "万用表", "示波器": "示波器", "频谱仪": "频谱仪",
    "网络分析仪": "网络分析仪",
}

# ===== 基础办公软件白名单（从缺口分析与匹配指数中排除）=====
# 这些工具在招聘描述中常见但院校培养方案不作为专业课程，
# 视为"通用基础"而非"专业供需缺口"。
BASIC_OFFICE_TOOLS = {
    "Excel", "Word", "PowerPoint", "Office", "WPS",
}


def canonicalize_tool(x: str) -> str:
    """把任意写法的工具名归一到双侧统一规范名。"""
    if not isinstance(x, str):
        return ""
    key = x.strip().lower()
    return TOOL_CANONICAL.get(key, x.strip())


def canonicalize_tools_list(items) -> list:
    """对 list/array 形式的工具列表做规范化 + 去重 + 过滤空值。"""
    if not hasattr(items, "__iter__") or isinstance(items, str):
        return []
    out, seen = [], set()
    for x in items:
        cx = canonicalize_tool(x)
        if cx and cx not in seen:
            seen.add(cx)
            out.append(cx)
    return out


# ============================================================
# 1. 加载数据
# ============================================================
def load_demand_side():
    """加载需求侧 V2 数据并过滤到 2021—2024。"""
    df_tools = pd.read_parquet(DATA_DIR / "v2_tech_tools.parquet")
    df_tools = df_tools[df_tools["招聘发布年份"].isin(YEAR_RANGE)].copy()

    df_soft = pd.read_parquet(DATA_DIR / "v2_soft_skills.parquet")
    df_soft = df_soft[df_soft["招聘发布年份"].isin(YEAR_RANGE)].copy()

    df_digi = pd.read_parquet(DATA_DIR / "v2_digitalization.parquet")
    df_digi = df_digi[df_digi["招聘发布年份"].isin(YEAR_RANGE)].copy()

    return df_tools, df_soft, df_digi


def load_supply_side():
    df = pd.read_parquet(DATA_DIR / "v4_supply_majors.parquet")
    return df


# ============================================================
# 2. 需求侧工具/软技能 Top N 频次表
# ============================================================
def demand_tool_topn(df_tools: pd.DataFrame, n: int = TOP_N_TOOLS, exclude_basic: bool = True) -> pd.Series:
    """需求侧 Top N 工具频次（出现在多少条记录中），归一化后统计。
    exclude_basic=True 时从结果中剔除基础办公软件（Excel/Word/PPT/Office/WPS）。
    """
    counter = Counter()
    for val in df_tools["tools"].dropna():
        items = list(val) if hasattr(val, "__iter__") and not isinstance(val, str) else []
        seen_in_record = set()  # 同一条记录内同一工具只计一次
        for x in items:
            cx = canonicalize_tool(x)
            if not cx:
                continue
            if exclude_basic and cx in BASIC_OFFICE_TOOLS:
                continue
            if cx not in seen_in_record:
                seen_in_record.add(cx)
                counter[cx] += 1
    s = pd.Series(counter).sort_values(ascending=False)
    return s.head(n)


def demand_soft_topn(df_soft: pd.DataFrame, n: int = TOP_N_SOFT) -> pd.Series:
    """需求侧 Top N 软技能频次（已含同义合并）。"""
    counter = Counter()
    for val in df_soft["soft_skills"].dropna():
        items = list(val) if hasattr(val, "__iter__") and not isinstance(val, str) else []
        for x in items:
            if not isinstance(x, str):
                continue
            x = SOFT_NORMALIZE.get(x.strip(), x.strip())
            counter[x] += 1
    s = pd.Series(counter).sort_values(ascending=False)
    return s.head(n)


# ============================================================
# 3. 工具覆盖矩阵：(N 专业) × (Top N 工具)
# ============================================================
def build_tool_coverage(supply: pd.DataFrame, top_tools: pd.Series) -> pd.DataFrame:
    """对每个专业，标记其规范化后的工具集中是否包含 Top N 工具。"""
    rows = []
    for _, r in supply.iterrows():
        major = r["专业名"]
        college = r["学院"]
        level = r["教育层次"]
        raw_tools = r["tools_normalized"] if isinstance(r["tools_normalized"], (list, np.ndarray)) else []
        tools_set = set(canonicalize_tools_list(list(raw_tools)))
        for tool, freq in top_tools.items():
            rows.append({
                "专业名": major,
                "学院": college,
                "教育层次": level,
                "tool": tool,
                "需求频次": int(freq),
                "供给覆盖": int(tool in tools_set),
            })
    cov = pd.DataFrame(rows)
    return cov


# ============================================================
# 4. 每专业的综合匹配指标
# ============================================================
def build_summary(
    supply: pd.DataFrame,
    cov: pd.DataFrame,
    top_tools: pd.Series,
    top_soft: pd.Series,
    df_digi: pd.DataFrame,
) -> pd.DataFrame:
    """生成每专业的综合匹配指标。"""
    demand_digi_mean = df_digi["数字化程度"].mean()
    demand_ai_mean = df_digi["AI相关性"].mean()

    rows = []
    for _, r in supply.iterrows():
        major = r["专业名"]
        college = r["学院"]
        level = r["教育层次"]
        raw_tools = list(r["tools_normalized"]) if isinstance(r["tools_normalized"], (list, np.ndarray)) else []
        tools = canonicalize_tools_list(raw_tools)  # 规范化
        softs = list(r["soft_skills_normalized"]) if isinstance(r["soft_skills_normalized"], (list, np.ndarray)) else []

        tools_set = set(tools)
        softs_set = set(softs)

        # 工具维度：覆盖 Top N 比例
        cov_tool_topn = sum(1 for t in top_tools.index if t in tools_set) / len(top_tools)

        # 工具维度：加权覆盖（按需求频次加权）
        weighted_cov = sum(top_tools[t] for t in top_tools.index if t in tools_set) / top_tools.sum()

        # 软技能维度：覆盖 Top N 比例
        cov_soft_topn = sum(1 for s in top_soft.index if s in softs_set) / len(top_soft)

        # 数字化匹配：供给-需求差（绝对值越小越匹配）
        supply_digi = r.get("数字化程度", np.nan)
        supply_ai = r.get("AI相关性", np.nan)
        digi_gap = (supply_digi - demand_digi_mean) if pd.notna(supply_digi) else np.nan
        ai_gap = (supply_ai - demand_ai_mean) if pd.notna(supply_ai) else np.nan

        # 综合匹配指数（0—100），等权三维度
        match_index = (cov_tool_topn * 0.5 + cov_soft_topn * 0.3 + (1 - min(abs(digi_gap or 0)/50, 1)) * 0.2) * 100 \
            if pd.notna(digi_gap) else (cov_tool_topn * 0.5 + cov_soft_topn * 0.3 + 0) * 100

        rows.append({
            "专业名": major,
            "学院": college,
            "教育层次": level,
            "供给侧工具数": len(tools),
            "供给侧软技能数": len(softs),
            "工具Top50覆盖率": round(cov_tool_topn, 3),
            "工具加权覆盖率": round(weighted_cov, 3),
            "软技能Top10覆盖率": round(cov_soft_topn, 3),
            "供给数字化均值": round(supply_digi, 1) if pd.notna(supply_digi) else None,
            "需求数字化均值": round(demand_digi_mean, 1),
            "数字化差值": round(digi_gap, 1) if pd.notna(digi_gap) else None,
            "供给AI相关性均值": round(supply_ai, 1) if pd.notna(supply_ai) else None,
            "需求AI相关性均值": round(demand_ai_mean, 1),
            "AI相关性差值": round(ai_gap, 1) if pd.notna(ai_gap) else None,
            "综合匹配指数": round(match_index, 1),
        })
    return pd.DataFrame(rows).sort_values("综合匹配指数", ascending=False).reset_index(drop=True)


# ============================================================
# 5. 缺口分析
# ============================================================
def analyze_gaps(cov: pd.DataFrame, supply: pd.DataFrame, top_tools: pd.Series):
    """识别高需求-低覆盖与低需求-高覆盖工具。"""
    n_majors = supply["专业名"].nunique()

    # 每个工具被多少专业覆盖
    tool_supply_count = cov.groupby("tool")["供给覆盖"].sum().to_dict()

    # 高需求-低覆盖：Top20 需求工具中，被覆盖专业数 < n_majors * 0.1（即不到 10% 专业有教学）
    high_demand_low_supply = []
    for tool, freq in top_tools.head(20).items():
        n_cov = tool_supply_count.get(tool, 0)
        rate = n_cov / n_majors
        if rate < 0.10:
            high_demand_low_supply.append({
                "tool": tool,
                "需求频次": int(freq),
                "覆盖专业数": int(n_cov),
                "覆盖率": round(rate, 3),
            })

    # 低需求-高覆盖：被 >30% 专业覆盖、但需求频次 < Top50 中位数
    median_demand = top_tools.median()
    all_supply_tools = Counter()
    for tools in supply["tools_normalized"]:
        if isinstance(tools, (list, np.ndarray)):
            cans = canonicalize_tools_list(list(tools))
            for t in cans:
                all_supply_tools[t] += 1
    low_demand_high_supply = []
    for tool, n_cov in all_supply_tools.items():
        if n_cov / n_majors >= 0.30:
            demand_freq = top_tools.get(tool, 0)
            if demand_freq < median_demand:
                low_demand_high_supply.append({
                    "tool": tool,
                    "覆盖专业数": int(n_cov),
                    "覆盖率": round(n_cov / n_majors, 3),
                    "需求频次": int(demand_freq),
                })
    low_demand_high_supply.sort(key=lambda x: x["覆盖专业数"], reverse=True)

    return (
        pd.DataFrame(high_demand_low_supply).sort_values("需求频次", ascending=False),
        pd.DataFrame(low_demand_high_supply).head(20),
    )


# ============================================================
# 6. 可视化
# ============================================================
def fig_match_index_bar(summary: pd.DataFrame):
    fig, ax = plt.subplots(figsize=(10, 13))
    s = summary.sort_values("综合匹配指数", ascending=True)
    colors_by_level = ["#0072B2" if x == "职业本科" else "#E69F00" for x in s["教育层次"]]
    ax.barh(range(len(s)), s["综合匹配指数"], color=colors_by_level, edgecolor="white", height=0.7)
    ax.set_yticks(range(len(s)))
    ax.set_yticklabels(s["专业名"], fontsize=8)
    for i, v in enumerate(s["综合匹配指数"]):
        ax.text(v + 0.5, i, f"{v:.1f}", va="center", fontsize=7)
    ax.set_xlabel("综合匹配指数（0—100）")
    ax.set_title("供给-需求综合匹配指数（每专业）", fontsize=12, pad=10)
    legend_handles = [
        plt.Rectangle((0, 0), 1, 1, color="#0072B2", label="职业本科"),
        plt.Rectangle((0, 0), 1, 1, color="#E69F00", label="高职专科"),
    ]
    ax.legend(handles=legend_handles, loc="lower right", fontsize=9)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "fig_v4_b01_match_index_bar.png", dpi=300, bbox_inches="tight")
    plt.savefig(FIG_DIR / "fig_v4_b01_match_index_bar.pdf", bbox_inches="tight")
    plt.close()
    print("  ✓ fig_v4_b01_match_index_bar")


def fig_tool_coverage_heatmap(cov: pd.DataFrame, top_tools: pd.Series, top_n_show: int = 25):
    """热力图：top N 工具 × 部分专业（按学院聚合可读性）"""
    pivot = cov.pivot(index="专业名", columns="tool", values="供给覆盖").fillna(0)
    pivot = pivot[top_tools.head(top_n_show).index]
    pivot = pivot.loc[pivot.sum(axis=1).sort_values(ascending=False).index]

    fig, ax = plt.subplots(figsize=(12, 13))
    sns.heatmap(pivot, cmap="Blues", cbar_kws={"label": "供给覆盖（0/1）"},
                linewidths=0.3, linecolor="white", ax=ax)
    ax.set_title(f"Top{top_n_show} 需求工具 × 各专业课程覆盖热力图", fontsize=12, pad=10)
    ax.set_xlabel("")
    ax.set_ylabel("")
    plt.xticks(rotation=45, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "fig_v4_b02_tool_coverage_heatmap.png", dpi=300, bbox_inches="tight")
    plt.savefig(FIG_DIR / "fig_v4_b02_tool_coverage_heatmap.pdf", bbox_inches="tight")
    plt.close()
    print("  ✓ fig_v4_b02_tool_coverage_heatmap")


def fig_demand_supply_quadrant(top_tools: pd.Series, supply_counts: dict, n_majors: int):
    """象限图：横轴=需求频次（log），纵轴=供给覆盖率"""
    rows = []
    for tool, freq in top_tools.items():
        n_cov = supply_counts.get(tool, 0)
        rows.append({"tool": tool, "需求频次": freq, "覆盖率": n_cov / n_majors})
    df = pd.DataFrame(rows)

    fig, ax = plt.subplots(figsize=(10, 7))
    ax.scatter(df["需求频次"], df["覆盖率"], s=80, alpha=0.7, color=COLORS[0], edgecolor="white")
    for _, r in df.iterrows():
        if r["需求频次"] >= top_tools.quantile(0.7) or r["覆盖率"] >= 0.5:
            ax.annotate(r["tool"], (r["需求频次"], r["覆盖率"]), fontsize=8,
                        xytext=(5, 3), textcoords="offset points")
    ax.set_xscale("log")
    ax.axhline(y=0.5, color="gray", linestyle="--", alpha=0.5, linewidth=1)
    ax.axvline(x=top_tools.median(), color="gray", linestyle="--", alpha=0.5, linewidth=1)
    ax.set_xlabel("需求频次（招聘记录数，log 轴）")
    ax.set_ylabel("供给覆盖率（覆盖专业 / 全部专业）")
    ax.set_title("Top50 工具的需求-供给象限分布", fontsize=12, pad=10)
    plt.tight_layout()
    plt.savefig(FIG_DIR / "fig_v4_b03_demand_supply_quadrant.png", dpi=300, bbox_inches="tight")
    plt.savefig(FIG_DIR / "fig_v4_b03_demand_supply_quadrant.pdf", bbox_inches="tight")
    plt.close()
    print("  ✓ fig_v4_b03_demand_supply_quadrant")


# ============================================================
# 6.5 V4 新增：超前度分布与适度超前窗口
# ============================================================
# 教育部"适度超前"原则的可量化定义（基于本研究证据的工作定义）：
#   超前度 = 供给侧 LLM 评分 − 需求侧 2024 年（最新一年）评分均值
#   分级：滞后 [-∞,0)；同步 [0,15)；适度超前 [15,35]；显著超前 (35,+∞)
LEAD_BANDS = [
    ("滞后", -200, 0),
    ("同步", 0, 15),
    ("适度超前", 15, 35),
    ("显著超前", 35, 200),
]


def compute_lead_distribution(supply: pd.DataFrame, demand_2024_means: dict) -> pd.DataFrame:
    rows = []
    for _, r in supply.iterrows():
        for dim in ["数字化程度", "AI相关性", "技术复杂度"]:
            sup = r.get(dim)
            dem = demand_2024_means.get(dim)
            if pd.isna(sup) or dem is None:
                continue
            lead = sup - dem
            band = next((b[0] for b in LEAD_BANDS if b[1] <= lead < b[2]), "其他")
            rows.append({
                "专业名": r["专业名"],
                "学院": r["学院"],
                "教育层次": r["教育层次"],
                "维度": dim,
                "供给评分": round(sup, 1),
                "2024需求均值": round(dem, 2),
                "超前度": round(lead, 1),
                "分级": band,
            })
    return pd.DataFrame(rows)


def fig_lead_distribution(lead_df: pd.DataFrame):
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.8))
    dims = ["数字化程度", "AI相关性", "技术复杂度"]
    band_colors = {"滞后": "#999", "同步": "#5fa8d3", "适度超前": "#62b56a", "显著超前": "#e07a5f"}
    for ax, dim in zip(axes, dims):
        sub = lead_df[lead_df["维度"] == dim]
        for band, color in band_colors.items():
            v = sub[sub["分级"] == band]["超前度"]
            if len(v) > 0:
                ax.hist(v, bins=15, color=color, alpha=0.85,
                        label=f"{band} ({len(v)})", edgecolor="white")
        ax.axvline(x=0, color="#222", linestyle="--", lw=1, alpha=0.6)
        ax.axvline(x=15, color="#62b56a", linestyle=":", lw=1.5, alpha=0.8)
        ax.axvline(x=35, color="#e07a5f", linestyle=":", lw=1.5, alpha=0.8)
        ax.set_xlabel(f"{dim} 超前度（供给 − 2024需求）")
        ax.set_ylabel("专业数")
        ax.set_title(f"{dim}", fontsize=11)
        ax.legend(fontsize=8, loc="upper right")
    plt.tight_layout()
    plt.savefig(FIG_DIR / "fig_v4_b04_lead_distribution.png", dpi=300, bbox_inches="tight")
    plt.savefig(FIG_DIR / "fig_v4_b04_lead_distribution.pdf", bbox_inches="tight")
    plt.close()
    print("  ✓ fig_v4_b04_lead_distribution")


def m4_demand_ai_trend_check(annual_path: pathlib.Path) -> dict:
    annual = pd.read_parquet(annual_path)
    ai = annual["AI相关性_均值"].tolist()
    yrs = annual["year"].tolist()
    delta = ai[-1] - ai[0]
    is_monotonic_up = all(ai[i+1] >= ai[i] for i in range(len(ai)-1))
    return {
        "yearly": dict(zip(yrs, ai)),
        "2024_minus_2021": round(delta, 2),
        "is_monotonic_up": is_monotonic_up,
        "verdict": "AI 需求未呈单调上升" if not is_monotonic_up else "单调上升",
    }


# ============================================================
# 7. 主流程
# ============================================================
def main():
    setup_style()

    print("=" * 60)
    print("V3 双侧匹配分析")
    print("=" * 60)

    print("\n[1/5] 加载数据 …")
    df_tools, df_soft, df_digi = load_demand_side()
    supply = load_supply_side()
    print(f"  需求侧：tools {len(df_tools):,}，soft {len(df_soft):,}，digi {len(df_digi):,}")
    print(f"  供给侧：{len(supply)} 个专业")

    print("\n[2/5] 需求侧 Top N 频次表 …")
    top_tools = demand_tool_topn(df_tools, TOP_N_TOOLS)
    top_soft = demand_soft_topn(df_soft, TOP_N_SOFT)
    print(f"  Top {TOP_N_TOOLS} 工具：{', '.join(top_tools.head(10).index.tolist())} …")
    print(f"  Top {TOP_N_SOFT} 软技能：{', '.join(top_soft.head(5).index.tolist())} …")

    print("\n[3/5] 构建工具覆盖矩阵 …")
    cov = build_tool_coverage(supply, top_tools)
    cov.to_parquet(DATA_DIR / "v4_match_tool_coverage.parquet", index=False)
    print(f"  → {DATA_DIR / 'v4_match_tool_coverage.parquet'}（{len(cov):,} 行）")

    print("\n[4/5] 计算每专业综合匹配指标 …")
    summary = build_summary(supply, cov, top_tools, top_soft, df_digi)
    summary.to_parquet(DATA_DIR / "v4_match_summary.parquet", index=False)
    summary.to_csv(DATA_DIR / "v4_match_summary.csv", index=False, encoding="utf-8-sig")
    print(f"  → {DATA_DIR / 'v4_match_summary.parquet'}")
    print("\n  匹配指数 Top10：")
    print(summary[["专业名", "学院", "教育层次", "工具Top50覆盖率", "软技能Top10覆盖率", "综合匹配指数"]].head(10).to_string(index=False))

    print("\n[5/5] 缺口分析 …")
    high_low, low_high = analyze_gaps(cov, supply, top_tools)
    high_low.to_csv(DATA_DIR / "v4_gap_high_demand_low_supply.csv", index=False, encoding="utf-8-sig")
    low_high.to_csv(DATA_DIR / "v4_gap_low_demand_high_supply.csv", index=False, encoding="utf-8-sig")
    print(f"  高需求-低覆盖工具：{len(high_low)} 项")
    if len(high_low):
        print(high_low.head(10).to_string(index=False))

    print("\n[图] 生成可视化 …")
    fig_match_index_bar(summary)
    fig_tool_coverage_heatmap(cov, top_tools)
    n_majors = supply["专业名"].nunique()
    supply_counts = cov.groupby("tool")["供给覆盖"].sum().to_dict()
    fig_demand_supply_quadrant(top_tools, supply_counts, n_majors)

    print("\n[V4 新增] 超前度分布 + M4/M5 …")
    annual = pd.read_parquet(DATA_DIR / "v4_demand_annual.parquet")
    last_year = annual.iloc[-1]
    demand_2024_means = {
        "数字化程度": float(last_year["数字化程度_均值"]),
        "AI相关性": float(last_year["AI相关性_均值"]),
        "技术复杂度": float(last_year["技术复杂度_均值"]),
    }
    print(f"  2024 需求均值：{demand_2024_means}")

    lead_df = compute_lead_distribution(supply, demand_2024_means)
    lead_df.to_parquet(DATA_DIR / "v4_lead_distribution.parquet", index=False)
    lead_df.to_csv(DATA_DIR / "v4_lead_distribution.csv", index=False, encoding="utf-8-sig")

    print("\n  各维度的分级分布：")
    dist = lead_df.groupby(["维度", "分级"]).size().unstack(fill_value=0)
    print(dist.to_string())

    fig_lead_distribution(lead_df)

    # M4: AI 需求逐年趋势
    m4 = m4_demand_ai_trend_check(DATA_DIR / "v4_demand_annual.parquet")
    print(f"\n  M4 检验：AI 相关性 {m4['yearly']}，2024−2021={m4['2024_minus_2021']}，{m4['verdict']}")

    print("\n=== 完成 ===")


if __name__ == "__main__":
    main()
