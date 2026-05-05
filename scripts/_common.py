# ============================================================
# _common.py
# 用途：所有 EDA 脚本共用的常量、字体配置和工具函数
# ============================================================

import os
import warnings
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm

# --- 全局常量 ---
RANDOM_SEED = 42
DATA_PATH = "源数据/合并画像后_智联招聘数据库2016-2025.7.csv"
FIGURES_DIR = "Figures/"

# 必须应用的数据过滤条件（每个脚本调用 load_filtered_data() 自动应用）
FILTER_CITY = "深圳市"
FILTER_FUHEJIEGUO_EXCLUDE = "未见信息"

# 色盲友好调色板（ColorBlind-safe，仿 seaborn colorblind）
COLORS = [
    "#0072B2",  # 深蓝
    "#E69F00",  # 橙色
    "#009E73",  # 绿色
    "#D55E00",  # 红橙
    "#CC79A7",  # 紫色
    "#56B4E9",  # 浅蓝
    "#F0E442",  # 黄色
    "#999999",  # 灰色
]
COLOR_PRIMARY = COLORS[0]
COLOR_SECONDARY = COLORS[1]
COLOR_NEUTRAL = COLORS[7]


# --- 中文字体配置 ---
def set_chinese_font():
    """配置 matplotlib 中文字体，按优先级尝试可用字体。"""
    preferred = [
        "Source Han Sans CN",
        "STHeiti",
        "Heiti TC",
        "PingFang SC",
        "PingFang HK",
        "Kaiti SC",
        "Arial Unicode MS",
    ]
    available = {f.name for f in fm.fontManager.ttflist}
    for font in preferred:
        if font in available:
            plt.rcParams["font.sans-serif"] = [font, "DejaVu Sans"]
            plt.rcParams["axes.unicode_minus"] = False
            return font
    warnings.warn("未找到合适的中文字体，图表可能显示乱码。")
    return None


# --- 全局图表样式 ---
def setup_style():
    """设置全局图表样式。"""
    font_used = set_chinese_font()
    plt.rcParams.update(
        {
            "figure.dpi": 150,
            "savefig.dpi": 300,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.titlesize": 14,
            "axes.labelsize": 12,
            "xtick.labelsize": 10,
            "ytick.labelsize": 10,
            "legend.fontsize": 10,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
        }
    )
    return font_used


# --- 数据加载与过滤 ---
def load_filtered_data():
    """
    加载源数据并应用必须的过滤条件。
    返回：pandas DataFrame，已过滤，附带过滤统计信息。
    """
    import pandas as pd

    print(f"正在加载数据：{DATA_PATH} ...")
    df = pd.read_csv(DATA_PATH, encoding="utf-8-sig", low_memory=False)
    n_raw = len(df)
    print(f"  原始行数：{n_raw:,}")

    # ===== 必须应用的数据过滤条件 =====
    df = df[df["目前所属城市"] == FILTER_CITY]  # 仅保留深圳企业
    n_city = len(df)

    df = df[df["复核结果"] != FILTER_FUHEJIEGUO_EXCLUDE]  # 排除信息不完整记录
    n_final = len(df)
    # ====================================

    print(f"  过滤后（目前所属城市=深圳市）：{n_city:,}")
    print(f"  过滤后（复核结果≠未见信息）：{n_final:,}")
    print(f"  最终分析样本：{n_final:,} 条（保留率 {n_final/n_raw:.1%}）")

    return df, {"raw": n_raw, "after_city": n_city, "final": n_final}


# --- 图表保存工具 ---
def save_fig(fig_name: str, fig=None):
    """同时保存 PNG 和 PDF 到 Figures/ 目录。"""
    os.makedirs(FIGURES_DIR, exist_ok=True)
    png_path = f"{FIGURES_DIR}{fig_name}.png"
    pdf_path = f"{FIGURES_DIR}{fig_name}.pdf"
    if fig is None:
        plt.savefig(png_path, dpi=300, bbox_inches="tight")
        plt.savefig(pdf_path, bbox_inches="tight")
    else:
        fig.savefig(png_path, dpi=300, bbox_inches="tight")
        fig.savefig(pdf_path, bbox_inches="tight")
    plt.close()
    print(f"  已保存：{png_path} / {pdf_path}")
