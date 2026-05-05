# Python 代码规范

本项目的所有 Python 数据分析脚本遵循以下规范，以确保可复现性、一致性和发表级输出质量。

---

## 1. 脚本结构（固定顺序）

每个分析脚本必须按以下顺序组织：

```python
# ============================================================
# [脚本名称].py
# 用途：[一句话说明该脚本的分析目标]
# 输出：Figures/[图表文件名].png / .pdf
# ============================================================

# --- 1. 导入库 ---
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
# ...其他库

# --- 2. 全局常量 ---
RANDOM_SEED = 42
DATA_PATH = "源数据/合并画像后_智联招聘数据库2016-2025.7.csv"
FIGURES_DIR = "Figures/"

# --- 3. 中文字体配置 ---
# （见第 3 节）

# --- 4. 数据加载 ---
# （见第 4 节）

# --- 5. 数据过滤（必须显式声明）---
# （见第 5 节）

# --- 6. 分析逻辑 ---

# --- 7. 可视化 ---
# （见第 6 节）

# --- 8. 输出保存 ---
# （见第 6 节）
```

---

## 2. 随机种子

所有涉及随机性的操作（采样、聚类、分词等）统一使用：

```python
RANDOM_SEED = 42
```

调用方式：
```python
import numpy as np
np.random.seed(RANDOM_SEED)

# sklearn 等库
model = KMeans(n_clusters=5, random_state=RANDOM_SEED)
```

---

## 3. 中文字体配置

每个生成图表的脚本必须在导入库后立即配置中文字体：

```python
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import warnings

# 配置中文字体（按优先级尝试）
def set_chinese_font():
    preferred_fonts = [
        'Source Han Sans CN',   # 思源黑体（推荐）
        'Noto Sans CJK SC',     # Google Noto
        'PingFang SC',          # macOS 系统字体
        'SimHei',               # Windows 黑体
        'Microsoft YaHei',      # 微软雅黑
    ]
    available = {f.name for f in fm.fontManager.ttflist}
    for font in preferred_fonts:
        if font in available:
            plt.rcParams['font.sans-serif'] = [font]
            plt.rcParams['axes.unicode_minus'] = False
            return font
    warnings.warn("未找到中文字体，图表可能显示乱码。请安装思源黑体。")
    return None

FONT_USED = set_chinese_font()
```

**安装思源黑体（macOS）：**
```bash
brew install font-source-han-sans
```

---

## 4. 数据加载

```python
# 大文件加载提示
print("正在加载数据，请稍候...")
df = pd.read_csv(
    DATA_PATH,
    encoding='utf-8-sig',   # 处理 BOM 头，避免列名乱码
    low_memory=False,        # 避免混合类型推断警告
)
print(f"原始数据：{len(df):,} 行，{len(df.columns)} 列")
```

---

## 5. 数据过滤（每个脚本必须包含，不得省略）

```python
# ===== 必须应用的数据过滤条件 =====
# 过滤前记录数量
n_before = len(df)

# 条件 1：仅保留深圳企业
df = df[df['目前所属城市'] == '深圳市']

# 条件 2：排除信息不完整记录
df = df[df['复核结果'] != '未见信息']

# 报告过滤结果
n_after = len(df)
print(f"过滤后：{n_after:,} 行（移除 {n_before - n_after:,} 行，保留率 {n_after/n_before:.1%}）")
# ====================================
```

**违反此规范视为代码质量不合格（低于 80 分）。**

---

## 6. 图表输出规范

### 图表设置

```python
# 学术图表全局设置
plt.rcParams.update({
    'figure.dpi': 150,          # 屏幕预览
    'savefig.dpi': 300,         # 保存输出
    'figure.figsize': (10, 6),  # 默认尺寸（可按需调整）
    'axes.spines.top': False,   # 去掉上边框（更简洁）
    'axes.spines.right': False, # 去掉右边框
})
```

### 配色规范

使用对色盲友好的调色板（避免纯红 + 纯绿并列）：

```python
# 推荐调色板（来自 seaborn colorblind / IBM Design）
COLORS = {
    'primary':   '#0072B2',  # 深蓝
    'secondary': '#E69F00',  # 橙色
    'tertiary':  '#009E73',  # 绿色
    'neutral':   '#999999',  # 灰色
    'accent':    '#CC79A7',  # 紫色
}

# seaborn 一行设置
import seaborn as sns
sns.set_palette('colorblind')
```

### 保存规范

```python
import os
os.makedirs(FIGURES_DIR, exist_ok=True)

# 同时保存 PNG（报告用）和 PDF（论文用）
fig_name = "figure_name"  # 下划线命名，无空格
plt.savefig(f"{FIGURES_DIR}{fig_name}.png", dpi=300, bbox_inches='tight')
plt.savefig(f"{FIGURES_DIR}{fig_name}.pdf", bbox_inches='tight')
plt.close()  # 释放内存
print(f"图表已保存：{FIGURES_DIR}{fig_name}.png / .pdf")
```

---

## 7. 命名规范

| 对象 | 规范 | 示例 |
|------|------|------|
| 脚本文件 | `snake_case.py` | `eda_recruitment_trend.py` |
| 图表文件 | `snake_case` | `fig_annual_job_count.png` |
| 变量名 | `snake_case` | `df_filtered`, `annual_counts` |
| 常量 | `UPPER_SNAKE` | `RANDOM_SEED`, `DATA_PATH` |
| 函数 | `snake_case` + 动词开头 | `compute_hhi()`, `plot_trend()` |

---

## 8. 注释规范

- 每个函数写一行中文说明
- 复杂计算步骤写行内注释
- 数据过滤条件必须注释说明原因（见第 5 节示例）
- 图表标题/轴标签直接写中文

---

## 9. 输出可复现性检查

每个脚本运行结束时打印摘要：

```python
print("\n===== 运行摘要 =====")
print(f"数据文件：{DATA_PATH}")
print(f"分析样本：{n_after:,} 条记录")
print(f"输出图表：{FIGURES_DIR}")
print(f"随机种子：{RANDOM_SEED}")
print("====================")
```
