# CLAUDE.MD — 深圳市专精特新"小巨人"企业招聘岗位变迁研究

**项目：** 深圳市专精特新"小巨人"企业招聘岗位变迁研究
**机构：** 深圳信息职业技术大学（深信大）
**分支：** main

---

## 核心原则

- **计划优先** — 非简单任务先进入计划模式，计划存入 `quality_reports/plans/`
- **完成即验证** — 每项任务结束后运行代码、确认输出正确
- **代码即数据文档** — 过滤条件必须在每个分析脚本中**显式声明**，绝不隐含
- **质量门槛** — 低于 80/100 不提交；论文级输出目标 90+
- **[LEARN] 标签** — 被纠正时，将 `[LEARN:类别] 错误做法 → 正确做法` 存入 MEMORY.md

---

## 数据说明

**数据来源：** 智联招聘数据库 2016–2025.7

| 文件 | 大小 | 用途 |
|------|------|------|
| `源数据/合并画像后_智联招聘数据库2016-2025.7.csv` | 94 MB | Python 主分析 |
| `源数据/合并画像后_智联招聘数据库2016-2025.7.dta` | 148 MB | Stata 备用 |

**必须应用的过滤条件（每个分析脚本开头显式声明）：**

```python
# 必须保留此注释，说明过滤原因
df = df[df['目前所属城市'] == '深圳市']      # 仅保留深圳企业
df = df[df['复核结果'] != '未见信息']          # 排除信息不完整记录
```

---

## 文件夹结构

```
深圳小巨人企业招聘情况/
├── CLAUDE.md                    # 本文件
├── .claude/                     # 规则、技能、智能体、钩子
├── Bibliography_base.bib        # 集中管理参考文献
├── Figures/                     # 图表输出（PNG + PDF，DPI≥300）
├── scripts/                     # Python 分析脚本
├── quality_reports/             # 计划、会话日志、质量报告
├── explorations/                # 探索性分析沙盒（60/100 门槛）
├── templates/                   # 会话日志、质量报告模板
├── master_supporting_docs/      # 参考文献 PDF、政策文件
└── 源数据/                      # 原始数据（只读，绝不修改）
```

---

## 常用命令

```bash
# 运行分析脚本
python3 scripts/analysis_name.py

# 快速脚本测试
python3 -c "import pandas as pd; df = pd.read_csv('源数据/合并画像后_智联招聘数据库2016-2025.7.csv', nrows=5); print(df.columns.tolist())"

# 检查中文字体
python3 -c "import matplotlib.font_manager as fm; fonts=[f.name for f in fm.fontManager.ttflist]; print([f for f in fonts if 'Hei' in f or 'Song' in f or 'Source' in f])"

# 质量评分
python3 scripts/quality_score.py scripts/analysis_name.py
```

---

## 质量门槛

| 分数 | 门槛 | 含义 |
|------|------|------|
| 80 | 提交 | 可存入版本控制 |
| 90 | 交付 | 可纳入论文/报告正文 |
| 95 | 卓越 | 直接发表标准 |

---

## 技能快速参考

| 命令 | 功能 |
|------|------|
| `/data-analysis [数据集]` | 端到端 Python 分析流程 |
| `/review-r [文件]` | 代码质量审查（适用于 Python 脚本） |
| `/lit-review [主题]` | 文献检索与综述 |
| `/research-ideation [主题]` | 研究问题与分析策略建议 |
| `/interview-me [主题]` | 交互式研究访谈 |
| `/review-paper [文件]` | 手稿审查 |
| `/proofread [文件]` | 中英文语法/表达审查 |
| `/commit [说明]` | 暂存、提交 |
| `/devils-advocate` | 挑战研究设计与分析逻辑 |

---

## 当前研究进度

| 研究模块 | 状态 | 关键文件 | 说明 |
|----------|------|----------|------|
| 数据清洗与基础探索（EDA） | 待启动 | — | 过滤 + 变量分布 |
| 岗位分类体系构建 | 待启动 | — | 职位标准化/聚类 |
| 历年招聘规模变迁 | 待启动 | — | 时间序列趋势 |
| 岗位结构与技能需求演变 | 待启动 | — | 结构变迁指标 |
| 与深信大专业对比分析 | 待启动 | — | 产教匹配度 |
| 论文/报告撰写（Word） | 待启动 | — | 中文期刊格式 |
