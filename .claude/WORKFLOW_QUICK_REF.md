# Workflow Quick Reference

**Model:** Contractor (you direct, Claude orchestrates)

---

## The Loop

```
Your instruction
    ↓
[PLAN] (if multi-file or unclear) → Show plan → Your approval
    ↓
[EXECUTE] Implement, verify, done
    ↓
[REPORT] Summary + what's ready
    ↓
Repeat
```

---

## I Ask You When

- **Design forks:** "Option A (fast) vs. Option B (robust). Which?"
- **Code ambiguity:** "Spec unclear on X. Assume Y?"
- **Replication edge case:** "Just missed tolerance. Investigate?"
- **Scope question:** "Also refactor Y while here, or focus on X?"

---

## I Just Execute When

- Code fix is obvious (bug, pattern application)
- Verification (tolerance checks, tests, compilation)
- Documentation (logs, commits)
- Plotting (per established standards)
- Deployment (after you approve, I ship automatically)

---

## Quality Gates (No Exceptions)

| Score | Action |
|-------|--------|
| >= 80 | Ready to commit |
| < 80  | Fix blocking issues |

---

## Non-Negotiables（不可妥协的项目约束）

**数据过滤（每个脚本必须显式声明，违反视为质量不合格）：**
```python
df = df[df['目前所属城市'] == '深圳市']
df = df[df['复核结果'] != '未见信息']
```

**随机种子：** 所有随机操作统一使用 `RANDOM_SEED = 42`

**图表标准：**
- 保存 DPI ≥ 300，同时输出 `.png`（报告）和 `.pdf`（论文）
- 所有图表保存至 `Figures/` 目录
- 中文标注，必须配置中文字体（思源黑体优先）
- 去掉上边框和右边框（学术简洁风格）

**配色规范：** 使用色盲友好调色板（`seaborn colorblind` 或项目约定色板），禁止纯红 + 纯绿并列

**路径约定：** 脚本从项目根目录运行，使用相对路径（`源数据/...`、`Figures/...`）

---

## Preferences

**汇报风格：** 简洁要点，关键发现加粗；细节按需提供
**Session logs:** 始终记录（计划后、增量、会话结束）
**可视化：** 每次分析生成图表后，直接给出简短解读
**歧义处理：** 遇到分析方法选择时主动提问，不自行假设

---

## Exploration Mode

For experimental work, use the **Fast-Track** workflow:
- Work in `explorations/` folder
- 60/100 quality threshold (vs. 80/100 for production)
- No plan needed — just a research value check (2 min)
- See `.claude/rules/exploration-fast-track.md`

---

## Next Step

You provide task → I plan (if needed) → Your approval → Execute → Done.
