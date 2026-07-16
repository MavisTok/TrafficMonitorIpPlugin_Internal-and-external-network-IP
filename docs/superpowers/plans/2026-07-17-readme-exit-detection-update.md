# README Exit Detection Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 更新中文 README，使其准确说明五站点出口检测功能，并将已验证的本地 `master` 推送到 GitHub。

**Architecture:** 只编辑现有 `README.md` 的相关功能、配置和项目结构段落，不改动程序代码。通过字符串检查、现有配置验证脚本和 Git 状态验证文档真实性，再提交并在拉取远端状态后推送。

**Tech Stack:** Markdown、PowerShell、Git。

---

### Task 1: 补充用户功能说明

**Files:**
- Modify: `README.md:5-15`
- Modify: `README.md:90-110`

- [ ] **Step 1: 更新主要功能列表**

增加默认关闭的“常用站点出口检测”，明确检测 Google、YouTube、OpenAI、Claude、Netflix 的出口国家/地区和网络标识。

- [ ] **Step 2: 新增独立功能章节**

在“Claude IP风险检测”之后新增“常用站点出口检测（可选功能）”，写明启用路径、五个站点、不支持 GitHub、结果含义、等待占位值 `-- WAIT` 和失败占位值 `-- ----`，并放入以下完整示例：

```text
──── 出口检测 ────
Google  ->  US GGL
YouTube ->  JP GGL
OpenAI  ->  US CF
Claude  ->  US CF
Netflix ->  JP NFLX
```

### Task 2: 补充配置和开发结构

**Files:**
- Modify: `README.md:150-165`
- Modify: `README.md:205-215`

- [ ] **Step 1: 更新配置示例**

在 `[ip]` 示例中增加：

```ini
enable_exit_detection=0       # 启用常用站点出口检测（默认关闭）
```

- [ ] **Step 2: 更新项目结构**

增加：

```text
src/exit_detection.h/.cpp：常用站点出口国家/地区检测和Tooltip格式化
```

### Task 3: 验证、提交并同步 GitHub

**Files:**
- Modify: `README.md`
- Create: `docs/superpowers/plans/2026-07-17-readme-exit-detection-update.md`

- [ ] **Step 1: 验证 README 内容和现有配置集成**

```powershell
rg -n "常用站点出口检测|──── 出口检测 ────|Google  ->  US GGL|YouTube ->  JP GGL|OpenAI  ->  US CF|Claude  ->  US CF|Netflix ->  JP NFLX|-- WAIT|-- ----|enable_exit_detection|src/exit_detection" README.md
& '.\tests\verify_exit_option.ps1'
git diff --check
git diff -- README.md
```

Expected: Tooltip 标题与五行示例按固定顺序连续出现，等待和失败占位值均有说明；配置验证脚本全部通过；无空白错误；README 差异仅包含规格内更新。

- [ ] **Step 2: 提交 README 和实施计划**

```powershell
git add README.md docs/superpowers/plans/2026-07-17-readme-exit-detection-update.md
git commit -m "docs: document exit detection feature"
```

- [ ] **Step 3: 获取远端状态并确认可快进推送**

```powershell
git fetch origin
git branch --show-current
git rev-list --left-right --count origin/master...master
git log --oneline origin/master..master
git diff --stat origin/master..master
git diff --name-status origin/master..master
git status --short
```

Expected: 当前分支为 `master`，工作区干净且 `master` 不落后于 `origin/master`；逐项审阅所有待推送提交和文件差异，确认它们均为本轮已经恢复、验证并获用户要求同步的出口检测功能、排版与 README 文档提交，没有无关或敏感文件。

- [ ] **Step 4: 推送 GitHub 并验证远端引用**

```powershell
git push origin master
git ls-remote origin refs/heads/master
git rev-parse HEAD
```

Expected: 推送成功，远端 `master` SHA 与本地 `HEAD` 相同。
