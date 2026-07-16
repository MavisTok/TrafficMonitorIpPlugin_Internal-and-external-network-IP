# Exit Tooltip Column Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将出口检测 Tooltip 改为中文标题和固定字符列宽的五行输出，同时保持现有检测逻辑并继续排除 GitHub。

**Architecture:** 仅修改 `FormatExitRow` 的纯文本格式化和 `FormatTooltip` 的标题。使用精确完整字符串测试锁定三列布局，网络探测、缓存与 UI 调用保持不变。

**Tech Stack:** C++17、Visual Studio/MSBuild、现有 `ExitDetectionTests` 控制台测试。

---

### Task 1: 用精确字符串锁定目标格式

**Files:**
- Modify: `tests/exit_detection_tests.cpp:135-160`
- Test: `tests/exit_detection_tests.cpp`

- [ ] **Step 1: 写失败测试**

删除初始快照和成功快照中所有依赖旧英文标题、Tab 或零散子串的格式断言，改为两组完整字符串比较。初始快照断言为：

```cpp
const std::wstring expected_initial_tooltip =
    L"──── 出口检测 ────\n"
    L"Google  ->  -- WAIT\n"
    L"YouTube ->  -- WAIT\n"
    L"OpenAI  ->  -- WAIT\n"
    L"Claude  ->  -- WAIT\n"
    L"Netflix ->  -- WAIT";
CHECK(initial_tooltip == expected_initial_tooltip);
CHECK(initial_tooltip.find(L'\t') == std::wstring::npos);
CHECK(initial_tooltip.find(L"GitHub") == std::wstring::npos);
```

成功快照断言为：

```cpp
const std::wstring expected_tooltip =
    L"──── 出口检测 ────\n"
    L"Google  ->  HK GGL\n"
    L"YouTube ->  JP GGL\n"
    L"OpenAI  ->  US CF\n"
    L"Claude  ->  SG CF\n"
    L"Netflix ->  JP NFLX";
CHECK(compact_tooltip == expected_tooltip);
CHECK(compact_tooltip.find(L'\t') == std::wstring::npos);
CHECK(compact_tooltip.find(L"GitHub") == std::wstring::npos);
```

- [ ] **Step 2: 运行测试并确认因旧格式失败**

Run:

```powershell
& 'E:\Microsoft Visual Studio\2026\MSBuild\Current\Bin\MSBuild.exe' tests\ExitDetectionTests.vcxproj /t:Rebuild /p:Configuration=Debug /p:Platform=x64
& '.\tests\bin\x64\Debug\ExitDetectionTests.exe'
```

Expected: 构建成功，测试在完整 Tooltip 相等断言处失败，因为旧实现仍输出英文标题和 Tab。

### Task 2: 实现固定列宽格式

**Files:**
- Modify: `src/exit_detection.cpp:676-686`
- Modify: `src/exit_detection.cpp:931-932`
- Test: `tests/exit_detection_tests.cpp`

- [ ] **Step 1: 写最小实现**

```cpp
std::wstring FormatExitRow(Site site, const std::wstring& result) {
    constexpr std::size_t kSiteColumnWidth = 7;
    std::wstring line = SiteName(site);
    if (line.size() < kSiteColumnWidth) {
        line.append(kSiteColumnWidth - line.size(), L' ');
    }
    line += L" ->  ";
    line += result;
    return line;
}
```

并将标题初始化改为：

```cpp
std::wstring tooltip = L"──── 出口检测 ────";
```

- [ ] **Step 2: 运行测试并确认通过**

运行 Task 1 的测试构建和可执行文件。Expected: `exit_detection parser tests passed`。

- [ ] **Step 3: 运行配置与代理回归验证**

```powershell
& '.\tests\verify_exit_option.ps1'
& '.\tests\verify_external_ip_proxy.ps1'
```

Expected: 两个脚本均成功退出。

### Task 3: 构建最终 Release DLL 并检查仓库

**Files:**
- Output: `bin/x64/Release/TrafficMonitorIpPlugin.dll`

- [ ] **Step 1: 重建 Release x64**

```powershell
& 'E:\Microsoft Visual Studio\2026\MSBuild\Current\Bin\MSBuild.exe' TrafficMonitorIpPlugin.sln /m /t:Rebuild /p:Configuration=Release /p:Platform=x64 /v:minimal
```

Expected: MSBuild 成功，输出 `bin\x64\Release\TrafficMonitorIpPlugin.dll`。

- [ ] **Step 2: 检查差异和产物时间戳**

```powershell
git diff --check
git status --short
Get-Item '.\bin\x64\Release\TrafficMonitorIpPlugin.dll'
```

Expected: 无空白错误；仅计划内源代码、测试和计划文档发生变化；DLL 时间戳为本次构建时间。

- [ ] **Step 3: 提交实现**

```powershell
git add src/exit_detection.cpp tests/exit_detection_tests.cpp docs/superpowers/plans/2026-07-17-exit-tooltip-column-alignment.md
git commit -m "fix: align exit tooltip columns"
```
