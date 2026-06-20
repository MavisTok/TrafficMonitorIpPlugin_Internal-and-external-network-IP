# Claude IP 风险检测 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为TrafficMonitorIpPlugin新增一个默认关闭的"Claude IP风险检测"功能：对比Cloudflare出口IP、检测受限地区、探测api.anthropic.com直连可达性、查询VPN/代理/机房风险、追踪30天IP波动，通过tooltip/紧凑标记/右键菜单展示，并在README中致谢参考项目。

**Architecture:** 新增独立模块 `src/claude_risk.h/.cpp`，内部用进程级静态缓存+互斥锁+detached后台线程实现"异步刷新、同步读取"模式，避免阻塞`DataRequired()`。展示层（tooltip拼接、自绘后缀、右键菜单）改在`plugin.h/.cpp`中按现有模式接入。设计依据见 `docs/superpowers/specs/2026-06-20-claude-ip-risk-design.md`（已通过spec审查）。

**Tech Stack:** C++17, WinHTTP, Win32 (DialogBoxParamW/MessageBoxW), 现有项目无自动化测试框架（无gtest/无CI单测）。本计划对纯逻辑函数（trace解析、受限地区判定、波动等级、历史文件去重）采用**Debug-only断言自检**代替传统单测框架：在`claude_risk.cpp`末尾用`#ifdef _DEBUG`包裹的静态对象在DLL加载时自动执行`assert()`校验，命中现有"Debug编译+PluginTester手动加载"的验证流程，不引入新的测试基础设施（该项目历来没有test runner，新增一个不符合YAGNI）。

---

## 前置说明（执行者必读）

- 本项目用Visual Studio 2022 + MSBuild构建，没有unit test框架。"运行测试"在本计划中指：**编译Debug x64 → 在调试器中运行PluginTester.exe并加载生成的DLL → 观察是否触发assert弹窗（自检失败会在DLL加载瞬间断言）**。纯逻辑函数因此必须先写出"自检代码"再写实现（红→绿），但执行方式是编译+加载DLL，不是`pytest`式命令行。
- 涉网络的代码（Cloudflare trace、ip-api.com、api.anthropic.com直连探测）无法做到这种自动断言（依赖真实网络），只能在最后的手动验证任务里用真实网络环境核对。
- 所有新增中文字符串字面量所在的`.cpp`必须在文件顶部加 `#pragma execution_character_set("utf-8")`（与`plugin.cpp`一致），否则中文会乱码。
- 构建命令（来自`CLAUDE.md`）：
  ```
  msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64
  ```

---

### Task 1: 新建claude_risk模块骨架并接入工程

**Files:**
- Create: `src/claude_risk.h`
- Create: `src/claude_risk.cpp`
- Modify: `TrafficMonitorIpPlugin.vcxproj`
- Modify: `TrafficMonitorIpPlugin.vcxproj.filters`

- [ ] **Step 1: 创建 `src/claude_risk.h`**

```cpp
/**
 * @file claude_risk.h
 * @brief Claude IP风险检测模块接口声明
 * @details 整合Cloudflare出口对比、受限地区检测、直连可达性探测、
 *          VPN/代理/机房风险查询、IP波动追踪五项检测。
 *          所有网络检测在后台线程异步执行，调用方只读取缓存快照，不阻塞。
 * @author Lynn
 * @date 2026
 */

#pragma once

#include <string>
#include <chrono>

namespace claude_risk {

enum class Reachability { Unknown, Reachable, Blocked };
enum class RotationLevel { None, Notice, Warning, Severe };

struct ClaudeRiskInfo {
    bool valid = false;                 ///< 是否已完成至少一次检测
    std::chrono::system_clock::time_point checked_at{};

    // 1. Cloudflare出口视角对比
    std::wstring cf_ip;                 ///< claude.ai/cdn-cgi/trace 的 ip=
    std::wstring cf_colo;                ///< colo= (机房代号，如LAX)
    std::wstring cf_loc;                 ///< loc=  (Cloudflare判定的国家代码)
    bool cf_warp = false;                ///< warp=on/off
    bool cf_trace_ok = false;            ///< trace请求是否成功
    bool ip_mismatch = false;            ///< cf_ip 与外网IP是否不一致

    // 2. 受限地区检测
    bool country_restricted = false;
    std::wstring restricted_country_code;

    // 3. 直连可达性
    Reachability direct_reachability = Reachability::Unknown;

    // 4. VPN/代理/机房风险（ip-api.com）
    bool is_proxy = false;
    bool is_hosting = false;
    bool is_mobile = false;
    bool risk_query_ok = false;          ///< ip-api.com请求是否成功

    // 5. IP波动追踪
    int distinct_ip_count_30d = 0;
    RotationLevel rotation_level = RotationLevel::None;

    /// 是否命中任意一项风险（用于紧凑标记显示判断）
    bool HasAnyRisk() const {
        return ip_mismatch || country_restricted
            || direct_reachability == Reachability::Blocked
            || is_proxy || is_hosting
            || rotation_level == RotationLevel::Warning
            || rotation_level == RotationLevel::Severe;
    }
};

/// 返回当前缓存的快照（非阻塞，立即返回，内部加锁拷贝）
ClaudeRiskInfo GetClaudeRiskSnapshot();

/// 检查是否到达刷新间隔（或外网IP变化/强制刷新），需要时异步启动一次检测（非阻塞）
void RequestClaudeRiskRefreshAsync(const std::wstring& config_dir,
                                    const std::wstring& current_external_ip,
                                    const std::wstring& current_country,
                                    bool force_refresh);

// === 以下为内部纯逻辑函数，声明在头文件中以便独立验证 ===

/// 解析cdn-cgi/trace纯文本响应（key=value逐行），取出指定字段；未找到返回空字符串
std::wstring ParseTraceField(const std::string& trace_text, const std::string& field);

/// 判断国家代码（不区分大小写）是否在受限名单中
bool IsRestrictedCountry(const std::wstring& country_code);

/// 根据30天内不同IP数量计算波动等级（1=None, 2-3=Notice, 4-6=Warning, 7+=Severe）
RotationLevel ComputeRotationLevel(int distinct_ip_count);

} // namespace claude_risk
```

- [ ] **Step 2: 创建 `src/claude_risk.cpp` 骨架（先放空实现，保证能编译）**

```cpp
/**
 * @file claude_risk.cpp
 * @brief Claude IP风险检测模块实现
 * @author Lynn
 * @date 2026
 */
#pragma execution_character_set("utf-8")

#include "claude_risk.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <winhttp.h>
#include <mutex>
#include <thread>
#include <vector>
#include <fstream>
#include <algorithm>
#include <cwctype>
#include <ctime>
#include <cassert>

#pragma comment(lib, "Winhttp.lib")

namespace claude_risk {

std::wstring ParseTraceField(const std::string& trace_text, const std::string& field) {
    (void)trace_text; (void)field;
    return L""; // TODO Task 2
}

bool IsRestrictedCountry(const std::wstring& country_code) {
    (void)country_code;
    return false; // TODO Task 3
}

RotationLevel ComputeRotationLevel(int distinct_ip_count) {
    (void)distinct_ip_count;
    return RotationLevel::None; // TODO Task 4
}

ClaudeRiskInfo GetClaudeRiskSnapshot() {
    return ClaudeRiskInfo{}; // TODO Task 7
}

void RequestClaudeRiskRefreshAsync(const std::wstring& config_dir,
                                    const std::wstring& current_external_ip,
                                    const std::wstring& current_country,
                                    bool force_refresh) {
    (void)config_dir; (void)current_external_ip; (void)current_country; (void)force_refresh;
    // TODO Task 7
}

} // namespace claude_risk
```

- [ ] **Step 3: 把新文件加入工程 — 修改 `TrafficMonitorIpPlugin.vcxproj`**

在第93-96行的`<ClCompile>`组追加一行，第99-104行的`<ClInclude>`组追加一行：

```diff
   <ItemGroup>
     <ClCompile Include="src\dllmain.cpp" />
+    <ClCompile Include="src\claude_risk.cpp" />
     <ClCompile Include="src\ip_utils.cpp" />
     <ClCompile Include="src\options_dialog.cpp" />
     <ClCompile Include="src\plugin.cpp" />
   </ItemGroup>
   <ItemGroup>
     <ClInclude Include="PluginInterface.h" />
+    <ClInclude Include="src\claude_risk.h" />
     <ClInclude Include="src\ip_item.h" />
     <ClInclude Include="src\ip_utils.h" />
     <ClInclude Include="src\options_dialog.h" />
     <ClInclude Include="src\plugin.h" />
     <ClInclude Include="src\plugin_options.h" />
   </ItemGroup>
```

- [ ] **Step 4: 同步修改 `TrafficMonitorIpPlugin.vcxproj.filters`**

```diff
   <ItemGroup>
     <ClCompile Include="src\dllmain.cpp">
       <Filter>源文件</Filter>
     </ClCompile>
+    <ClCompile Include="src\claude_risk.cpp">
+      <Filter>源文件</Filter>
+    </ClCompile>
     <ClCompile Include="src\ip_utils.cpp">
       <Filter>源文件</Filter>
     </ClCompile>
     ...
   </ItemGroup>
   <ItemGroup>
     <ClInclude Include="PluginInterface.h">
       <Filter>头文件</Filter>
     </ClInclude>
+    <ClInclude Include="src\claude_risk.h">
+      <Filter>头文件</Filter>
+    </ClInclude>
     <ClInclude Include="src\ip_item.h">
       <Filter>头文件</Filter>
     </ClInclude>
     ...
   </ItemGroup>
```

- [ ] **Step 5: 构建验证骨架可编译**

Run: `msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64`
Expected: `Build succeeded.`，输出 `bin\x64\Debug\TrafficMonitorIpPlugin.dll`

- [ ] **Step 6: Commit**

```bash
git add src/claude_risk.h src/claude_risk.cpp TrafficMonitorIpPlugin.vcxproj TrafficMonitorIpPlugin.vcxproj.filters
git commit -m "新增claude_risk模块骨架并接入工程"
```

---

### Task 2: 实现并自检 `ParseTraceField`

**Files:**
- Modify: `src/claude_risk.cpp`

- [ ] **Step 1: 在文件末尾追加Debug自检代码（先写断言，此时应该编译通过但运行时断言失败——因为Step 2还没实现真正逻辑）**

在 `claude_risk.cpp` 文件最后（namespace闭合的`}`之后）追加：

```cpp
#ifdef _DEBUG
namespace claude_risk {
namespace {

void RunSelfTests() {
    // --- ParseTraceField ---
    {
        std::string sample =
            "fl=1164f6\nh=claude.ai\nip=69.63.196.167\nts=1781928228.000\n"
            "loc=US\ncolo=LAX\nwarp=off\n";
        assert(ParseTraceField(sample, "ip") == L"69.63.196.167");
        assert(ParseTraceField(sample, "loc") == L"US");
        assert(ParseTraceField(sample, "colo") == L"LAX");
        assert(ParseTraceField(sample, "warp") == L"off");
        assert(ParseTraceField(sample, "missing_field") == L"");
    }
}

struct SelfTestRunner {
    SelfTestRunner() { RunSelfTests(); }
};
static SelfTestRunner g_self_test_runner;

} // anonymous namespace
} // namespace claude_risk
#endif // _DEBUG
```

- [ ] **Step 2: 构建Debug，确认编译通过（此时逻辑还是空实现，断言会在运行时失败，但这一步只验证能编译）**

Run: `msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64`
Expected: `Build succeeded.`

- [ ] **Step 3: 实现 `ParseTraceField` 真正逻辑**

替换Step 2（Task 1中）写的占位实现：

```cpp
std::wstring ParseTraceField(const std::string& trace_text, const std::string& field) {
    std::string pattern = field + "=";
    size_t pos = 0;
    while (pos < trace_text.size()) {
        size_t line_end = trace_text.find('\n', pos);
        if (line_end == std::string::npos) line_end = trace_text.size();
        std::string line = trace_text.substr(pos, line_end - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.compare(0, pattern.size(), pattern) == 0) {
            std::string value = line.substr(pattern.size());
            int wlen = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), (int)value.size(), nullptr, 0);
            if (wlen <= 0) return L"";
            std::wstring wvalue(wlen, L'\0');
            MultiByteToWideChar(CP_UTF8, 0, value.c_str(), (int)value.size(),
                                 const_cast<wchar_t*>(wvalue.data()), wlen);
            return wvalue;
        }
        pos = line_end + 1;
    }
    return L"";
}
```

- [ ] **Step 4: 构建Debug，用调试器运行PluginTester加载DLL验证断言不再触发**

Run: `msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64`
然后在Visual Studio中以调试模式启动 `PluginTester` 项目（或直接运行 `PluginTester\x64\Debug\PluginTester.exe`），通过其界面加载 `bin\x64\Debug\TrafficMonitorIpPlugin.dll`。
Expected: DLL加载时不出现assert断言对话框（说明`ParseTraceField`三个用例全部通过）。

- [ ] **Step 5: Commit**

```bash
git add src/claude_risk.cpp
git commit -m "实现ParseTraceField并添加Debug自检"
```

---

### Task 3: 实现并自检 `IsRestrictedCountry`

**Files:**
- Modify: `src/claude_risk.cpp`

- [ ] **Step 1: 在 `RunSelfTests()` 函数体内追加用例**

```cpp
    // --- IsRestrictedCountry ---
    {
        assert(IsRestrictedCountry(L"CN") == true);
        assert(IsRestrictedCountry(L"cn") == true);  // 大小写不敏感
        assert(IsRestrictedCountry(L"RU") == true);
        assert(IsRestrictedCountry(L"UA") == true);  // 名单最后一项
        assert(IsRestrictedCountry(L"US") == false);
        assert(IsRestrictedCountry(L"") == false);
    }
```

- [ ] **Step 2: 构建确认能编译（断言此时会失败，预期内）**

Run: `msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64`
Expected: `Build succeeded.`

- [ ] **Step 3: 实现 `IsRestrictedCountry`（含国家名单常量）**

在 `ParseTraceField` 实现之前新开一个匿名namespace放置名单常量（此时文件里还没有其他匿名namespace块，这是第一个；后续Task 5、Task 6还会各自新增匿名namespace块——C++允许同一个.cpp文件中存在多个匿名namespace块，它们都属于同一个该翻译单元内部链接的命名空间，相互可见，不会冲突）：

```cpp
namespace {
// 名单来源：https://github.com/cso1z/claude-ip-guard (MIT License)
// 综合Anthropic官方支持地区与OFAC出口管制名单整理，社区版本，仅供参考。
const wchar_t* const kRestrictedCountries[] = {
    L"CN", L"RU", L"KP", L"IR", L"SY", L"CU", L"BY", L"VE", L"MM",
    L"LY", L"SO", L"YE", L"ML", L"CF", L"SS", L"CD", L"ER", L"AF", L"UA"
};
} // anonymous namespace

bool IsRestrictedCountry(const std::wstring& country_code) {
    if (country_code.empty()) return false;
    std::wstring upper = country_code;
    std::transform(upper.begin(), upper.end(), upper.begin(),
                   [](wchar_t c) { return (wchar_t)::towupper(c); });
    for (const wchar_t* c : kRestrictedCountries) {
        if (upper == c) return true;
    }
    return false;
}
```

- [ ] **Step 4: 构建Debug + PluginTester加载验证断言通过**

Run: `msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64`
用PluginTester加载DLL，确认无断言弹窗。

- [ ] **Step 5: Commit**

```bash
git add src/claude_risk.cpp
git commit -m "实现IsRestrictedCountry受限地区名单检测"
```

---

### Task 4: 实现并自检 `ComputeRotationLevel`

**Files:**
- Modify: `src/claude_risk.cpp`

- [ ] **Step 1: 追加自检用例**

```cpp
    // --- ComputeRotationLevel ---
    {
        assert(ComputeRotationLevel(1) == RotationLevel::None);
        assert(ComputeRotationLevel(2) == RotationLevel::Notice);
        assert(ComputeRotationLevel(3) == RotationLevel::Notice);
        assert(ComputeRotationLevel(4) == RotationLevel::Warning);
        assert(ComputeRotationLevel(6) == RotationLevel::Warning);
        assert(ComputeRotationLevel(7) == RotationLevel::Severe);
        assert(ComputeRotationLevel(100) == RotationLevel::Severe);
        assert(ComputeRotationLevel(0) == RotationLevel::None);
    }
```

- [ ] **Step 2: 构建确认能编译**

Run: `msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64`

- [ ] **Step 3: 实现 `ComputeRotationLevel`**

```cpp
RotationLevel ComputeRotationLevel(int distinct_ip_count) {
    if (distinct_ip_count >= 7) return RotationLevel::Severe;
    if (distinct_ip_count >= 4) return RotationLevel::Warning;
    if (distinct_ip_count >= 2) return RotationLevel::Notice;
    return RotationLevel::None;
}
```

- [ ] **Step 4: 构建Debug + PluginTester验证**

Run: `msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64`，PluginTester加载DLL确认无断言。

- [ ] **Step 5: Commit**

```bash
git add src/claude_risk.cpp
git commit -m "实现ComputeRotationLevel IP波动分级"
```

---

### Task 5: 实现IP历史文件读写与30天去重统计

**Files:**
- Modify: `src/claude_risk.cpp`

- [ ] **Step 1: 追加自检用例（使用系统临时目录，测试后自行清理）**

```cpp
    // --- UpdateAndCountHistory: 去重 + 30天窗口 ---
    {
        wchar_t temp_dir[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, temp_dir);
        std::wstring test_dir = temp_dir;
        std::wstring test_file = test_dir + L"tm_ip_plugin_iphistory.log";
        DeleteFileW(test_file.c_str()); // 清理可能残留的上次测试文件

        int c1 = UpdateAndCountHistory(test_dir, L"1.1.1.1", L"US");
        assert(c1 == 1);
        int c2 = UpdateAndCountHistory(test_dir, L"1.1.1.1", L"US"); // 重复IP不应新增
        assert(c2 == 1);
        int c3 = UpdateAndCountHistory(test_dir, L"2.2.2.2", L"CN"); // 新IP
        assert(c3 == 2);
        int c4 = UpdateAndCountHistory(test_dir, L"3.3.3.3", L"JP");
        assert(c4 == 3);

        DeleteFileW(test_file.c_str()); // 清理测试产生的文件，不污染真实配置目录
    }
```

- [ ] **Step 2: 构建确认能编译（此时`UpdateAndCountHistory`尚未声明，预期编译失败）**

Run: `msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64`
Expected: 编译错误（`UpdateAndCountHistory`未定义）——这是正常的，下一步补上实现。

- [ ] **Step 3: 实现历史文件读写逻辑**

在匿名namespace中添加（放在 `IsRestrictedCountry` 实现之后）：

```cpp
namespace {

struct HistoryEntry {
    long long timestamp = 0;
    std::wstring ip;
    std::wstring country;
};

std::wstring HistoryFilePath(const std::wstring& config_dir) {
    std::wstring path = config_dir;
    if (!path.empty() && path.back() != L'\\' && path.back() != L'/') path += L'\\';
    path += L"tm_ip_plugin_iphistory.log";
    return path;
}

std::vector<HistoryEntry> LoadHistory(const std::wstring& path) {
    std::vector<HistoryEntry> entries;
    std::wifstream file(path);
    if (!file.is_open()) return entries;
    std::wstring line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        size_t p1 = line.find(L'|');
        if (p1 == std::wstring::npos) continue;
        size_t p2 = line.find(L'|', p1 + 1);
        if (p2 == std::wstring::npos) continue;
        HistoryEntry e;
        try {
            e.timestamp = std::stoll(line.substr(0, p1));
        } catch (...) {
            continue;
        }
        e.ip = line.substr(p1 + 1, p2 - p1 - 1);
        e.country = line.substr(p2 + 1);
        entries.push_back(std::move(e));
    }
    return entries;
}

void SaveHistoryAtomic(const std::wstring& path, const std::vector<HistoryEntry>& entries) {
    std::wstring tmp_path = path + L".tmp";
    {
        std::wofstream file(tmp_path, std::ios::trunc);
        if (!file.is_open()) return;
        for (const auto& e : entries) {
            file << e.timestamp << L"|" << e.ip << L"|" << e.country << L"\n";
        }
    }
    MoveFileExW(tmp_path.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING);
}

// 更新历史文件（按IP去重，30天滚动窗口），返回窗口内不同IP数量
int UpdateAndCountHistory(const std::wstring& config_dir, const std::wstring& ip, const std::wstring& country) {
    if (config_dir.empty() || ip.empty()) return 0;
    std::wstring path = HistoryFilePath(config_dir);

    auto entries = LoadHistory(path);

    const long long now = (long long)std::time(nullptr);
    const long long window_seconds = 30LL * 24 * 3600;

    entries.erase(std::remove_if(entries.begin(), entries.end(), [&](const HistoryEntry& e) {
        return (now - e.timestamp) > window_seconds;
    }), entries.end());

    bool exists = std::any_of(entries.begin(), entries.end(), [&](const HistoryEntry& e) {
        return e.ip == ip;
    });

    if (!exists) {
        HistoryEntry e;
        e.timestamp = now;
        e.ip = ip;
        e.country = country;
        entries.push_back(std::move(e));
    }

    SaveHistoryAtomic(path, entries);
    return (int)entries.size();
}

} // anonymous namespace
```

- [ ] **Step 4: 构建Debug + PluginTester验证断言通过**

Run: `msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64`，PluginTester加载DLL确认无断言弹窗。

- [ ] **Step 5: Commit**

```bash
git add src/claude_risk.cpp
git commit -m "实现IP历史文件读写与30天去重统计"
```

---

### Task 6: 实现通用HTTP请求helper（支持HTTP/HTTPS、GET/POST、自定义header）

**Files:**
- Modify: `src/claude_risk.cpp`

此部分依赖真实网络，不写自动断言，仅靠构建通过 + 后续任务的实际调用来验证。

- [ ] **Step 1: 在匿名namespace中实现 `HttpRequest`**

放在文件靠前位置（`ParseTraceField`实现之前）：

```cpp
namespace {

struct HttpResult {
    bool ok = false;
    int status_code = 0;
    std::string body;
};

HttpResult HttpRequest(const std::wstring& host, const std::wstring& path, bool use_https,
                        const std::wstring& method,
                        const std::vector<std::pair<std::wstring, std::wstring>>& headers,
                        const std::string& body, unsigned timeout_ms) {
    HttpResult result;

    HINTERNET hSession = WinHttpOpen(L"TrafficMonitorIpPlugin/1.0",
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return result;
    WinHttpSetTimeouts(hSession, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    INTERNET_PORT port = use_https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return result; }

    DWORD flags = use_https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, method.c_str(), path.c_str(), nullptr,
                                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return result; }

    std::wstring header_blob;
    for (const auto& h : headers) {
        header_blob += h.first + L": " + h.second + L"\r\n";
    }

    LPVOID send_data = body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data();
    DWORD send_len = (DWORD)body.size();

    bool ok = !!WinHttpSendRequest(hRequest,
                                    header_blob.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : header_blob.c_str(),
                                    (DWORD)-1L, send_data, send_len, send_len, 0);
    if (ok) ok = !!WinHttpReceiveResponse(hRequest, nullptr);

    if (ok) {
        DWORD status = 0, status_size = sizeof(status);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_FLAG_NUMBER | WINHTTP_QUERY_STATUS_CODE,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX);
        result.status_code = (int)status;

        std::string data;
        DWORD dwSize = 0;
        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            if (dwSize == 0) break;
            size_t old = data.size();
            data.resize(old + dwSize);
            DWORD dwRead = 0;
            if (!WinHttpReadData(hRequest, const_cast<char*>(data.data()) + old, dwSize, &dwRead)) break;
            data.resize(old + dwRead);
        } while (dwSize > 0);

        result.body = std::move(data);
        result.ok = true;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

std::string ExtractJsonBool(const std::string& json, const std::string& field, bool* found) {
    std::string pattern = "\"" + field + "\"";
    size_t start = json.find(pattern);
    *found = false;
    if (start == std::string::npos) return "";
    start += pattern.length();
    while (start < json.length() && (json[start] == ':' || json[start] == ' ')) start++;
    if (start + 4 <= json.length() && json.compare(start, 4, "true") == 0) { *found = true; return "true"; }
    if (start + 5 <= json.length() && json.compare(start, 5, "false") == 0) { *found = true; return "false"; }
    return "";
}

} // anonymous namespace
```

- [ ] **Step 2: 构建确认能编译**

Run: `msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64`
Expected: `Build succeeded.`（此时`HttpRequest`/`ExtractJsonBool`尚未被调用，可能有"未使用的静态函数"警告，属预期，下个任务会用到）

- [ ] **Step 3: Commit**

```bash
git add src/claude_risk.cpp
git commit -m "添加通用WinHTTP请求helper，支持HTTP/HTTPS与自定义header"
```

---

### Task 7: 实现五项检测的串联逻辑 `DoRefresh` 与缓存快照

**Files:**
- Modify: `src/claude_risk.cpp`

- [ ] **Step 1: 在文件中加入缓存相关静态变量与 `DoRefresh`（放在 `GetClaudeRiskSnapshot`/`RequestClaudeRiskRefreshAsync` 占位实现之前）**

```cpp
namespace {

std::mutex g_mtx;
ClaudeRiskInfo g_cached;
std::chrono::steady_clock::time_point g_last_refresh{};
bool g_refresh_in_flight = false;
std::wstring g_last_checked_ip;

constexpr auto kRefreshInterval = std::chrono::minutes(30);

void DoRefresh(std::wstring config_dir, std::wstring external_ip, std::wstring external_country) {
    ClaudeRiskInfo info;
    info.checked_at = std::chrono::system_clock::now();

    // 1. Cloudflare出口视角对比
    auto trace = HttpRequest(L"claude.ai", L"/cdn-cgi/trace", true, L"GET", {}, "", 5000);
    if (trace.ok && trace.status_code == 200) {
        info.cf_trace_ok = true;
        info.cf_ip = ParseTraceField(trace.body, "ip");
        info.cf_colo = ParseTraceField(trace.body, "colo");
        info.cf_loc = ParseTraceField(trace.body, "loc");
        info.cf_warp = (ParseTraceField(trace.body, "warp") == L"on");
        if (!info.cf_ip.empty() && !external_ip.empty()) {
            info.ip_mismatch = (info.cf_ip != external_ip);
        }
    }

    // 2. 受限地区检测：优先用本次取到的cf_loc，否则回退调用方传入的country（同一次调用，时间点一致）
    std::wstring country_for_check = !info.cf_loc.empty() ? info.cf_loc : external_country;
    info.country_restricted = IsRestrictedCountry(country_for_check);
    if (info.country_restricted) info.restricted_country_code = country_for_check;

    // 3. 直连可达性探测（使用占位假Key，不消耗真实账号额度）
    {
        std::vector<std::pair<std::wstring, std::wstring>> headers = {
            {L"Content-Type", L"application/json"},
            {L"anthropic-version", L"2023-06-01"},
            {L"x-api-key", L"sk-ant-api03-dummy"}
        };
        std::string body =
            "{\"model\":\"claude-3-5-sonnet-20240620\",\"max_tokens\":16,"
            "\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}]}";
        auto probe = HttpRequest(L"api.anthropic.com", L"/v1/messages", true, L"POST", headers, body, 5000);
        if (!probe.ok) {
            info.direct_reachability = Reachability::Unknown;
        } else if (probe.status_code == 403) {
            info.direct_reachability = Reachability::Blocked;
        } else {
            info.direct_reachability = Reachability::Reachable;
        }
    }

    // 4. VPN/代理/机房风险（ip-api.com，明文HTTP——免费版限制，已知取舍）
    if (!external_ip.empty()) {
        std::wstring path = L"/json/" + external_ip + L"?fields=status,proxy,hosting,mobile";
        auto risk = HttpRequest(L"ip-api.com", path, false, L"GET", {}, "", 5000);
        if (risk.ok && risk.status_code == 200) {
            bool found = false;
            info.is_proxy = (ExtractJsonBool(risk.body, "proxy", &found) == "true");
            info.is_hosting = (ExtractJsonBool(risk.body, "hosting", &found) == "true");
            info.is_mobile = (ExtractJsonBool(risk.body, "mobile", &found) == "true");
            info.risk_query_ok = true;
        }
    }

    // 5. IP波动追踪
    if (!external_ip.empty()) {
        info.distinct_ip_count_30d = UpdateAndCountHistory(config_dir, external_ip, external_country);
        info.rotation_level = ComputeRotationLevel(info.distinct_ip_count_30d);
    }

    info.valid = true;

    std::lock_guard<std::mutex> lk(g_mtx);
    g_cached = info;
    g_refresh_in_flight = false;
}

} // anonymous namespace
```

- [ ] **Step 2: 替换 `GetClaudeRiskSnapshot` 与 `RequestClaudeRiskRefreshAsync` 的占位实现**

```cpp
ClaudeRiskInfo GetClaudeRiskSnapshot() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return g_cached;
}

void RequestClaudeRiskRefreshAsync(const std::wstring& config_dir,
                                    const std::wstring& current_external_ip,
                                    const std::wstring& current_country,
                                    bool force_refresh) {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (g_refresh_in_flight) return;

    const auto now = std::chrono::steady_clock::now();
    bool ip_changed = !current_external_ip.empty() && current_external_ip != g_last_checked_ip;
    bool due = (g_last_refresh.time_since_epoch().count() == 0)
            || (now - g_last_refresh >= kRefreshInterval);

    if (!force_refresh && !ip_changed && !due) return;

    g_refresh_in_flight = true;
    g_last_refresh = now;
    g_last_checked_ip = current_external_ip;

    std::thread(DoRefresh, config_dir, current_external_ip, current_country).detach();
}
```

- [ ] **Step 3: 构建Debug确认编译通过**

Run: `msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64`
Expected: `Build succeeded.`（此时还没有任何调用方触发`RequestClaudeRiskRefreshAsync`，下面的任务负责接入UI层）

- [ ] **Step 4: Commit**

```bash
git add src/claude_risk.cpp
git commit -m "实现五项检测的串联逻辑与后台线程刷新缓存"
```

---

### Task 8: 新增配置开关 `enable_claude_risk_check`

**Files:**
- Modify: `src/plugin_options.h`

- [ ] **Step 1: 在 `PluginOptions` 结构体中新增字段**

修改 `src/plugin_options.h`，在"界面配置"分组之前新增一个分组：

```diff
     // === 智能缓存设置 ===
     bool enable_smart_cache = true;                     ///< 启用智能缓存（推荐）
     std::chrono::seconds fast_refresh{30};             ///< 网络变化后快速刷新间隔（秒）
     std::chrono::minutes max_refresh{15};              ///< 稳定期最大刷新间隔（分钟）
     
+    // === Claude IP风险检测 ===
+    bool enable_claude_risk_check = false;              ///< 启用Claude IP风险检测（默认关闭）
+
     // === 界面配置 ===
     std::wstring separator = L" | ";                   ///< 内外网IP之间的分隔符
```

- [ ] **Step 2: 构建确认编译通过**

Run: `msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64`

- [ ] **Step 3: Commit**

```bash
git add src/plugin_options.h
git commit -m "新增enable_claude_risk_check配置项"
```

---

### Task 9: 设置对话框新增勾选框（resource.h + plugin.rc + options_dialog.cpp）

**Files:**
- Modify: `res/resource.h`
- Modify: `res/plugin.rc`
- Modify: `src/options_dialog.cpp`

- [ ] **Step 1: 新增资源ID — 修改 `res/resource.h`**

```diff
 #define IDC_EDIT_SEPARATOR  1005
+#define IDC_CHECK_CLAUDE_RISK 1006
```

- [ ] **Step 2: 调整对话框布局 — 修改 `res/plugin.rc`**

完整替换 `IDD_OPTIONS` 定义为：

```rc
IDD_OPTIONS DIALOGEX 0, 0, 250, 165
STYLE DS_SETFONT | DS_MODALFRAME | WS_POPUP | WS_CAPTION | WS_SYSMENU
CAPTION "IP 插件设置"
FONT 9, "Segoe UI", 0, 0, 0x1
BEGIN
    CONTROL "显示内网IP", IDC_CHECK_INTERNAL, "Button", BS_AUTOCHECKBOX | WS_TABSTOP, 10, 10, 80, 12
    CONTROL "显示外网IP", IDC_CHECK_EXTERNAL, "Button", BS_AUTOCHECKBOX | WS_TABSTOP, 120, 10, 80, 12

    LTEXT   "首选网卡:", -1, 10, 35, 60, 12
    COMBOBOX IDC_EDIT_ADAPTER, 75, 33, 160, 100, CBS_DROPDOWNLIST | CBS_SORT | WS_VSCROLL | WS_TABSTOP

    LTEXT   "刷新间隔(分钟):", -1, 10, 60, 80, 12
    EDITTEXT IDC_EDIT_REFRESH, 95, 58, 40, 14, ES_NUMBER | ES_AUTOHSCROLL

    LTEXT   "分隔符:", -1, 10, 85, 60, 12
    EDITTEXT IDC_EDIT_SEPARATOR, 75, 83, 80, 14, ES_AUTOHSCROLL

    CONTROL "启用Claude IP风险检测", IDC_CHECK_CLAUDE_RISK, "Button", BS_AUTOCHECKBOX | WS_TABSTOP, 10, 100, 180, 12

    DEFPUSHBUTTON "确定", IDOK, 110, 130, 50, 14
    PUSHBUTTON     "取消", IDCANCEL, 170, 130, 50, 14
END
```

- [ ] **Step 3: 在 `src/options_dialog.cpp` 的 `WM_INITDIALOG` 分支中新增读取**

```diff
         SetCheck(hDlg, IDC_CHECK_INTERNAL, s_opts->show_internal);
         SetCheck(hDlg, IDC_CHECK_EXTERNAL, s_opts->show_external);
+        SetCheck(hDlg, IDC_CHECK_CLAUDE_RISK, s_opts->enable_claude_risk_check);
         SetupAdapterCombo(hDlg, IDC_EDIT_ADAPTER, s_opts->preferred_adapter);
```

- [ ] **Step 4: 在 `IDOK` 分支中新增写入与变更比较**

```diff
             new_opts.show_internal = GetCheck(hDlg, IDC_CHECK_INTERNAL);
             new_opts.show_external = GetCheck(hDlg, IDC_CHECK_EXTERNAL);
+            new_opts.enable_claude_risk_check = GetCheck(hDlg, IDC_CHECK_CLAUDE_RISK);
             new_opts.preferred_adapter = GetSelectedAdapter(hDlg, IDC_EDIT_ADAPTER);
```

```diff
             bool changed = (new_opts.show_internal != s_opts->show_internal)
                 || (new_opts.show_external != s_opts->show_external)
+                || (new_opts.enable_claude_risk_check != s_opts->enable_claude_risk_check)
                 || (new_opts.preferred_adapter != s_opts->preferred_adapter)
                 || (new_opts.external_refresh != s_opts->external_refresh)
                 || (new_opts.separator != s_opts->separator);
```

- [ ] **Step 5: 构建确认编译通过**

Run: `msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64`

- [ ] **Step 6: Commit**

```bash
git add res/resource.h res/plugin.rc src/options_dialog.cpp
git commit -m "设置对话框新增Claude IP风险检测开关"
```

---

### Task 10: `IpPluginItem` 暴露外网IP/国家，调整自绘宽度与紧凑标记

**Files:**
- Modify: `src/plugin.h`
- Modify: `src/plugin.cpp`

- [ ] **Step 1: 在 `src/plugin.h` 中把 `Update()` 内的局部变量 `ext_result` 提升为成员变量**

把 `Update()` 方法体中从"获取外网IP和公司信息"注释开始到方法结尾的整段代码，完整替换为（把所有原来的局部变量 `ext_result` 改成成员 `ext_result_`，逻辑不变）：

```cpp
        // 获取外网IP和公司信息（无论是否显示内网都需要获取）
        ext_result_ = iputils::IpWithCountry{};
        if (options.show_external) {
            iputils::ExternalIpOptions opt;
            // 配置智能缓存策略
            if (options.enable_smart_cache) {
                opt.strategy = iputils::CacheStrategy::HYBRID;
                opt.min_refresh = options.external_refresh;
                opt.fast_refresh = options.fast_refresh;
                opt.max_refresh = options.max_refresh;
            } else {
                opt.strategy = iputils::CacheStrategy::FIXED;
                opt.min_refresh = options.external_refresh;
            }

            ext_result_ = iputils::GetExternalIPv4WithCountry(opt, force_external_refresh);
        }

        if (options.show_internal) {
            // 显示内网IP
            internal_ip_ = iputils::GetInternalIPv4(options.preferred_adapter);
            if (internal_ip_.empty()) internal_ip_ = L"N/A";
        } else if (options.show_external && ext_result_.IsValid() && !ext_result_.as_name.empty()) {
            // 内网关闭但外网开启时，在内网位置显示公司名称
            internal_ip_ = ext_result_.GetCompanyName();
        } else {
            internal_ip_.clear();
        }

        if (options.show_external) {
            if (ext_result_.IsValid()) {
                external_ip_ = ext_result_.GetDisplayString();
            } else {
                external_ip_ = L"N/A";
            }
        } else {
            external_ip_.clear();
        }
    }
```

（即：把原来声明在方法内部的 `iputils::IpWithCountry ext_result;` 整行删除，方法体里所有出现的 `ext_result.xxx` 都改成 `ext_result_.xxx`，其余代码逐字不变。）

在类的private成员区新增：
```cpp
    iputils::IpWithCountry ext_result_;  ///< 最近一次Update()获取到的外网IP详情，供claude_risk模块读取
```

新增两个public getter（放在 `RawValue()` 附近）：
```cpp
    /**
     * @brief 获取最近一次检测到的外网IP（原始值，不含国家代码前缀）
     */
    const std::wstring& ExternalIpRaw() const { return ext_result_.ip; }

    /**
     * @brief 获取最近一次检测到的外网IP对应国家代码
     */
    const std::wstring& ExternalCountryRaw() const { return ext_result_.country; }
```

- [ ] **Step 2: 构建确认编译通过**

Run: `msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64`
Expected: `Build succeeded.`

- [ ] **Step 3: 在 `src/plugin.cpp` 顶部新增include**

```diff
 #include "plugin.h"
 #include <Shlwapi.h>
 #include "options_dialog.h"
+#include "claude_risk.h"
```

- [ ] **Step 4: 修改 `IpPluginItem::GetItemWidth()`，开启风险检测时多预留空间给紧凑标记**

```cpp
int IpPluginItem::GetItemWidth() const {
    int base = 120;
    if (provider_ && provider_->GetOptions().enable_claude_risk_check) {
        base += 14; // 多预留一个字符宽度给紧凑风险标记（⚠）
    }
    return base;
}
```

- [ ] **Step 5: 修改 `IpPluginItem::DrawItem()`，外网IP行追加紧凑标记**

在现有"绘制外网IP（如果存在）"代码块中，把直接绘制 `external_ip_` 改为绘制一个本地拼接好后缀的字符串：

```diff
     // 绘制外网IP（如果存在）
     if (!external_ip_.empty()) {
-        RECT rect = {x, currentY, x + w, currentY + lineHeight};
-        ::DrawText(dc, external_ip_.c_str(), -1, &rect, 
-                  DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
+        std::wstring display = external_ip_;
+        if (provider_ && provider_->GetOptions().enable_claude_risk_check) {
+            auto risk = claude_risk::GetClaudeRiskSnapshot();
+            if (risk.valid && risk.HasAnyRisk()) display += L" ⚠"; // ⚠
+        }
+        RECT rect = {x, currentY, x + w, currentY + lineHeight};
+        ::DrawText(dc, display.c_str(), -1, &rect,
+                  DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
         currentY += lineHeight;
     }
```

注意：`provider_` 在 `IpPluginItem` 中是private成员，`DrawItem`是该类的成员函数，可以直接访问，无需新增getter。

- [ ] **Step 6: 构建确认编译通过**

Run: `msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64`
Expected: `Build succeeded.`

- [ ] **Step 7: Commit**

```bash
git add src/plugin.h src/plugin.cpp
git commit -m "IpPluginItem暴露外网IP/国家getter，自绘加入风险紧凑标记"
```

---

### Task 11: `TMIpPlugin` 接入刷新触发、tooltip风险段落、INI读写

**Files:**
- Modify: `src/plugin.h`
- Modify: `src/plugin.cpp`

- [ ] **Step 1: 在 `src/plugin.h` 的 `TMIpPlugin` 私有方法区新增声明**

```diff
 private:
     // === 私有辅助方法 ===
     void LoadOptions();                                                           ///< 从配置文件加载选项
     void SaveOptions();                                                           ///< 保存选项到配置文件
+    void AppendClaudeRiskTooltip();                                               ///< 在tooltip_末尾追加Claude风险检测段落
+    void ShowClaudeRiskReport(HWND hWnd);                                         ///< 弹窗展示完整Claude风险报告
```

- [ ] **Step 2: 修改 `src/plugin.cpp` 中的 `TMIpPlugin::DataRequired()`**

完整替换为：

```cpp
void TMIpPlugin::DataRequired() {
    text_provider_.SetOptions(options_);
    bool force_refresh_requested = force_refresh_next_;
    item_.Update(force_refresh_next_);
    force_refresh_next_ = false;

    if (options_.enable_claude_risk_check) {
        claude_risk::RequestClaudeRiskRefreshAsync(
            config_dir_, item_.ExternalIpRaw(), item_.ExternalCountryRaw(), force_refresh_requested);
    }

    const auto& v = item_.RawValue();

    // 确保即使值为空也能提供有意义的显示
    if (v.empty()) {
        // 如果值为空，设置一个默认提示
        if (options_.show_internal && options_.show_external) {
            tooltip_ = L"内网: N/A\n外网: N/A";
        } else if (options_.show_internal) {
            tooltip_ = L"内网: N/A";
        } else if (options_.show_external) {
            tooltip_ = L"外网: N/A";
        } else {
            tooltip_ = L"请在选项中启用IP显示";
        }
        AppendClaudeRiskTooltip();
        return;
    }

    if (options_.show_internal && options_.show_external) {
        // Split for tooltip if both enabled
        std::wstring internal, external;
        size_t pos = v.find(options_.separator);
        if (pos != std::wstring::npos) {
            internal = v.substr(0, pos);
            external = v.substr(pos + options_.separator.size());
        } else {
            internal = v;
        }
        tooltip_.clear();
        if (!internal.empty()) {
            tooltip_ += L"内网: ";
            tooltip_ += internal;
        }
        if (!external.empty()) {
            if (!tooltip_.empty()) tooltip_ += L"\n";
            tooltip_ += L"外网: ";
            tooltip_ += external;
        }
    } else if (options_.show_internal) {
        tooltip_ = L"内网: ";
        tooltip_ += v;
    } else if (options_.show_external) {
        tooltip_ = L"外网: ";
        tooltip_ += v;
    } else {
        tooltip_ = L"请在选项中启用IP显示";
    }

    AppendClaudeRiskTooltip();
}
```

- [ ] **Step 3: 新增 `AppendClaudeRiskTooltip()` 实现（追加到 `plugin.cpp` 末尾，`TMPluginGetInstance` 之前任意位置）**

```cpp
void TMIpPlugin::AppendClaudeRiskTooltip() {
    if (!options_.enable_claude_risk_check) return;

    auto risk = claude_risk::GetClaudeRiskSnapshot();
    if (!tooltip_.empty()) tooltip_ += L"\n";
    tooltip_ += L"——Claude IP风险——";

    if (!risk.valid) {
        tooltip_ += L"\n检测中…";
        return;
    }

    tooltip_ += L"\n出口对比: ";
    if (!risk.cf_trace_ok) {
        tooltip_ += L"未知（请求失败）";
    } else if (risk.ip_mismatch) {
        tooltip_ += L"不一致，可能存在分流代理";
    } else {
        tooltip_ += L"一致";
        if (!risk.cf_colo.empty()) {
            tooltip_ += L" (";
            tooltip_ += risk.cf_colo;
            tooltip_ += L"机房)";
        }
    }

    tooltip_ += L"\n受限地区: ";
    if (risk.country_restricted) {
        tooltip_ += L"命中：";
        tooltip_ += risk.restricted_country_code;
        tooltip_ += L"（仅供参考）";
    } else {
        tooltip_ += L"未命中";
    }

    tooltip_ += L"\n直连Claude: ";
    switch (risk.direct_reachability) {
        case claude_risk::Reachability::Reachable: tooltip_ += L"可达"; break;
        case claude_risk::Reachability::Blocked: tooltip_ += L"被屏蔽(403)"; break;
        default: tooltip_ += L"未知"; break;
    }

    tooltip_ += L"\n风险属性: ";
    if (!risk.risk_query_ok) {
        tooltip_ += L"未知（查询失败）";
    } else if (risk.is_proxy || risk.is_hosting) {
        tooltip_ += L"疑似";
        if (risk.is_proxy) tooltip_ += L"代理/VPN ";
        if (risk.is_hosting) tooltip_ += L"机房IP";
    } else {
        tooltip_ += L"无明显风险";
    }

    tooltip_ += L"\nIP波动: 近30天";
    tooltip_ += std::to_wstring(risk.distinct_ip_count_30d);
    tooltip_ += L"个IP";
    switch (risk.rotation_level) {
        case claude_risk::RotationLevel::Notice: tooltip_ += L"（注意）"; break;
        case claude_risk::RotationLevel::Warning: tooltip_ += L"（警告）"; break;
        case claude_risk::RotationLevel::Severe: tooltip_ += L"（严重警告）"; break;
        default: break;
    }
}

void TMIpPlugin::ShowClaudeRiskReport(HWND hWnd) {
    if (!options_.enable_claude_risk_check) {
        MessageBoxW(hWnd, L"请先在插件设置中启用\"Claude IP风险检测\"。",
                    L"Claude IP风险详情", MB_OK | MB_ICONINFORMATION);
        return;
    }

    auto risk = claude_risk::GetClaudeRiskSnapshot();
    std::wstring report;
    if (!risk.valid) {
        report = L"检测中，请稍后重试。";
    } else {
        report = L"出口IP(Cloudflare视角): " + (risk.cf_ip.empty() ? L"未知" : risk.cf_ip) + L"\n";
        report += L"机房代号: " + (risk.cf_colo.empty() ? L"未知" : risk.cf_colo) + L"\n";
        report += L"与本机检测外网IP是否一致: " + std::wstring(risk.ip_mismatch ? L"不一致" : L"一致") + L"\n";
        report += L"受限地区: ";
        report += risk.country_restricted ? (L"命中 " + risk.restricted_country_code) : L"未命中";
        report += L"\n直连api.anthropic.com: ";
        switch (risk.direct_reachability) {
            case claude_risk::Reachability::Reachable: report += L"可达"; break;
            case claude_risk::Reachability::Blocked: report += L"被屏蔽(HTTP 403)"; break;
            default: report += L"未知"; break;
        }
        report += L"\nVPN/代理: ";
        report += risk.is_proxy ? L"是" : L"否";
        report += L"\n机房/数据中心: ";
        report += risk.is_hosting ? L"是" : L"否";
        report += L"\n移动网络: ";
        report += risk.is_mobile ? L"是" : L"否";
        report += L"\n近30天出现过的不同外网IP数: " + std::to_wstring(risk.distinct_ip_count_30d);
        report += L"\n\n注：受限地区名单与直连探测逻辑均为社区经验整理，不代表Anthropic官方实时政策，仅供参考。";
    }

    MessageBoxW(hWnd, report.c_str(), L"Claude IP风险详情", MB_OK | MB_ICONINFORMATION);
}
```

- [ ] **Step 4: 在 `src/plugin.h` 中把 `GetCommandCount()` 从3改为4**

```diff
-    int GetCommandCount() override { return 3; }                                 ///< 命令数量（3个：切换内网、切换外网、强制刷新）
+    int GetCommandCount() override { return 4; }                                 ///< 命令数量（4个：切换内网、切换外网、强制刷新、查看Claude IP风险详情）
```

- [ ] **Step 5: 修改 `src/plugin.cpp` 中的 `GetCommandName` 与 `OnPluginCommand`**

```diff
 const wchar_t* TMIpPlugin::GetCommandName(int command_index) {
     switch (command_index) {
     case 0: return L"显示内网IP"; // toggle
     case 1: return L"显示外网IP"; // toggle
     case 2: return L"刷新外网IP"; // one-shot refresh
+    case 3: return L"查看Claude IP风险详情";
     default: return L"";
     }
 }
 
-void TMIpPlugin::OnPluginCommand(int command_index, void* /*hWnd*/, void* /*para*/) {
+void TMIpPlugin::OnPluginCommand(int command_index, void* hWnd, void* /*para*/) {
     switch (command_index) {
     case 0:
         options_.show_internal = !options_.show_internal;
         SaveOptions();
         break;
     case 1:
         options_.show_external = !options_.show_external;
         SaveOptions();
         break;
     case 2:
         force_refresh_next_ = true;
         break;
+    case 3:
+        ShowClaudeRiskReport((HWND)hWnd);
+        break;
     default:
         break;
     }
 }
```

- [ ] **Step 6: 修改 `LoadOptions`/`SaveOptions` 读写新INI键**

```diff
         GetPrivateProfileStringW(L"ip", L"separator", L" | ", buf, (DWORD)std::size(buf), ini.c_str());
         options_.separator = buf;
+
+        options_.enable_claude_risk_check = GetPrivateProfileIntW(
+            L"ip", L"enable_claude_risk_check", options_.enable_claude_risk_check ? 1 : 0, ini.c_str()) != 0;
     }
 }
```

```diff
     WritePrivateProfileStringW(L"ip", L"separator", options_.separator.c_str(), ini.c_str());
+    WritePrivateProfileStringW(L"ip", L"enable_claude_risk_check",
+                                options_.enable_claude_risk_check ? L"1" : L"0", ini.c_str());
 }
```

- [ ] **Step 7: 构建Debug确认编译通过**

Run: `msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64`
Expected: `Build succeeded.`

- [ ] **Step 8: Commit**

```bash
git add src/plugin.h src/plugin.cpp
git commit -m "接入Claude IP风险检测的刷新触发、tooltip展示与右键菜单命令"
```

---

### Task 12: Release构建 + PluginTester手动验证

**Files:** 无代码修改，仅验证

- [ ] **Step 1: 构建Release x64**

Run: `msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Release /p:Platform=x64`
Expected: `Build succeeded.`，输出 `bin\x64\Release\TrafficMonitorIpPlugin.dll`

- [ ] **Step 2: 用PluginTester加载Debug DLL，确认Debug自检无断言**

在Visual Studio中启动（调试模式）`PluginTester` 项目，加载 `bin\x64\Debug\TrafficMonitorIpPlugin.dll`。
Expected: 无assert弹窗（Task 2-5写的所有断言全部通过）。

- [ ] **Step 3: 在设置对话框中勾选"启用Claude IP风险检测"，确认能保存**

在PluginTester里打开插件选项对话框，勾选新增的"启用Claude IP风险检测"，点确定，重新打开对话框确认勾选状态被保存（同时检查`%TrafficMonitor%`配置目录或PluginTester的等效配置目录下 `tm_ip_plugin.ini` 中出现 `enable_claude_risk_check=1`）。

- [ ] **Step 4: 等待一次数据刷新周期，检查tooltip是否出现"——Claude IP风险——"段落**

需要真实网络环境。悬浮查看插件提示文本，确认五项检测结果都有展示（哪怕个别项因网络环境显示"未知"也算预期，只要不崩溃、文本不乱码）。

- [ ] **Step 5: 触发右键菜单"查看Claude IP风险详情"，确认弹窗内容正常、中文无乱码**

- [ ] **Step 6: 检查插件配置目录下是否生成了 `tm_ip_plugin_iphistory.log`，内容格式是否为 `时间戳|IP|国家代码` 每行一条**

- [ ] **Step 7: 关闭"启用Claude IP风险检测"，确认任务栏自绘区域宽度恢复、tooltip不再出现风险段落、右键菜单第4项弹出"请先启用"提示**

- [ ] **Step 8: 如发现问题，记录现象并修复对应Task的代码，重新构建验证，再继续**

---

### Task 13: 更新README，新增功能说明与参考致谢

**Files:**
- Modify: `README.md`

- [ ] **Step 1: 在"主要功能"列表中追加一项**

```diff
 - **网络优先级**：智能选择最佳内网IP（192.168.x.x > 10.x.x.x > 172.16-31.x.x）
+- **Claude IP风险检测**（可选，默认关闭）：对比Cloudflare出口IP、检测受限地区、探测Claude直连可达性、识别VPN/代理/机房IP、追踪30天IP波动
```

- [ ] **Step 2: 在"右键菜单命令"列表追加一项**

```diff
 - **刷新外网IP**：立即强制刷新
+- **查看Claude IP风险详情**：弹窗展示完整的Claude IP风险检测报告（需先在设置中启用该功能）
```

- [ ] **Step 3: 新增"Claude IP风险检测"小节（放在"⚙️ 配置选项"之前）**

```markdown
## 🔍 Claude IP风险检测（可选功能）

默认关闭，需在插件设置中勾选"启用Claude IP风险检测"。启用后会增加以下检测，结果显示在悬浮提示和右键菜单"查看Claude IP风险详情"中：

| 检测项 | 说明 |
|--------|------|
| Cloudflare出口对比 | 请求 `claude.ai/cdn-cgi/trace`，对比Cloudflare看到的出口IP与本机检测到的外网IP是否一致，用于发现分流代理 |
| 受限地区检测 | 将出口国家代码与Anthropic受限地区/OFAC制裁名单比对，仅提示不拦截 |
| 直连可达性探测 | 对`api.anthropic.com`发起一次轻量探测请求（使用占位假Key，不消耗真实账号），判断网络层是否被屏蔽 |
| VPN/代理/机房风险 | 通过`ip-api.com`查询当前外网IP是否为VPN/代理/数据中心/移动网络出口 |
| IP波动追踪 | 本地记录外网IP变化历史，统计近30天出现过的不同IP数量并分级提示 |

**已知取舍**：
- VPN/代理/机房风险查询走明文HTTP（`ip-api.com`免费版不支持HTTPS），不涉及账号密钥等敏感信息，纯展示用途。
- 受限地区名单与直连探测的判定逻辑均为社区经验整理，不代表Anthropic官方实时政策，仅供参考。
- 该功能会引入额外的后台网络请求和一个后台线程，默认关闭，需用户主动启用。
```

- [ ] **Step 4: 在"💾 配置文件"的INI示例中追加新键**

```diff
 enable_smart_cache=1           # 启用智能缓存
 fast_refresh_seconds=30        # 快速刷新间隔
 max_refresh_minutes=15         # 最大刷新间隔
+enable_claude_risk_check=0     # 启用Claude IP风险检测（默认关闭）
 ```

- [ ] **Step 5: 在文档末尾"开发者信息"之前新增"参考与致谢"小节**

```markdown
## 🙏 参考与致谢

"Claude IP风险检测"功能的设计参考了以下项目，特此致谢：

- [ip.net.coffee/claude](https://ip.net.coffee/claude/) —— Cloudflare出口IP对比思路的灵感来源
- [cso1z/claude-ip-guard](https://github.com/cso1z/claude-ip-guard)（MIT License）—— 受限地区名单、直连可达性探测方法、IP波动分级阈值参考自该项目
```

- [ ] **Step 6: 在"项目结构"小节追加新文件**

```diff
 - `src/ip_utils.h/.cpp`：IP获取和智能缓存逻辑
+- `src/claude_risk.h/.cpp`：Claude IP风险检测逻辑（Cloudflare对比、受限地区、直连探测、VPN/代理识别、IP波动追踪）
 - `src/plugin_options.h`：用户配置选项定义
```

- [ ] **Step 7: Commit**

```bash
git add README.md
git commit -m "README新增Claude IP风险检测功能说明与参考致谢"
```

---

## 完成标准

- [ ] Debug x64 与 Release x64 均能成功构建
- [ ] PluginTester加载Debug DLL时不触发任何Debug自检assert
- [ ] 设置对话框新勾选框可正常保存/读取，INI文件出现新键
- [ ] 启用功能后tooltip出现"——Claude IP风险——"段落，五项检测结果均有文本展示（即使部分为"未知"）
- [ ] 右键菜单新增命令可正常弹窗，未启用时给出友好提示
- [ ] 关闭功能后界面/tooltip/菜单行为恢复原状，不残留风险相关UI
- [ ] README已更新功能说明、配置项、参考致谢
- [ ] 所有任务均已按步骤commit
