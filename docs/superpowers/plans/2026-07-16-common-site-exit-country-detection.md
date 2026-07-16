# Common Site Exit Country Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in, persisted common-site exit-country detector that asynchronously reports Google, YouTube, OpenAI, Claude, GitHub, and Netflix countries in the TrafficMonitor tooltip.

**Architecture:** Add a focused `exit_detection` module containing response parsers, country presentation, WinHTTP probes, an immutable snapshot, and a mutex-protected ten-minute refresh state. Keep configuration and tooltip composition in the existing plugin layer. Add a standalone C++ test executable so every pure behavior can follow a visible red-green cycle without loading the DLL.

**Tech Stack:** C++17, WinHTTP, Win32 resource dialogs, MSBuild/Visual Studio 2022, assertion-based console tests.

---

## File map

- Create `src/exit_detection.h`: public site/result/snapshot types, pure parser/formatter APIs, refresh-decision API, and asynchronous snapshot API.
- Create `src/exit_detection.cpp`: pure logic, WinHTTP requests, site probes, cache, and worker thread.
- Create `tests/exit_detection_tests.cpp`: deterministic parser, formatting, and scheduler tests.
- Create `tests/ExitDetectionTests.vcxproj`: standalone x64 console test target linked with WinHTTP.
- Modify `TrafficMonitorIpPlugin.vcxproj` and `.filters`: compile the new production module.
- Modify `src/plugin_options.h`, `src/options_dialog.cpp`, `res/resource.h`, and `res/plugin.rc`: persisted default-off setting and checkbox.
- Modify `src/plugin.h` and `src/plugin.cpp`: refresh triggering and tooltip append.
- Modify `README.md`: user-facing behavior, refresh rules, sources, and limitations.

## Commands used throughout

Run from the repository root. If `msbuild` is not on `PATH`, replace it with:

```powershell
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe'
```

Test build and execution:

```powershell
msbuild tests\ExitDetectionTests.vcxproj /p:Configuration=Debug /p:Platform=x64
& tests\bin\x64\Debug\ExitDetectionTests.exe
```

Plugin builds:

```powershell
msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64
msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Release /p:Platform=x64
```

---

### Task 1: Establish the test target and response parsers

**Files:**
- Create: `tests/exit_detection_tests.cpp`
- Create: `tests/ExitDetectionTests.vcxproj`
- Create: `src/exit_detection.h`
- Create: `src/exit_detection.cpp`
- Modify: `TrafficMonitorIpPlugin.vcxproj`
- Modify: `TrafficMonitorIpPlugin.vcxproj.filters`

- [ ] **Step 1: Write the parser tests before the production module exists**

Create `tests/exit_detection_tests.cpp`:

```cpp
#include <cassert>
#include <iostream>
#include "../src/exit_detection.h"

using namespace exit_detection;

int main() {
    assert(NormalizeCountryCode(L"jp") == L"JP");
    assert(NormalizeCountryCode(L"USA").empty());
    assert(NormalizeCountryCode(L"1P").empty());
    assert(NormalizeCountryCode(L"").empty());

    assert(ParseGoogleMappingIp("203.0.113.7 => cache.googlevideo.com\n") == L"203.0.113.7");
    assert(ParseGoogleMappingIp("not-an-ip => cache\n").empty());

    assert(ParseYouTubeCountry(R"({"countryCode":"jp","premium":true})") == L"JP");
    assert(ParseYouTubeCountry(R"({"premium":true})").empty());

    assert(ParseTraceCountry("ip=203.0.113.8\nloc=sg\ncolo=SIN\n") == L"SG");
    assert(ParseTraceCountry("location=US\n").empty());

    assert(ParseNetflixCountry(R"({"id":"HK","countryName":"Hong Kong"})") == L"HK");
    assert(ParseNetflixCountry(R"({"countryName":"Hong Kong"})").empty());

    assert(ParseIpInfoCountry(R"({"ip":"203.0.113.7","country":"us"})") == L"US");
    assert(ParseIpInfoCountry(R"({"country":"USA"})").empty());

    assert(ParseGitHubCountry("server: github.com\r\nx-frame-options: deny\r\n").empty());
    assert(ParseGitHubCountry("x-github-country: ca\r\n") == L"CA");

    std::cout << "exit_detection parser tests passed\n";
    return 0;
}
```

- [ ] **Step 2: Create the standalone test project**

Create `tests/ExitDetectionTests.vcxproj` as a console application with `Debug|x64` and `Release|x64`, toolset `v145`, C++17, `/utf-8`, include path `$(ProjectDir)..\src`, sources `exit_detection_tests.cpp` and `..\src\exit_detection.cpp`, output `tests\bin\$(Platform)\$(Configuration)\`, and linker dependency `Winhttp.lib`.

The two source entries must be:

```xml
<ItemGroup>
  <ClCompile Include="exit_detection_tests.cpp" />
  <ClCompile Include="..\src\exit_detection.cpp" />
</ItemGroup>
```

The compiler and linker settings in both configurations must contain:

```xml
<ClCompile>
  <LanguageStandard>stdcpp17</LanguageStandard>
  <AdditionalOptions>/utf-8 %(AdditionalOptions)</AdditionalOptions>
  <PreprocessorDefinitions>WIN32;_WINDOWS;UNICODE;_UNICODE;NOMINMAX;WIN32_LEAN_AND_MEAN;%(PreprocessorDefinitions)</PreprocessorDefinitions>
</ClCompile>
<Link>
  <AdditionalDependencies>Winhttp.lib;%(AdditionalDependencies)</AdditionalDependencies>
</Link>
```

- [ ] **Step 3: Run RED and confirm the expected missing-header failure**

Run:

```powershell
msbuild tests\ExitDetectionTests.vcxproj /p:Configuration=Debug /p:Platform=x64
```

Expected: FAIL with `C1083` because `src/exit_detection.h` does not exist. This is the required red state.

- [ ] **Step 4: Add the public parser API**

Create `src/exit_detection.h`:

```cpp
#pragma once

#include <array>
#include <chrono>
#include <string>

namespace exit_detection {

enum class Site { Google, YouTube, OpenAI, Claude, GitHub, Netflix, Count };
enum class ResultState { Pending, Success, Unknown };

struct SiteResult {
    Site site = Site::Google;
    ResultState state = ResultState::Pending;
    std::wstring country_code;
};

struct Snapshot {
    bool has_completed = false;
    bool refresh_in_flight = false;
    std::array<SiteResult, static_cast<size_t>(Site::Count)> sites{};
};

enum class RefreshDecision { Skip, Start, QueueForced };

std::wstring NormalizeCountryCode(const std::wstring& value);
std::wstring ParseGoogleMappingIp(const std::string& body);
std::wstring ParseYouTubeCountry(const std::string& body);
std::wstring ParseTraceCountry(const std::string& body);
std::wstring ParseNetflixCountry(const std::string& body);
std::wstring ParseIpInfoCountry(const std::string& body);
std::wstring ParseGitHubCountry(const std::string& headers);

std::wstring CountryFlag(const std::wstring& country_code);
std::wstring CountryName(const std::wstring& country_code);
Snapshot MakeInitialSnapshot();
std::wstring FormatTooltip(const Snapshot& snapshot);

RefreshDecision EvaluateRefresh(bool has_completed,
                                bool refresh_in_flight,
                                std::chrono::steady_clock::duration age,
                                bool force_refresh);

Snapshot GetSnapshot();
void RequestRefreshAsync(bool force_refresh);

} // namespace exit_detection
```

- [ ] **Step 5: Implement only enough pure parsing to pass**

Create `src/exit_detection.cpp`. Use these exact parsing rules:

```cpp
#pragma execution_character_set("utf-8")
#include "exit_detection.h"

#include <algorithm>
#include <cctype>
#include <cwctype>

namespace exit_detection {
namespace {

std::string ExtractJsonString(const std::string& text, const std::string& field) {
    const std::string key = "\"" + field + "\"";
    size_t pos = text.find(key);
    if (pos == std::string::npos) return {};
    pos = text.find(':', pos + key.size());
    if (pos == std::string::npos) return {};
    pos = text.find('"', pos + 1);
    if (pos == std::string::npos) return {};
    size_t end = text.find('"', pos + 1);
    if (end == std::string::npos) return {};
    return text.substr(pos + 1, end - pos - 1);
}

std::wstring AsciiToWide(const std::string& value) {
    return std::wstring(value.begin(), value.end());
}

std::wstring ParseJsonCountry(const std::string& body, const std::string& field) {
    return NormalizeCountryCode(AsciiToWide(ExtractJsonString(body, field)));
}

bool IsIpv4(const std::string& value) {
    int parts = 0;
    size_t start = 0;
    while (start < value.size()) {
        size_t end = value.find('.', start);
        std::string part = value.substr(start, end == std::string::npos ? value.size() - start : end - start);
        if (part.empty() || part.size() > 3 || !std::all_of(part.begin(), part.end(), ::isdigit)) return false;
        int number = std::stoi(part);
        if (number < 0 || number > 255) return false;
        ++parts;
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return parts == 4;
}

} // namespace

std::wstring NormalizeCountryCode(const std::wstring& value) {
    if (value.size() != 2) return {};
    std::wstring result;
    for (wchar_t ch : value) {
        if (!((ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z'))) return {};
        result.push_back(static_cast<wchar_t>(std::towupper(ch)));
    }
    return result;
}

std::wstring ParseGoogleMappingIp(const std::string& body) {
    size_t end = body.find_first_of(" \t\r\n");
    std::string candidate = body.substr(0, end);
    return IsIpv4(candidate) ? AsciiToWide(candidate) : L"";
}

std::wstring ParseYouTubeCountry(const std::string& body) { return ParseJsonCountry(body, "countryCode"); }

std::wstring ParseTraceCountry(const std::string& body) {
    size_t start = 0;
    while (start < body.size()) {
        size_t end = body.find('\n', start);
        std::string line = body.substr(start, end == std::string::npos ? body.size() - start : end - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.rfind("loc=", 0) == 0) return NormalizeCountryCode(AsciiToWide(line.substr(4)));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return {};
}

std::wstring ParseNetflixCountry(const std::string& body) {
    size_t country_name = body.find("\"countryName\"");
    if (country_name == std::string::npos) return {};
    size_t id = body.rfind("\"id\"", country_name);
    if (id == std::string::npos) return {};
    return ParseJsonCountry(body.substr(id, country_name - id + 32), "id");
}

std::wstring ParseIpInfoCountry(const std::string& body) { return ParseJsonCountry(body, "country"); }

std::wstring ParseGitHubCountry(const std::string& headers) {
    std::string lower = headers;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    const std::string key = "x-github-country:";
    size_t pos = lower.find(key);
    if (pos == std::string::npos) return {};
    pos += key.size();
    while (pos < lower.size() && (lower[pos] == ' ' || lower[pos] == '\t')) ++pos;
    size_t end = lower.find_first_of("\r\n", pos);
    return NormalizeCountryCode(AsciiToWide(lower.substr(pos, end - pos)));
}

} // namespace exit_detection
```

- [ ] **Step 6: Add the module to the plugin project**

Add `src\exit_detection.cpp` to the `<ClCompile>` group and `src\exit_detection.h` to the `<ClInclude>` group in `TrafficMonitorIpPlugin.vcxproj`. Add matching “源文件” and “头文件” entries to `TrafficMonitorIpPlugin.vcxproj.filters`.

- [ ] **Step 7: Run GREEN**

Run the test build and executable. Expected output:

```text
exit_detection parser tests passed
```

- [ ] **Step 8: Commit**

```powershell
git add tests src/exit_detection.h src/exit_detection.cpp TrafficMonitorIpPlugin.vcxproj TrafficMonitorIpPlugin.vcxproj.filters
git commit -m "test: add exit detection parsers"
```

---

### Task 2: Add country presentation and aligned tooltip formatting

**Files:**
- Modify: `tests/exit_detection_tests.cpp`
- Modify: `src/exit_detection.cpp`

- [ ] **Step 1: Add failing presentation tests**

Before the final success message in `main()`, add:

```cpp
    assert(CountryFlag(L"HK") == L"🇭🇰");
    assert(CountryFlag(L"zz").empty());
    assert(CountryName(L"HK") == L"Hong Kong");
    assert(CountryName(L"JP") == L"Japan");
    assert(CountryName(L"US") == L"United States");
    assert(CountryName(L"ZZ") == L"ZZ");

    Snapshot pending = MakeInitialSnapshot();
    const std::wstring pending_text = FormatTooltip(pending);
    assert(pending_text.find(L"Google   → ⏳ Detecting...") != std::wstring::npos);
    assert(pending_text.find(L"YouTube  → ⏳ Detecting...") != std::wstring::npos);

    Snapshot ready = MakeInitialSnapshot();
    ready.has_completed = true;
    ready.sites[0] = {Site::Google, ResultState::Success, L"HK"};
    ready.sites[1] = {Site::YouTube, ResultState::Success, L"JP"};
    ready.sites[2] = {Site::OpenAI, ResultState::Success, L"US"};
    ready.sites[3] = {Site::Claude, ResultState::Success, L"SG"};
    ready.sites[4] = {Site::GitHub, ResultState::Unknown, L""};
    ready.sites[5] = {Site::Netflix, ResultState::Success, L"JP"};
    assert(FormatTooltip(ready) ==
        L"──────── 出口检测 ────────\n"
        L"Google   → 🇭🇰 Hong Kong\n"
        L"YouTube  → 🇯🇵 Japan\n"
        L"OpenAI   → 🇺🇸 United States\n"
        L"Claude   → 🇸🇬 Singapore\n"
        L"GitHub   → ❔ Unknown\n"
        L"Netflix  → 🇯🇵 Japan");
```

- [ ] **Step 2: Run RED**

Build the test project. Expected: linker failures for `CountryFlag`, `CountryName`, `MakeInitialSnapshot`, and `FormatTooltip`.

- [ ] **Step 3: Implement presentation**

In `src/exit_detection.cpp`, include `<windows.h>` and `<iterator>` and add:

```cpp
namespace {
const wchar_t* SiteName(Site site) {
    switch (site) {
    case Site::Google: return L"Google";
    case Site::YouTube: return L"YouTube";
    case Site::OpenAI: return L"OpenAI";
    case Site::Claude: return L"Claude";
    case Site::GitHub: return L"GitHub";
    case Site::Netflix: return L"Netflix";
    default: return L"";
    }
}

struct GeoLookupContext { std::wstring code; GEOID id = GEOID_NOT_AVAILABLE; };
thread_local GeoLookupContext* g_geo_lookup = nullptr;

BOOL CALLBACK FindGeoByIso2(GEOID id) {
    wchar_t iso2[8]{};
    if (g_geo_lookup && GetGeoInfoW(id, GEO_ISO2, iso2, static_cast<int>(std::size(iso2)), 0) > 0
        && g_geo_lookup->code == iso2) {
        g_geo_lookup->id = id;
        return FALSE;
    }
    return TRUE;
}
} // namespace

std::wstring CountryFlag(const std::wstring& country_code) {
    std::wstring code = NormalizeCountryCode(country_code);
    if (code.empty() || CountryName(code) == code) return {};
    std::wstring result;
    for (wchar_t ch : code) {
        unsigned int cp = 0x1F1E6u + static_cast<unsigned int>(ch - L'A');
        cp -= 0x10000u;
        result.push_back(static_cast<wchar_t>(0xD800u + (cp >> 10)));
        result.push_back(static_cast<wchar_t>(0xDC00u + (cp & 0x3FFu)));
    }
    return result;
}

std::wstring CountryName(const std::wstring& country_code) {
    std::wstring code = NormalizeCountryCode(country_code);
    if (code.empty()) return {};
    if (code == L"HK") return L"Hong Kong";
    GeoLookupContext context{code};
    g_geo_lookup = &context;
    EnumSystemGeoID(GEOCLASS_NATION, 0, FindGeoByIso2);
    g_geo_lookup = nullptr;
    if (context.id == GEOID_NOT_AVAILABLE) return code;
    wchar_t name[128]{};
    int length = GetGeoInfoW(context.id, GEO_FRIENDLYNAME, name,
                             static_cast<int>(std::size(name)),
                             MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US));
    return length > 0 ? std::wstring(name) : code;
}

Snapshot MakeInitialSnapshot() {
    Snapshot snapshot;
    for (size_t i = 0; i < snapshot.sites.size(); ++i) {
        snapshot.sites[i].site = static_cast<Site>(i);
    }
    return snapshot;
}

std::wstring FormatTooltip(const Snapshot& snapshot) {
    std::wstring text = L"──────── 出口检测 ────────";
    for (const SiteResult& result : snapshot.sites) {
        std::wstring name = SiteName(result.site);
        text += L"\n" + name + std::wstring(7 - name.size(), L' ') + L"  → ";
        if (!snapshot.has_completed || result.state == ResultState::Pending) {
            text += L"⏳ Detecting...";
        } else if (result.state != ResultState::Success) {
            text += L"❔ Unknown";
        } else {
            std::wstring flag = CountryFlag(result.country_code);
            std::wstring country = CountryName(result.country_code);
            text += flag.empty() ? country : flag + L" " + country;
        }
    }
    return text;
}
```

- [ ] **Step 4: Run GREEN and commit**

Run the test executable and confirm the success message, then:

```powershell
git add tests/exit_detection_tests.cpp src/exit_detection.cpp
git commit -m "feat: format exit country tooltip"
```

---

### Task 3: Implement the ten-minute scheduler and asynchronous site probes

**Files:**
- Modify: `tests/exit_detection_tests.cpp`
- Modify: `src/exit_detection.cpp`

- [ ] **Step 1: Add failing refresh-decision tests**

Add:

```cpp
    using namespace std::chrono;
    assert(EvaluateRefresh(false, false, seconds(0), false) == RefreshDecision::Start);
    assert(EvaluateRefresh(true, false, minutes(9), false) == RefreshDecision::Skip);
    assert(EvaluateRefresh(true, false, minutes(10), false) == RefreshDecision::Start);
    assert(EvaluateRefresh(true, false, minutes(1), true) == RefreshDecision::Start);
    assert(EvaluateRefresh(true, true, minutes(10), false) == RefreshDecision::Skip);
    assert(EvaluateRefresh(true, true, minutes(1), true) == RefreshDecision::QueueForced);
```

- [ ] **Step 2: Run RED**

Expected: linker failure for `EvaluateRefresh`.

- [ ] **Step 3: Implement the pure decision function and run GREEN**

```cpp
RefreshDecision EvaluateRefresh(bool has_completed,
                                bool refresh_in_flight,
                                std::chrono::steady_clock::duration age,
                                bool force_refresh) {
    if (refresh_in_flight) return force_refresh ? RefreshDecision::QueueForced : RefreshDecision::Skip;
    if (force_refresh || !has_completed || age >= std::chrono::minutes(10)) return RefreshDecision::Start;
    return RefreshDecision::Skip;
}
```

- [ ] **Step 4: Add the bounded WinHTTP helper**

Inside the anonymous namespace add `HttpResponse { bool ok; DWORD status; std::string body; std::string headers; }` and a `Get(host, path)` helper. It must:

- open a `WINHTTP_ACCESS_TYPE_DEFAULT_PROXY` session;
- set connect/send/receive timeouts to 3000/3000/5000 ms;
- use HTTPS and `WINHTTP_FLAG_SECURE`;
- send `User-Agent: TrafficMonitorIpPlugin/1.0` and `Accept-Language: en-US,en;q=0.9`;
- query numeric status and raw headers;
- read in chunks while rejecting bodies larger than 1 MiB;
- close every WinHTTP handle on all paths;
- report `ok=true` only for status 200-399 and a body within the limit.

Keep this helper private to `exit_detection.cpp`; tests exercise its parsers, not live internet.

- [ ] **Step 5: Implement one isolated detector per site**

Use these exact requests and parsers:

```cpp
std::wstring DetectGoogle() {
    HttpResponse mapping = Get(L"redirector.gvt1.com", L"/report_mapping?di=no");
    std::wstring ip = mapping.ok ? ParseGoogleMappingIp(mapping.body) : L"";
    if (ip.empty()) return {};
    HttpResponse geo = Get(L"ipinfo.io", L"/" + ip + L"/json");
    return geo.ok ? ParseIpInfoCountry(geo.body) : L"";
}

std::wstring DetectYouTube() {
    HttpResponse response = Get(L"www.youtube.com", L"/premium");
    return response.ok ? ParseYouTubeCountry(response.body) : L"";
}

std::wstring DetectOpenAI() {
    HttpResponse response = Get(L"chatgpt.com", L"/cdn-cgi/trace");
    return response.ok ? ParseTraceCountry(response.body) : L"";
}

std::wstring DetectClaude() {
    HttpResponse response = Get(L"claude.ai", L"/cdn-cgi/trace");
    return response.ok ? ParseTraceCountry(response.body) : L"";
}

std::wstring DetectGitHub() {
    HttpResponse response = Get(L"github.com", L"/");
    return response.ok ? ParseGitHubCountry(response.headers) : L"";
}

std::wstring DetectNetflix() {
    HttpResponse response = Get(L"www.netflix.com", L"/title/81280792");
    return response.ok ? ParseNetflixCountry(response.body) : L"";
}
```

Create `RunBatch()` from an array of these six functions. Each result is `Success` only when its normalized code is non-empty; otherwise it is `Unknown`.

- [ ] **Step 6: Implement snapshot publication and forced-request coalescing**

Add module globals:

```cpp
std::mutex g_mutex;
Snapshot g_snapshot = MakeInitialSnapshot();
std::chrono::steady_clock::time_point g_last_refresh{};
bool g_forced_refresh_pending = false;
```

`RequestRefreshAsync()` must evaluate under the mutex. `Skip` returns; `QueueForced` sets `g_forced_refresh_pending=true`; `Start` marks `refresh_in_flight=true` and launches one detached worker. The worker runs `RunBatch()`, publishes the full batch atomically, then checks `g_forced_refresh_pending`. If set, it clears the flag and runs exactly one more batch; otherwise it clears `refresh_in_flight` and exits. `GetSnapshot()` returns a locked copy.

- [ ] **Step 7: Run deterministic tests and build the DLL**

Run the test executable, then Debug plugin build. Expected: both exit 0.

- [ ] **Step 8: Commit**

```powershell
git add tests/exit_detection_tests.cpp src/exit_detection.cpp
git commit -m "feat: probe common site exit countries"
```

---

### Task 4: Add the persisted option and settings checkbox

**Files:**
- Modify: `src/plugin_options.h`
- Modify: `src/options_dialog.cpp`
- Modify: `res/resource.h`
- Modify: `res/plugin.rc`
- Modify: `src/plugin.cpp`

- [ ] **Step 1: Add a failing source-level persistence test**

Create `tests/verify_exit_option.ps1`:

```powershell
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$checks = @(
    @{ Path = 'src\plugin_options.h'; Pattern = 'enable_exit_detection\s*=\s*false' },
    @{ Path = 'res\resource.h'; Pattern = 'IDC_CHECK_EXIT_DETECTION' },
    @{ Path = 'res\plugin.rc'; Pattern = '启用常见网站出口检测' },
    @{ Path = 'src\options_dialog.cpp'; Pattern = 'IDC_CHECK_EXIT_DETECTION' },
    @{ Path = 'src\plugin.cpp'; Pattern = 'L"enable_exit_detection"' }
)
foreach ($check in $checks) {
    $content = Get-Content -Raw (Join-Path $root $check.Path)
    if ($content -notmatch $check.Pattern) {
        throw "Missing $($check.Pattern) in $($check.Path)"
    }
}
Write-Output 'exit detection option verification passed'
```

Run it before editing production files. Expected: FAIL because the symbols are absent.

- [ ] **Step 2: Add the default-off option**

In `PluginOptions` add:

```cpp
// === 常见网站出口检测 ===
bool enable_exit_detection = false;
```

- [ ] **Step 3: Add and persist the dialog control**

Define `IDC_CHECK_EXIT_DETECTION 1007`. Resize the dialog to height 180, add the checkbox at `(10, 115, 200, 12)`, and move the OK/Cancel buttons to y=145:

```rc
CONTROL "启用常见网站出口检测", IDC_CHECK_EXIT_DETECTION, "Button", BS_AUTOCHECKBOX | WS_TABSTOP, 10, 115, 200, 12
```

In `WM_INITDIALOG`, call:

```cpp
SetCheck(hDlg, IDC_CHECK_EXIT_DETECTION, s_opts->enable_exit_detection);
```

In `IDOK`, read it into `new_opts.enable_exit_detection` and include it in the `changed` expression.

- [ ] **Step 4: Load and save the INI value**

In `LoadOptions()`:

```cpp
options_.enable_exit_detection = GetPrivateProfileIntW(
    L"ip", L"enable_exit_detection", options_.enable_exit_detection ? 1 : 0, ini.c_str()) != 0;
```

In `SaveOptions()`:

```cpp
WritePrivateProfileStringW(L"ip", L"enable_exit_detection",
                           options_.enable_exit_detection ? L"1" : L"0", ini.c_str());
```

- [ ] **Step 5: Run GREEN**

Run `tests/verify_exit_option.ps1`, then Debug build. Expected: script exit 0 and build exit 0.

- [ ] **Step 6: Commit**

```powershell
git add src/plugin_options.h src/options_dialog.cpp res/resource.h res/plugin.rc src/plugin.cpp tests/verify_exit_option.ps1
git commit -m "feat: persist exit detection option"
```

---

### Task 5: Trigger refreshes and append the tooltip section

**Files:**
- Modify: `src/plugin.h`
- Modify: `src/plugin.cpp`
- Modify: `tests/verify_exit_option.ps1`

- [ ] **Step 1: Extend the source-level test before integration**

Append these checks to `tests/verify_exit_option.ps1` before its success output:

```powershell
$integrationChecks = @(
    @{ Path = 'src\plugin.h'; Pattern = 'AppendExitDetectionTooltip' },
    @{ Path = 'src\plugin.cpp'; Pattern = 'RequestRefreshAsync\(force_refresh_requested\)' },
    @{ Path = 'src\plugin.cpp'; Pattern = 'FormatTooltip' }
)
foreach ($check in $integrationChecks) {
    $content = Get-Content -Raw (Join-Path $root $check.Path)
    if ($content -notmatch $check.Pattern) {
        throw "Missing $($check.Pattern) in $($check.Path)"
    }
}
```

Run the script. Expected: FAIL.

- [ ] **Step 2: Add the tooltip helper declaration and include**

Include `exit_detection.h` in `plugin.cpp`. Add to `TMIpPlugin`:

```cpp
void AppendExitDetectionTooltip();
```

- [ ] **Step 3: Trigger asynchronous refresh from `DataRequired()`**

Immediately after the existing Claude refresh block add:

```cpp
if (options_.enable_exit_detection) {
    exit_detection::RequestRefreshAsync(force_refresh_requested);
}
```

This reuses both proxy-window-triggered refreshes and right-click manual refreshes without adding another command.

- [ ] **Step 4: Append the section on every tooltip construction path**

Implement:

```cpp
void TMIpPlugin::AppendExitDetectionTooltip() {
    if (!options_.enable_exit_detection) return;
    if (!tooltip_.empty()) tooltip_ += L"\n";
    tooltip_ += exit_detection::FormatTooltip(exit_detection::GetSnapshot());
}
```

Call it immediately after `AppendClaudeRiskTooltip()` in both the empty-value early-return path and the normal path. This guarantees the exit section is always last.

- [ ] **Step 5: Run GREEN and all builds**

Run the source verification, test executable, Debug build, and Release build. Expected: all exit 0.

- [ ] **Step 6: Commit**

```powershell
git add src/plugin.h src/plugin.cpp tests/verify_exit_option.ps1
git commit -m "feat: show exit countries in tooltip"
```

---

### Task 6: Document and perform end-to-end verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README**

Add a feature bullet, tooltip example, setting entry, INI example `enable_exit_detection=0`, and a dedicated section stating:

- the feature is default-off and persisted;
- it refreshes every 10 minutes and on proxy-window/manual refresh events;
- each site is isolated and failures show `Unknown`;
- Google uses its mapping response plus explicit-IP geolocation, YouTube/Netflix use site region data, OpenAI/Claude use Cloudflare trace;
- GitHub currently has no stable public client-country field and may remain `Unknown`;
- country flags depend on Windows glyph support.

- [ ] **Step 2: Run fresh automated verification**

```powershell
& tests\bin\x64\Debug\ExitDetectionTests.exe
& tests\verify_exit_option.ps1
msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64
msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Release /p:Platform=x64
git diff --check
```

Expected: parser/presentation/scheduler success message, verification script exit 0, both builds report zero errors, and `git diff --check` emits no errors.

- [ ] **Step 3: Run live smoke checks**

With exit detection enabled in PluginTester:

1. Hover the item while the first batch runs and confirm six aligned `Detecting...` rows.
2. Wait for completion and confirm successful rows show a flag and English country name.
3. Confirm GitHub displays `Unknown` when no trusted header exists.
4. Trigger “刷新外网IP” and confirm the old snapshot remains visible while refresh runs.
5. Toggle the option off/on, restart PluginTester, and confirm the stored choice persists.
6. Confirm the exit section is below the Claude section both when Claude risk is enabled and disabled.

- [ ] **Step 4: Inspect the native Tooltip alignment**

Verify that arrows appear aligned in the actual common-control Tooltip. If the proportional font makes ASCII padding visibly uneven, replace only the padding characters in `FormatTooltip()` with U+2007 figure spaces and update the exact formatter test string; do not change the data flow or add custom tooltip drawing outside the plugin API.

- [ ] **Step 5: Commit documentation and any verified alignment adjustment**

```powershell
git add README.md src/exit_detection.cpp tests/exit_detection_tests.cpp
git commit -m "docs: describe common site exit detection"
```

- [ ] **Step 6: Final requirement audit**

Compare the implementation against `docs/superpowers/specs/2026-07-16-common-site-exit-country-design.md` and confirm: default-off persisted switch, six fixed rows, flags plus countries only, aligned columns, ten-minute cache, forced refresh, old-snapshot retention, isolated unknown states, and GitHub honesty boundary.
