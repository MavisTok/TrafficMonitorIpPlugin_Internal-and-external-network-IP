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

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) return L"";
    int wlen = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), (int)value.size(), nullptr, 0);
    if (wlen <= 0) return L"";
    std::wstring wvalue(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), (int)value.size(),
                         const_cast<wchar_t*>(wvalue.data()), wlen);
    return wvalue;
}

std::string ExtractJsonString(const std::string& json, const std::string& field) {
    std::string pattern = "\"" + field + "\"";
    size_t start = json.find(pattern);
    if (start == std::string::npos) return "";
    start += pattern.length();
    while (start < json.length() && (json[start] == ':' || json[start] == ' ' || json[start] == '\t')) start++;
    if (start >= json.length() || json[start] != '"') return "";
    start++;

    std::string value;
    bool escaped = false;
    for (size_t i = start; i < json.length(); ++i) {
        char ch = json[i];
        if (escaped) {
            value.push_back(ch);
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == '"') return value;
        value.push_back(ch);
    }
    return "";
}

std::wstring ParseIpInfoOrgFieldImpl(const std::string& json) {
    return Utf8ToWide(ExtractJsonString(json, "org"));
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

std::wstring ParseIpInfoOrgField(const std::string& json) {
    return ParseIpInfoOrgFieldImpl(json);
}

namespace {
// 名单来源：https://github.com/cso1z/claude-ip-guard (MIT License)
// 综合Anthropic官方支持地区与OFAC出口管制名单整理，社区版本，仅供参考。
const wchar_t* const kRestrictedCountries[] = {
    L"CN", L"RU", L"KP", L"IR", L"SY", L"CU", L"BY", L"VE", L"MM",
    L"LY", L"SO", L"YE", L"ML", L"CF", L"SS", L"CD", L"ER", L"AF", L"UA"
};
} // anonymous namespace

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

RotationLevel ComputeRotationLevel(int distinct_ip_count) {
    if (distinct_ip_count >= 7) return RotationLevel::Severe;
    if (distinct_ip_count >= 4) return RotationLevel::Warning;
    if (distinct_ip_count >= 2) return RotationLevel::Notice;
    return RotationLevel::None;
}

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

    // 1. Cloudflare出口信息（纯展示，不参与风险判定）
    auto trace = HttpRequest(L"claude.ai", L"/cdn-cgi/trace", true, L"GET", {}, "", 5000);
    if (trace.ok && trace.status_code == 200) {
        info.cf_trace_ok = true;
        info.cf_ip = ParseTraceField(trace.body, "ip");
        info.cf_colo = ParseTraceField(trace.body, "colo");
        info.cf_loc = ParseTraceField(trace.body, "loc");
        info.cf_warp = (ParseTraceField(trace.body, "warp") == L"on");
    }

    if (!info.cf_ip.empty()) {
        std::wstring path = L"/" + info.cf_ip + L"/json";
        auto ipinfo = HttpRequest(L"ipinfo.io", path, true, L"GET", {}, "", 5000);
        if (ipinfo.ok && ipinfo.status_code == 200) {
            info.cf_as_name = ParseIpInfoOrgField(ipinfo.body);
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

} // namespace claude_risk

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

    // --- IsRestrictedCountry ---
    {
        assert(IsRestrictedCountry(L"CN") == true);
        assert(IsRestrictedCountry(L"cn") == true);  // 大小写不敏感
        assert(IsRestrictedCountry(L"RU") == true);
        assert(IsRestrictedCountry(L"UA") == true);  // 名单最后一项
        assert(IsRestrictedCountry(L"US") == false);
        assert(IsRestrictedCountry(L"") == false);
    }

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

    // --- ParseIpInfoOrgField ---
    {
        std::string sample =
            "{\"ip\":\"69.63.196.167\",\"country\":\"US\","
            "\"org\":\"AS13335 Cloudflare, Inc.\"}";
        assert(ParseIpInfoOrgField(sample) == L"AS13335 Cloudflare, Inc.");
    }

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
}

struct SelfTestRunner {
    SelfTestRunner() { RunSelfTests(); }
};
static SelfTestRunner g_self_test_runner;

} // anonymous namespace
} // namespace claude_risk
#endif // _DEBUG
