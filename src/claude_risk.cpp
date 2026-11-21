/**
 * @file claude_risk.cpp
 * @brief Claude IP风险检测模块实现
 * @author Lynn
 * @date 2026
 */
#pragma execution_character_set("utf-8")

#include "claude_risk.h"
#include "claude_risk_parse.h"
#include "winhttp_proxy.h"

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
    using winhttp_proxy::InternetHandle;
    InternetHandle session(WinHttpOpen(L"TrafficMonitorIpPlugin/1.0",
                                      WINHTTP_ACCESS_TYPE_NO_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session || !WinHttpSetTimeouts(session.get(), timeout_ms, timeout_ms,
                                       timeout_ms, timeout_ms)) return result;

    const INTERNET_PORT port = use_https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    InternetHandle connection(WinHttpConnect(session.get(), host.c_str(), port, 0));
    if (!connection) return result;
    InternetHandle request(WinHttpOpenRequest(connection.get(), method.c_str(), path.c_str(), nullptr,
                                              WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                              use_https ? WINHTTP_FLAG_SECURE : 0));
    if (!request) return result;
    const std::wstring url = (use_https ? L"https://" : L"http://") + host + path;
    winhttp_proxy::ApplyCurrentUserProxyForRequest(request.get(), url.c_str());

    std::wstring header_blob;
    for (const auto& header : headers) header_blob += header.first + L": " + header.second + L"\r\n";
    LPVOID send_data = body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data();
    const DWORD send_len = static_cast<DWORD>(body.size());
    if (!WinHttpSendRequest(request.get(),
                            header_blob.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : header_blob.c_str(),
                            static_cast<DWORD>(-1L), send_data, send_len, send_len, 0) ||
        !WinHttpReceiveResponse(request.get(), nullptr)) return result;

    DWORD status = 0, status_size = sizeof(status);
    if (!WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_FLAG_NUMBER | WINHTTP_QUERY_STATUS_CODE,
                              WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                              WINHTTP_NO_HEADER_INDEX)) return result;
    result.status_code = static_cast<int>(status);
    constexpr std::size_t kMaximumResponseBytes = 64u * 1024u;
    std::string data;
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.get(), &available)) return result;
        if (available == 0) break;
        if (available > kMaximumResponseBytes - data.size()) return result;
        const std::size_t old = data.size();
        data.resize(old + available);
        DWORD read = 0;
        if (!WinHttpReadData(request.get(), &data[old], available, &read) || read == 0) return result;
        data.resize(old + read);
    }
    result.body = std::move(data);
    result.ok = true;
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

struct RefreshArguments {
    std::wstring config_dir;
    std::wstring external_ip;
    std::wstring external_country;
};

struct RefreshState {
    std::mutex mutex;
    ClaudeRiskInfo cached;
    std::chrono::steady_clock::time_point last_refresh{};
    std::wstring last_checked_ip;
    bool refresh_in_flight = false;
    bool forced_pending = false;
    bool rerun_consumed = false;
    bool shutdown_requested = false;
    RefreshArguments pending_arguments;
    std::thread worker;
};

RefreshState& SharedState() {
    // The plugin owns shutdown. Do not destroy a joinable thread at CRT detach.
    static RefreshState* state = new RefreshState;
    return *state;
}

bool ShutdownRequested() {
    RefreshState& state = SharedState();
    std::lock_guard<std::mutex> lock(state.mutex);
    return state.shutdown_requested;
}

constexpr auto kRefreshInterval = std::chrono::minutes(30);

bool DoRefresh(const RefreshArguments& arguments, ClaudeRiskInfo& info) {
    const auto& config_dir = arguments.config_dir;
    const auto& external_ip = arguments.external_ip;
    const auto& external_country = arguments.external_country;
    if (ShutdownRequested()) return false;
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

    if (ShutdownRequested()) return false;
    if (!info.cf_ip.empty()) {
        std::wstring path = L"/" + info.cf_ip + L"/json";
        auto ipinfo = HttpRequest(L"ipinfo.io", path, true, L"GET", {}, "", 5000);
        if (ipinfo.ok && ipinfo.status_code == 200) {
            info.cf_as_name = ParseIpInfoOrgField(ipinfo.body);
        }
    }

    if (ShutdownRequested()) return false;

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

    if (ShutdownRequested()) return false;

    // 4. VPN/代理/机房风险（ip-api.com，明文HTTP——免费版限制，已知取舍）
    if (!external_ip.empty()) {
        std::wstring path = L"/json/" + external_ip + L"?fields=status,proxy,hosting,mobile";
        auto risk = HttpRequest(L"ip-api.com", path, false, L"GET", {}, "", 5000);
        if (risk.ok && risk.status_code == 200) {
            RiskFlags flags;
            if (ParseRiskResponse(risk.body, flags)) {
                info.is_proxy = flags.proxy;
                info.is_hosting = flags.hosting;
                info.is_mobile = flags.mobile;
                info.risk_query_ok = true;
            }
        }
    }

    if (ShutdownRequested()) return false;

    // 5. IP波动追踪
    if (!external_ip.empty()) {
        info.distinct_ip_count_30d = UpdateAndCountHistory(config_dir, external_ip, external_country);
        info.rotation_level = ComputeRotationLevel(info.distinct_ip_count_30d);
    }

    info.valid = true;
    return true;
}

void RefreshWorker(RefreshArguments arguments) {
    RefreshState& state = SharedState();
    try {
        for (;;) {
            ClaudeRiskInfo info;
            bool completed = false;
            try {
                completed = DoRefresh(arguments, info);
            } catch (...) {
                // A failed allocation or parser must not terminate the host process.
            }
            std::lock_guard<std::mutex> lock(state.mutex);
            if (completed && !state.shutdown_requested) state.cached = std::move(info);
            if (!state.shutdown_requested && state.forced_pending && !state.rerun_consumed) {
                arguments = std::move(state.pending_arguments);
                state.forced_pending = false;
                state.rerun_consumed = true;
                state.last_checked_ip = arguments.external_ip;
                state.last_refresh = std::chrono::steady_clock::now();
                continue;
            }
            state.refresh_in_flight = false;
            state.forced_pending = false;
            if (!completed) state.last_refresh = {};
            return;
        }
    } catch (...) {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.refresh_in_flight = false;
        state.forced_pending = false;
        state.last_refresh = {};
    }
}

} // anonymous namespace

ClaudeRiskInfo GetClaudeRiskSnapshot() {
    RefreshState& state = SharedState();
    std::lock_guard<std::mutex> lock(state.mutex);
    return state.cached;
}

void RequestClaudeRiskRefreshAsync(const std::wstring& config_dir,
                                    const std::wstring& current_external_ip,
                                    const std::wstring& current_country,
                                    bool force_refresh) {
    RefreshState& state = SharedState();
    std::thread previous_worker;
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        if (state.shutdown_requested) return;
        const auto now = std::chrono::steady_clock::now();
        const bool ip_changed = !current_external_ip.empty() && current_external_ip != state.last_checked_ip;
        if (state.refresh_in_flight) {
            if ((force_refresh || ip_changed) && !state.rerun_consumed) {
                state.pending_arguments = {config_dir, current_external_ip, current_country};
                state.forced_pending = true;
            }
            return;
        }
        const bool due = state.last_refresh.time_since_epoch().count() == 0
                      || now - state.last_refresh >= kRefreshInterval;
        if (!force_refresh && !ip_changed && !due) return;
        state.last_checked_ip = current_external_ip;
        if (state.worker.joinable()) previous_worker = std::move(state.worker);
        state.refresh_in_flight = true;
        state.forced_pending = false;
        state.rerun_consumed = false;
        state.last_refresh = now;
    }
    if (previous_worker.joinable()) previous_worker.join();
    std::lock_guard<std::mutex> lock(state.mutex);
    if (state.shutdown_requested) {
        state.refresh_in_flight = false;
        return;
    }
    try {
        // Publish the worker while holding the lock so shutdown cannot miss it.
        state.worker = std::thread(RefreshWorker,
                                  RefreshArguments{config_dir, current_external_ip, current_country});
    } catch (...) {
        state.refresh_in_flight = false;
        state.forced_pending = false;
        state.last_refresh = {};
    }
}

void ShutdownRefreshWorker() {
    RefreshState& state = SharedState();
    std::thread worker;
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.shutdown_requested = true;
        state.forced_pending = false;
        if (state.worker.joinable()) worker = std::move(state.worker);
    }
    // Explicit owner teardown only; do not call while holding the DLL loader lock.
    if (worker.joinable()) worker.join();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.refresh_in_flight = false;
}

} // namespace claude_risk
