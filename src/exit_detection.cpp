#pragma execution_character_set("utf-8")
#include "exit_detection.h"

#include <Windows.h>
#include <winhttp.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <mutex>
#include <new>
#include <thread>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "Winhttp.lib")

namespace exit_detection {
namespace {

constexpr std::size_t kMaximumResponseBytes = 1024u * 1024u;
constexpr auto kRefreshInterval = std::chrono::minutes(10);

struct InternetHandleCloser {
    void operator()(void* handle) const noexcept {
        if (handle != nullptr) {
            WinHttpCloseHandle(handle);
        }
    }
};

using InternetHandle = std::unique_ptr<void, InternetHandleCloser>;

struct HttpResponse {
    bool ok = false;
    DWORD status = 0;
    std::string body;
    std::string headers;
};

wchar_t* DuplicateWideString(LPCWSTR value) {
    if (value == nullptr || *value == L'\0') {
        return nullptr;
    }
    const std::size_t length = wcslen(value);
    std::unique_ptr<wchar_t[]> copy(new (std::nothrow) wchar_t[length + 1]);
    if (!copy) {
        return nullptr;
    }
    wcscpy_s(copy.get(), length + 1, value);
    return copy.release();
}

void FreeProxyInfo(WINHTTP_PROXY_INFO& proxy_info) noexcept {
    delete[] proxy_info.lpszProxy;
    delete[] proxy_info.lpszProxyBypass;
    proxy_info = {};
}

void FreeIeProxyConfig(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG& ie_proxy) noexcept {
    if (ie_proxy.lpszAutoConfigUrl != nullptr) {
        GlobalFree(ie_proxy.lpszAutoConfigUrl);
    }
    if (ie_proxy.lpszProxy != nullptr) {
        GlobalFree(ie_proxy.lpszProxy);
    }
    if (ie_proxy.lpszProxyBypass != nullptr) {
        GlobalFree(ie_proxy.lpszProxyBypass);
    }
    ie_proxy = {};
}

struct ProxyInfoOwner {
    WINHTTP_PROXY_INFO value{};
    ~ProxyInfoOwner() { FreeProxyInfo(value); }
};

struct IeProxyConfigOwner {
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG value{};
    ~IeProxyConfigOwner() { FreeIeProxyConfig(value); }
};

bool BuildProxyInfoFromIeConfigForUrl(
    const WINHTTP_CURRENT_USER_IE_PROXY_CONFIG& ie_proxy,
    LPCWSTR url,
    WINHTTP_PROXY_INFO& proxy_info) {
    proxy_info = {};
    if (ie_proxy.lpszProxy != nullptr && *ie_proxy.lpszProxy != L'\0') {
        proxy_info.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        proxy_info.lpszProxy = DuplicateWideString(ie_proxy.lpszProxy);
        proxy_info.lpszProxyBypass = DuplicateWideString(ie_proxy.lpszProxyBypass);
        return proxy_info.lpszProxy != nullptr;
    }
    if (url == nullptr || *url == L'\0' ||
        (!ie_proxy.fAutoDetect && ie_proxy.lpszAutoConfigUrl == nullptr)) {
        return false;
    }

    WINHTTP_AUTOPROXY_OPTIONS options{};
    if (ie_proxy.fAutoDetect) {
        options.dwFlags |= WINHTTP_AUTOPROXY_AUTO_DETECT;
        options.dwAutoDetectFlags =
            WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
    }
    if (ie_proxy.lpszAutoConfigUrl != nullptr && *ie_proxy.lpszAutoConfigUrl != L'\0') {
        options.dwFlags |= WINHTTP_AUTOPROXY_CONFIG_URL;
        options.lpszAutoConfigUrl = ie_proxy.lpszAutoConfigUrl;
    }
    options.fAutoLogonIfChallenged = TRUE;

    InternetHandle session(WinHttpOpen(L"TrafficMonitorIpPlugin/1.0",
                                       WINHTTP_ACCESS_TYPE_NO_PROXY,
                                       WINHTTP_NO_PROXY_NAME,
                                       WINHTTP_NO_PROXY_BYPASS,
                                       0));
    if (!session) {
        return false;
    }

    WINHTTP_PROXY_INFO detected{};
    const bool found = !!WinHttpGetProxyForUrl(session.get(), url, &options, &detected);
    if (!found || detected.dwAccessType != WINHTTP_ACCESS_TYPE_NAMED_PROXY ||
        detected.lpszProxy == nullptr || *detected.lpszProxy == L'\0') {
        if (detected.lpszProxy != nullptr) GlobalFree(detected.lpszProxy);
        if (detected.lpszProxyBypass != nullptr) GlobalFree(detected.lpszProxyBypass);
        return false;
    }

    proxy_info.dwAccessType = detected.dwAccessType;
    proxy_info.lpszProxy = DuplicateWideString(detected.lpszProxy);
    proxy_info.lpszProxyBypass = DuplicateWideString(detected.lpszProxyBypass);
    GlobalFree(detected.lpszProxy);
    if (detected.lpszProxyBypass != nullptr) GlobalFree(detected.lpszProxyBypass);
    return proxy_info.lpszProxy != nullptr;
}

bool ApplyCurrentUserProxyForRequest(HINTERNET request, LPCWSTR url) {
    IeProxyConfigOwner ie_proxy;
    if (!WinHttpGetIEProxyConfigForCurrentUser(&ie_proxy.value)) {
        return false;
    }
    ProxyInfoOwner proxy_info;
    if (!BuildProxyInfoFromIeConfigForUrl(ie_proxy.value, url, proxy_info.value)) {
        return false;
    }
    return !!WinHttpSetOption(request,
                              WINHTTP_OPTION_PROXY,
                              &proxy_info.value,
                              sizeof(proxy_info.value));
}

std::string NarrowHeaders(const std::vector<wchar_t>& headers) {
    if (headers.empty()) {
        return {};
    }
    const int source_length = static_cast<int>(headers.size() - 1);
    const int required = WideCharToMultiByte(CP_UTF8, 0, headers.data(), source_length,
                                             nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return {};
    }
    std::string result(static_cast<std::size_t>(required), '\0');
    WideCharToMultiByte(CP_UTF8, 0, headers.data(), source_length,
                        &result[0], required, nullptr, nullptr);
    return result;
}

HttpResponse Get(const wchar_t* host, const wchar_t* path) {
    HttpResponse response;
    InternetHandle session(WinHttpOpen(L"TrafficMonitorIpPlugin/1.0",
                                       WINHTTP_ACCESS_TYPE_NO_PROXY,
                                       WINHTTP_NO_PROXY_NAME,
                                       WINHTTP_NO_PROXY_BYPASS,
                                       0));
    if (!session || !WinHttpSetTimeouts(session.get(), 3000, 3000, 3000, 5000)) {
        return response;
    }
    InternetHandle connection(WinHttpConnect(session.get(), host,
                                              INTERNET_DEFAULT_HTTPS_PORT, 0));
    if (!connection) {
        return response;
    }
    InternetHandle request(WinHttpOpenRequest(connection.get(), L"GET", path, nullptr,
                                              WINHTTP_NO_REFERER,
                                              WINHTTP_DEFAULT_ACCEPT_TYPES,
                                              WINHTTP_FLAG_SECURE));
    if (!request) {
        return response;
    }

    std::wstring url = L"https://";
    url += host;
    url += path;
    ApplyCurrentUserProxyForRequest(request.get(), url.c_str());
    const wchar_t accept_language[] = L"Accept-Language: en-US\r\n";
    if (!WinHttpAddRequestHeaders(request.get(), accept_language, DWORD(-1L),
                                  WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE) ||
        !WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request.get(), nullptr)) {
        return response;
    }

    DWORD status_size = sizeof(response.status);
    if (!WinHttpQueryHeaders(request.get(),
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX,
                             &response.status, &status_size, WINHTTP_NO_HEADER_INDEX)) {
        return response;
    }

    DWORD headers_size = 0;
    WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF,
                        WINHTTP_HEADER_NAME_BY_INDEX, nullptr,
                        &headers_size, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || headers_size < sizeof(wchar_t)) {
        return response;
    }
    std::vector<wchar_t> raw_headers(headers_size / sizeof(wchar_t));
    if (!WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_RAW_HEADERS_CRLF,
                             WINHTTP_HEADER_NAME_BY_INDEX, raw_headers.data(),
                             &headers_size, WINHTTP_NO_HEADER_INDEX)) {
        return response;
    }
    response.headers = NarrowHeaders(raw_headers);

    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.get(), &available)) {
            return HttpResponse{};
        }
        if (available == 0) {
            break;
        }
        if (available > kMaximumResponseBytes - response.body.size()) {
            // Response exceeds the cap. Keep the prefix already buffered rather
            // than discarding the whole body: early-page signals (e.g. Netflix
            // <html lang> and og:locale live in the first few KB) survive so the
            // parsers can still succeed on very large pages.
            const std::size_t remaining = kMaximumResponseBytes - response.body.size();
            if (remaining > 0) {
                const std::size_t kept = response.body.size();
                response.body.resize(kept + remaining);
                DWORD read = 0;
                if (WinHttpReadData(request.get(), &response.body[kept],
                                    static_cast<DWORD>(remaining), &read)) {
                    response.body.resize(kept + read);
                } else {
                    response.body.resize(kept);
                }
            }
            break;
        }
        const std::size_t old_size = response.body.size();
        response.body.resize(old_size + available);
        DWORD read = 0;
        if (!WinHttpReadData(request.get(), &response.body[old_size], available, &read)) {
            return HttpResponse{};
        }
        if (read == 0) {
            return HttpResponse{};
        }
        response.body.resize(old_size + read);
    }
    response.ok = response.status >= 200 && response.status <= 399;
    return response;
}

SiteResult MakeResult(Site site, const std::wstring& value) {
    const std::wstring code = NormalizeCountryCode(value);
    return code.empty()
        ? SiteResult{site, ResultState::Unknown, L""}
        : SiteResult{site, ResultState::Success, code};
}

SiteResult ProbeGoogle() {
    const HttpResponse mapping = Get(L"redirector.gvt1.com", L"/report_mapping?di=no");
    if (!mapping.ok) return MakeResult(Site::Google, L"");
    const std::wstring ip = ParseGoogleMappingIp(mapping.body);
    if (ip.empty()) return MakeResult(Site::Google, L"");
    const std::wstring path = L"/" + ip + L"/json";
    const HttpResponse info = Get(L"ipinfo.io", path.c_str());
    return MakeResult(Site::Google, info.ok ? ParseIpInfoCountry(info.body) : L"");
}

SiteResult ProbeYouTube() {
    const HttpResponse response = Get(L"www.youtube.com", L"/premium");
    return MakeResult(Site::YouTube,
                      response.ok ? ParseYouTubeCountry(response.body) : L"");
}

SiteResult ProbeTrace(Site site, const wchar_t* host) {
    const HttpResponse response = Get(host, L"/cdn-cgi/trace");
    return MakeResult(site, response.ok ? ParseTraceCountry(response.body) : L"");
}

SiteResult ProbeNetflix() {
    const HttpResponse response = Get(L"www.netflix.com", L"/title/81280792");
    return MakeResult(Site::Netflix,
                      response.ok ? ParseNetflixCountry(response.body) : L"");
}

bool RefreshShutdownRequested();

Snapshot RunBatch() {
    Snapshot result = MakeInitialSnapshot();
    using Probe = SiteResult (*)();
    const Probe probes[] = {
        ProbeGoogle,
        ProbeYouTube,
        [] { return ProbeTrace(Site::OpenAI, L"chatgpt.com"); },
        [] { return ProbeTrace(Site::Claude, L"claude.ai"); },
        ProbeNetflix
    };
    for (std::size_t i = 0; i < result.sites.size(); ++i) {
        if (RefreshShutdownRequested()) return result;
        try {
            result.sites[i] = probes[i]();
        } catch (...) {
            result.sites[i] = MakeResult(static_cast<Site>(i), L"");
        }
    }
    result.has_completed = true;
    result.refresh_in_flight = true;
    return result;
}

struct RefreshState {
    std::mutex mutex;
    Snapshot snapshot = MakeInitialSnapshot();
    std::chrono::steady_clock::time_point last_refresh{};
    RefreshQueueState queue;
    std::thread worker;
    bool shutdown_requested = false;
};

RefreshState& SharedState() {
    static RefreshState* state = new RefreshState;
    return *state;
}

bool RefreshShutdownRequested() {
    RefreshState& state = SharedState();
    std::lock_guard<std::mutex> lock(state.mutex);
    return state.shutdown_requested;
}

void RefreshWorker() {
    RefreshState& state = SharedState();
    try {
        for (;;) {
            {
                std::lock_guard<std::mutex> lock(state.mutex);
                if (state.queue.shutdown_requested) {
                    state.snapshot.refresh_in_flight = false;
                    state.queue.refresh_in_flight = false;
                    return;
                }
            }

            Snapshot completed = RunBatch();
            const auto now = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lock(state.mutex);
            if (state.shutdown_requested) {
                state.snapshot.refresh_in_flight = false;
                state.queue.refresh_in_flight = false;
                return;
            }
            state.snapshot.sites = std::move(completed.sites);
            state.snapshot.has_completed = true;
            state.last_refresh = now;
            if (CompleteRefreshIteration(state.queue) == RefreshCompletionDecision::RunAgain) {
                state.snapshot.refresh_in_flight = true;
                continue;
            }
            state.snapshot.refresh_in_flight = false;
            return;
        }
    } catch (...) {
        // Do not let a failed allocation in a worker terminate TrafficMonitor.
        std::lock_guard<std::mutex> lock(state.mutex);
        state.snapshot.refresh_in_flight = false;
        state.queue = RefreshQueueState{};
        state.queue.shutdown_requested = state.shutdown_requested;
    }
}

std::wstring AsciiToWide(const std::string& value) {
    return std::wstring(value.begin(), value.end());
}

void SkipWhitespace(const std::string& text, std::size_t& pos) {
    while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
        ++pos;
    }
}

bool HasKeyPrefix(const std::string& text, std::size_t key_pos) {
    std::size_t pos = key_pos;
    while (pos > 0 && std::isspace(static_cast<unsigned char>(text[pos - 1]))) {
        --pos;
    }
    return pos > 0 && (text[pos - 1] == '{' || text[pos - 1] == ',');
}

bool HasValueTerminator(const std::string& text, std::size_t value_end) {
    SkipWhitespace(text, value_end);
    return value_end < text.size() &&
           (text[value_end] == ',' || text[value_end] == '}');
}

char AsciiLower(char ch) {
    return ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch - 'A' + 'a') : ch;
}

std::size_t RFindAsciiNoCase(const std::string& text,
                             const std::string& needle,
                             std::size_t before) {
    std::size_t found = std::string::npos;
    for (std::size_t pos = 0;
         pos <= before && pos + needle.size() <= text.size();
         ++pos) {
        bool matches = true;
        for (std::size_t i = 0; i < needle.size(); ++i) {
            if (AsciiLower(text[pos + i]) != AsciiLower(needle[i])) {
                matches = false;
                break;
            }
        }
        if (matches) {
            found = pos;
        }
    }
    return found;
}

bool IsInsideScriptLiteral(const std::string& text, std::size_t position) {
    const std::size_t script_start = RFindAsciiNoCase(text, "<script", position);
    const std::size_t script_end = RFindAsciiNoCase(text, "</script", position);
    if (script_start == std::string::npos ||
        (script_end != std::string::npos && script_end > script_start)) {
        return false;
    }
    const std::size_t content_start = text.find('>', script_start);
    if (content_start == std::string::npos || content_start >= position) {
        return false;
    }

    char quote = 0;
    std::size_t pos = content_start + 1;
    while (pos < position) {
        const char ch = text[pos];
        if (quote != 0) {
            if (ch == '\\' && pos + 1 < position) {
                pos += 2;
                continue;
            }
            if (ch == quote) {
                quote = 0;
            }
        } else if (ch == '\'' || ch == '`') {
            quote = ch;
        }
        ++pos;
    }
    return quote != 0;
}

bool ParseCountryValue(const std::string& text,
                       std::size_t key_end,
                       std::wstring& country) {
    std::size_t pos = key_end;
    SkipWhitespace(text, pos);
    if (pos >= text.size() || text[pos] != ':') {
        return false;
    }
    ++pos;
    SkipWhitespace(text, pos);
    if (pos + 3 >= text.size() || text[pos] != '"' || text[pos + 3] != '"' ||
        !HasValueTerminator(text, pos + 4)) {
        return false;
    }
    const unsigned char first = static_cast<unsigned char>(text[pos + 1]);
    const unsigned char second = static_cast<unsigned char>(text[pos + 2]);
    if (!((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) ||
        !((second >= 'a' && second <= 'z') || (second >= 'A' && second <= 'Z'))) {
        return false;
    }
    country = NormalizeCountryCode(AsciiToWide(text.substr(pos + 1, 2)));
    return !country.empty();
}

std::wstring ParseJsonCountry(const std::string& body, const std::string& field) {
    const std::string key = "\"" + field + "\"";
    std::wstring country;
    std::size_t key_pos = body.find(key);
    while (key_pos != std::string::npos) {
        std::wstring candidate;
        if (HasKeyPrefix(body, key_pos) &&
            !(field == "countryCode" && IsInsideScriptLiteral(body, key_pos)) &&
            ParseCountryValue(body, key_pos + key.size(), candidate)) {
            if (!country.empty() && country != candidate) {
                return {};
            }
            country = candidate;
        }
        key_pos = body.find(key, key_pos + key.size());
    }
    return country;
}

bool HasStringValue(const std::string& text, std::size_t key_end) {
    std::size_t pos = key_end;
    SkipWhitespace(text, pos);
    if (pos >= text.size() || text[pos] != ':') {
        return false;
    }
    ++pos;
    SkipWhitespace(text, pos);
    if (pos >= text.size() || text[pos] != '"') {
        return false;
    }
    ++pos;
    while (pos < text.size()) {
        if (text[pos] == '\\') {
            if (pos + 1 >= text.size()) {
                return false;
            }
            pos += 2;
        } else if (text[pos] == '"') {
            return HasValueTerminator(text, pos + 1);
        } else {
            ++pos;
        }
    }
    return false;
}

bool IsIpv4(const std::string& value) {
    if (value.empty() || value.front() == '.' || value.back() == '.') {
        return false;
    }

    std::size_t start = 0;
    int part_count = 0;
    while (start < value.size()) {
        const std::size_t end = value.find('.', start);
        const std::size_t length = (end == std::string::npos ? value.size() : end) - start;
        if (length == 0 || length > 3) {
            return false;
        }

        unsigned int number = 0;
        for (std::size_t i = start; i < start + length; ++i) {
            const unsigned char ch = static_cast<unsigned char>(value[i]);
            if (!std::isdigit(ch)) {
                return false;
            }
            number = number * 10u + static_cast<unsigned int>(ch - '0');
        }
        if (number > 255u) {
            return false;
        }

        ++part_count;
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    return part_count == 4;
}

using CountryMap = std::unordered_map<std::wstring, std::wstring>;

thread_local CountryMap* country_map_under_construction = nullptr;
thread_local CountryMap* english_names_under_construction = nullptr;

std::wstring GetGeoText(GEOID geo_id, GEOTYPE type, LANGID language) {
    const int length = GetGeoInfoW(geo_id, type, nullptr, 0, language);
    if (length <= 1) {
        return {};
    }

    std::wstring value(static_cast<std::size_t>(length), L'\0');
    if (GetGeoInfoW(geo_id, type, &value[0], length, language) == 0) {
        return {};
    }
    value.resize(static_cast<std::size_t>(length - 1));
    return value;
}

std::wstring GetLocaleText(const wchar_t* locale_name, LCTYPE type) {
    const int length = GetLocaleInfoEx(
        locale_name, type, nullptr, 0);
    if (length <= 1) {
        return {};
    }

    std::wstring value(static_cast<std::size_t>(length), L'\0');
    if (GetLocaleInfoEx(locale_name,
                        type,
                        &value[0],
                        length) == 0) {
        return {};
    }
    value.resize(static_cast<std::size_t>(length - 1));
    return value;
}

BOOL CALLBACK CollectEnglishCountryName(LPWSTR locale_name, DWORD, LPARAM) {
    if (english_names_under_construction == nullptr) {
        return FALSE;
    }

    const std::wstring code = GetLocaleText(locale_name, LOCALE_SISO3166CTRYNAME);
    const std::wstring name = GetLocaleText(locale_name, LOCALE_SENGLISHCOUNTRYNAME);
    if (code.size() == 2 && !name.empty()) {
        english_names_under_construction->emplace(code, name);
    }
    return TRUE;
}

const CountryMap& EnglishCountryNames() {
    static const CountryMap names = [] {
        CountryMap result;
        english_names_under_construction = &result;
        EnumSystemLocalesEx(CollectEnglishCountryName, LOCALE_ALL, 0, nullptr);
        english_names_under_construction = nullptr;
        return result;
    }();
    return names;
}

BOOL CALLBACK CollectCountry(GEOID geo_id) {
    if (country_map_under_construction == nullptr) {
        return FALSE;
    }

    const std::wstring code = GetGeoText(geo_id, GEO_ISO2, 0);
    // Query the geographic name as part of the Windows GEO record lookup, but
    // do not display it because Windows localizes this field to the UI language.
    GetGeoText(geo_id, GEO_FRIENDLYNAME, 0);
    const auto english_name = EnglishCountryNames().find(code);
    std::wstring name = english_name == EnglishCountryNames().end()
        ? code
        : english_name->second;
    if (code.size() == 2) {
        if (code == L"HK") {
            name = L"Hong Kong";
        }
        country_map_under_construction->emplace(code, std::move(name));
    }
    return TRUE;
}

const CountryMap& Countries() {
    static const CountryMap countries = [] {
        CountryMap result;
        country_map_under_construction = &result;
        EnumSystemGeoID(GEOCLASS_NATION, 0, CollectCountry);
        country_map_under_construction = nullptr;
        return result;
    }();
    return countries;
}

const wchar_t* SiteName(Site site) {
    switch (site) {
    case Site::Google: return L"Google";
    case Site::YouTube: return L"YouTube";
    case Site::OpenAI: return L"OpenAI";
    case Site::Claude: return L"Claude";
    case Site::Netflix: return L"Netflix";
    default: return L"";
    }
}

const SiteResult* FindSite(const Snapshot& snapshot, Site site) {
    for (const auto& result : snapshot.sites) {
        if (result.site == site) {
            return &result;
        }
    }
    return nullptr;
}

const wchar_t* NetworkCode(Site site) {
    switch (site) {
    case Site::Google: return L"GGL";
    case Site::YouTube: return L"GGL";
    case Site::OpenAI: return L"CF";
    case Site::Claude: return L"CF";
    case Site::Netflix: return L"NFLX";
    default: return L"";
    }
}

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

std::wstring ParseLocaleCountry(const std::string& body, const std::string& marker) {
    std::size_t pos = body.find(marker);
    while (pos != std::string::npos) {
        pos += marker.size();
        if (pos + 5 <= body.size() &&
            std::isalpha(static_cast<unsigned char>(body[pos])) &&
            std::isalpha(static_cast<unsigned char>(body[pos + 1])) &&
            body[pos + 2] == '-' &&
            std::isalpha(static_cast<unsigned char>(body[pos + 3])) &&
            std::isalpha(static_cast<unsigned char>(body[pos + 4]))) {
            std::wstring code = AsciiToWide(body.substr(pos + 3, 2));
            for (wchar_t& ch : code) {
                if (ch >= L'a' && ch <= L'z') {
                    ch = static_cast<wchar_t>(ch - L'a' + L'A');
                }
            }
            return code;
        }
        pos = body.find(marker, pos);
    }
    return {};
}

void AppendRegionalIndicator(std::wstring& text, wchar_t letter) {
    const unsigned int code_point = 0x1F1E6u + static_cast<unsigned int>(letter - L'A');
    const unsigned int offset = code_point - 0x10000u;
    text.push_back(static_cast<wchar_t>(0xD800u + (offset >> 10)));
    text.push_back(static_cast<wchar_t>(0xDC00u + (offset & 0x3FFu)));
}

// Netflix embeds the authoritative exit region as
// "requestCountry":{...,"id":"XX",...}. Read the first two-letter "id" that
// follows a requestCountry object.
std::wstring ParseRequestCountryId(const std::string& body) {
    const std::string key = "\"requestCountry\"";
    std::size_t pos = body.find(key);
    while (pos != std::string::npos) {
        const std::size_t brace = body.find('{', pos + key.size());
        if (brace != std::string::npos) {
            std::size_t id_pos = body.find("\"id\"", brace + 1);
            // Only trust an "id" that stays within this small object.
            while (id_pos != std::string::npos && id_pos < brace + 400) {
                std::wstring code;
                if (HasKeyPrefix(body, id_pos) &&
                    ParseCountryValue(body, id_pos + 4, code)) {
                    return code;
                }
                id_pos = body.find("\"id\"", id_pos + 4);
            }
        }
        pos = body.find(key, pos + key.size());
    }
    return {};
}

// Last-resort heuristic: pair a "countryName" with the "id" that precedes it in
// the same JSON object. Returns empty when signals are missing or ambiguous.
std::wstring NetflixCountryNameHeuristic(const std::string& body) {
    const std::string country_key = "\"countryName\"";
    const std::string id_key = "\"id\"";
    std::wstring candidate;

    std::size_t country_pos = body.find(country_key);
    while (country_pos != std::string::npos) {
        if (HasKeyPrefix(body, country_pos)) {
            if (!HasStringValue(body, country_pos + country_key.size())) {
                if (!candidate.empty()) {
                    return {};
                }
                country_pos = body.find(country_key, country_pos + country_key.size());
                continue;
            }
            const std::size_t object_start = body.rfind('{', country_pos);
            const std::size_t last_close = body.rfind('}', country_pos);
            if (object_start == std::string::npos ||
                (last_close != std::string::npos && last_close > object_start)) {
                return {};
            }

            std::wstring object_id;
            std::size_t id_pos = body.find(id_key, object_start + 1);
            while (id_pos != std::string::npos && id_pos < country_pos) {
                if (HasKeyPrefix(body, id_pos)) {
                    std::wstring parsed_id;
                    if (!ParseCountryValue(body, id_pos + id_key.size(), parsed_id)) {
                        if (!candidate.empty()) {
                            return {};
                        }
                        id_pos = body.find(id_key, id_pos + id_key.size());
                        continue;
                    }
                    object_id = parsed_id;
                }
                id_pos = body.find(id_key, id_pos + id_key.size());
            }
            if (object_id.empty()) {
                country_pos = body.find(country_key, country_pos + country_key.size());
                continue;
            }
            if (!candidate.empty() && candidate != object_id) {
                return {};
            }
            candidate = object_id;
        }
        country_pos = body.find(country_key, country_pos + country_key.size());
    }
    return candidate;
}

} // namespace

std::wstring NormalizeCountryCode(const std::wstring& value) {
    if (value.size() != 2) {
        return {};
    }

    std::wstring result;
    result.reserve(2);
    for (wchar_t ch : value) {
        if (!((ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z'))) {
            return {};
        }
        result.push_back(ch >= L'a' ? static_cast<wchar_t>(ch - L'a' + L'A') : ch);
    }
    return result;
}

std::wstring ParseGoogleMappingIp(const std::string& body) {
    const std::size_t ip_end = body.find_first_of(" \t\r\n");
    if (ip_end == std::string::npos) {
        return {};
    }

    std::size_t mapping = ip_end;
    while (mapping < body.size() && (body[mapping] == ' ' || body[mapping] == '\t')) {
        ++mapping;
    }
    if (body.compare(mapping, 2, "=>") != 0) {
        return {};
    }

    const std::string candidate = body.substr(0, ip_end);
    return IsIpv4(candidate) ? AsciiToWide(candidate) : L"";
}

std::wstring ParseYouTubeCountry(const std::string& body) {
    std::wstring country = ParseJsonCountry(body, "countryCode");
    if (!country.empty()) {
        return country;
    }
    return ParseJsonCountry(body, "contentRegion");
}

std::wstring ParseTraceCountry(const std::string& body) {
    std::size_t start = 0;
    while (start < body.size()) {
        const std::size_t end = body.find('\n', start);
        std::string line = body.substr(start, end == std::string::npos ? body.size() - start : end - start);
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.compare(0, 4, "loc=") == 0) {
            return NormalizeCountryCode(AsciiToWide(line.substr(4)));
        }
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    return {};
}

std::wstring ParseNetflixCountry(const std::string& body) {
    // Reliable region signals that live in the first few KB of the page, so they
    // survive huge or truncated responses and never conflict with each other.
    std::wstring region = ParseLocaleCountry(body, "<html lang=\"");
    if (!region.empty()) {
        return region;
    }
    region = ParseLocaleCountry(body, "property=\"og:locale\" content=\"");
    if (!region.empty()) {
        return region;
    }

    // Authoritative geo field embedded deeper in the page.
    region = ParseRequestCountryId(body);
    if (!region.empty()) {
        return region;
    }

    // Legacy JSON fields.
    region = ParseJsonCountry(body, "countryCode");
    if (!region.empty()) {
        return region;
    }
    region = ParseJsonCountry(body, "contentRegion");
    if (!region.empty()) {
        return region;
    }

    // Object-pairing heuristic last: an ambiguous match here no longer discards
    // the reliable signals above, since those were already checked.
    return NetflixCountryNameHeuristic(body);
}

std::wstring ParseIpInfoCountry(const std::string& body) {
    return ParseJsonCountry(body, "country");
}

std::wstring CountryFlag(const std::wstring& country_code) {
    const std::wstring code = NormalizeCountryCode(country_code);
    if (code.empty() || Countries().find(code) == Countries().end()) {
        return {};
    }

    std::wstring flag;
    flag.reserve(4);
    AppendRegionalIndicator(flag, code[0]);
    AppendRegionalIndicator(flag, code[1]);
    return flag;
}

std::wstring CountryName(const std::wstring& country_code) {
    const std::wstring code = NormalizeCountryCode(country_code);
    if (code.empty()) {
        return {};
    }

    const auto found = Countries().find(code);
    return found == Countries().end() ? code : found->second;
}

Snapshot MakeInitialSnapshot() {
    Snapshot snapshot;
    for (std::size_t i = 0; i < snapshot.sites.size(); ++i) {
        snapshot.sites[i] = {
            static_cast<Site>(i),
            ResultState::Pending,
            L""
        };
    }
    return snapshot;
}

std::wstring FormatTooltip(const Snapshot& snapshot) {
    std::wstring tooltip = L"──── 出口检测 ────";
    for (std::size_t i = 0; i < static_cast<std::size_t>(Site::Count); ++i) {
        const Site site = static_cast<Site>(i);

        std::wstring value;
        const SiteResult* result = FindSite(snapshot, site);
        if (!snapshot.has_completed ||
            (result != nullptr && result->state == ResultState::Pending)) {
            value = L"-- WAIT";
        } else if (result != nullptr && result->state == ResultState::Success) {
            const std::wstring code = NormalizeCountryCode(result->country_code);
            if (!code.empty()) {
                value = code;
                value += L' ';
                value += NetworkCode(site);
            }
        }
        if (value.empty()) {
            value = L"-- ----";
        }

        tooltip += L'\n';
        tooltip += FormatExitRow(site, value);
    }
    return tooltip;
}

RefreshDecision EvaluateRefresh(bool has_completed,
                                bool refresh_in_flight,
                                std::chrono::steady_clock::duration age,
                                bool force_refresh) {
    if (refresh_in_flight) {
        return force_refresh ? RefreshDecision::QueueForced : RefreshDecision::Skip;
    }
    if (force_refresh || !has_completed) {
        return RefreshDecision::Start;
    }
    if (age < std::chrono::steady_clock::duration::zero()) {
        return RefreshDecision::Skip;
    }
    return age >= kRefreshInterval ? RefreshDecision::Start : RefreshDecision::Skip;
}

void StartRefreshQueue(RefreshQueueState& state) {
    state = RefreshQueueState{};
    state.refresh_in_flight = true;
}

bool QueueForcedRefresh(RefreshQueueState& state) {
    if (!state.refresh_in_flight || state.shutdown_requested ||
        state.forced_rerun_consumed) {
        return false;
    }
    state.forced_pending = true;
    return true;
}

RefreshCompletionDecision CompleteRefreshIteration(RefreshQueueState& state) {
    if (state.shutdown_requested) {
        state.refresh_in_flight = false;
        state.forced_pending = false;
        state.forced_rerun_consumed = false;
        return RefreshCompletionDecision::Stop;
    }
    if (state.forced_pending && !state.forced_rerun_consumed) {
        state.forced_pending = false;
        state.forced_rerun_consumed = true;
        state.refresh_in_flight = true;
        return RefreshCompletionDecision::RunAgain;
    }
    state.refresh_in_flight = false;
    state.forced_pending = false;
    state.forced_rerun_consumed = false;
    return RefreshCompletionDecision::Stop;
}

Snapshot GetSnapshot() {
    RefreshState& state = SharedState();
    std::lock_guard<std::mutex> lock(state.mutex);
    return state.snapshot;
}

void RequestRefreshAsync(bool force_refresh) {
    RefreshState& state = SharedState();
    std::thread previous_worker;
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        if (state.shutdown_requested) return;
        const auto now = std::chrono::steady_clock::now();
        const auto age = state.snapshot.has_completed
            ? now - state.last_refresh
            : std::chrono::steady_clock::duration::zero();
        const RefreshDecision decision = EvaluateRefresh(
            state.snapshot.has_completed,
            state.snapshot.refresh_in_flight,
            age,
            force_refresh);
        if (decision == RefreshDecision::Skip) {
            return;
        }
        if (decision == RefreshDecision::QueueForced) {
            QueueForcedRefresh(state.queue);
            return;
        }
        if (state.worker.joinable()) {
            previous_worker = std::move(state.worker);
        }
        StartRefreshQueue(state.queue);
        state.snapshot.refresh_in_flight = true;
    }
    if (previous_worker.joinable()) {
        previous_worker.join();
    }

    std::lock_guard<std::mutex> lock(state.mutex);
    if (state.shutdown_requested) {
        state.snapshot.refresh_in_flight = false;
        return;
    }
    try {
        // Publish the worker atomically with respect to shutdown.
        state.worker = std::thread(RefreshWorker);
    } catch (...) {
        state.snapshot.refresh_in_flight = false;
        state.queue = RefreshQueueState{};
    }
}

void ShutdownRefreshWorker() {
    RefreshState& state = SharedState();
    std::thread worker;
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.shutdown_requested = true;
        state.queue.shutdown_requested = true;
        state.queue.forced_pending = false;
        state.snapshot.refresh_in_flight = false;
        if (!state.worker.joinable()) {
            state.queue.refresh_in_flight = false;
            return;
        }
        worker = std::move(state.worker);
    }
    worker.join();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.queue = RefreshQueueState{};
    state.queue.shutdown_requested = true;
    state.snapshot.refresh_in_flight = false;
}

} // namespace exit_detection
