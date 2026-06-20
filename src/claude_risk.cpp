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
