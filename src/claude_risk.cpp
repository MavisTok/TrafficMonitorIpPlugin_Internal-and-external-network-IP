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
}

struct SelfTestRunner {
    SelfTestRunner() { RunSelfTests(); }
};
static SelfTestRunner g_self_test_runner;

} // anonymous namespace
} // namespace claude_risk
#endif // _DEBUG
