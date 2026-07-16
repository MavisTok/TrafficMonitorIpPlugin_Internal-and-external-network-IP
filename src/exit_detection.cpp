#pragma execution_character_set("utf-8")
#include "exit_detection.h"

#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <unordered_map>

namespace exit_detection {
namespace {

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
    case Site::GitHub: return L"GitHub";
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

void AppendRegionalIndicator(std::wstring& text, wchar_t letter) {
    const unsigned int code_point = 0x1F1E6u + static_cast<unsigned int>(letter - L'A');
    const unsigned int offset = code_point - 0x10000u;
    text.push_back(static_cast<wchar_t>(0xD800u + (offset >> 10)));
    text.push_back(static_cast<wchar_t>(0xDC00u + (offset & 0x3FFu)));
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
    return ParseJsonCountry(body, "countryCode");
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
    const std::string country_key = "\"countryName\"";
    const std::string id_key = "\"id\"";
    std::wstring candidate;

    std::size_t country_pos = body.find(country_key);
    while (country_pos != std::string::npos) {
        if (HasKeyPrefix(body, country_pos)) {
            if (!HasStringValue(body, country_pos + country_key.size())) {
                return {};
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
                        return {};
                    }
                    object_id = parsed_id;
                }
                id_pos = body.find(id_key, id_pos + id_key.size());
            }
            if (object_id.empty()) {
                return {};
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

std::wstring ParseIpInfoCountry(const std::string& body) {
    return ParseJsonCountry(body, "country");
}

std::wstring ParseGitHubCountry(const std::string& headers) {
    std::size_t start = 0;
    while (start < headers.size()) {
        const std::size_t end = headers.find('\n', start);
        std::string line = headers.substr(start, end == std::string::npos ? headers.size() - start : end - start);
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        const std::size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = line.substr(0, colon);
            std::transform(name.begin(), name.end(), name.begin(), [](unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });
            if (name == "x-github-country") {
                std::size_t value_start = colon + 1;
                while (value_start < line.size() &&
                       (line[value_start] == ' ' || line[value_start] == '\t')) {
                    ++value_start;
                }
                std::size_t value_end = line.size();
                while (value_end > value_start &&
                       (line[value_end - 1] == ' ' || line[value_end - 1] == '\t')) {
                    --value_end;
                }
                return NormalizeCountryCode(AsciiToWide(line.substr(value_start, value_end - value_start)));
            }
        }

        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    return {};
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
    std::wstring tooltip = L"──────── 出口检测 ────────";
    for (std::size_t i = 0; i < static_cast<std::size_t>(Site::Count); ++i) {
        const Site site = static_cast<Site>(i);
        const std::wstring name = SiteName(site);
        tooltip += L'\n';
        tooltip += name;
        if (name.size() < 7) {
            tooltip.append(7 - name.size(), L' ');
        }
        tooltip += L"  → ";

        const SiteResult* result = FindSite(snapshot, site);
        if (!snapshot.has_completed ||
            (result != nullptr && result->state == ResultState::Pending)) {
            tooltip += L"⏳ Detecting...";
            continue;
        }

        if (result != nullptr && result->state == ResultState::Success) {
            const std::wstring flag = CountryFlag(result->country_code);
            if (!flag.empty()) {
                tooltip += flag;
                tooltip += L' ';
                tooltip += CountryName(result->country_code);
                continue;
            }
        }
        tooltip += L"❔ Unknown";
    }
    return tooltip;
}

} // namespace exit_detection
