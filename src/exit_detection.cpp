#pragma execution_character_set("utf-8")
#include "exit_detection.h"

#include <algorithm>
#include <cctype>
#include <vector>

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

bool ReadJsonString(const std::string& text, std::size_t& pos, std::string& value) {
    if (pos >= text.size() || text[pos] != '"') {
        return false;
    }

    value.clear();
    ++pos;
    while (pos < text.size()) {
        const char ch = text[pos++];
        if (ch == '"') {
            return true;
        }
        if (ch == '\\') {
            if (pos >= text.size()) {
                return false;
            }
            value.push_back(text[pos++]);
        } else {
            value.push_back(ch);
        }
    }
    return false;
}

std::wstring ParseJsonCountry(const std::string& body, const std::string& field) {
    std::vector<char> containers;
    std::wstring country;
    bool saw_root = false;

    std::size_t pos = 0;
    while (pos < body.size()) {
        const char ch = body[pos];
        if (ch == '{' || ch == '[') {
            containers.push_back(ch);
            saw_root = true;
            ++pos;
            continue;
        }
        if (ch == '}' || ch == ']') {
            if (containers.empty() ||
                (ch == '}' && containers.back() != '{') ||
                (ch == ']' && containers.back() != '[')) {
                return {};
            }
            containers.pop_back();
            ++pos;
            continue;
        }
        if (ch != '"') {
            ++pos;
            continue;
        }

        std::string key;
        if (!ReadJsonString(body, pos, key)) {
            return {};
        }
        std::size_t value_pos = pos;
        SkipWhitespace(body, value_pos);
        if (containers.empty() || containers.back() != '{' || key != field ||
            value_pos >= body.size() || body[value_pos] != ':') {
            continue;
        }
        ++value_pos;
        SkipWhitespace(body, value_pos);
        std::string value;
        if (!ReadJsonString(body, value_pos, value)) {
            continue;
        }

        const std::wstring normalized = NormalizeCountryCode(AsciiToWide(value));
        if (normalized.empty()) {
            continue;
        }
        if (!country.empty() && country != normalized) {
            return {};
        }
        country = normalized;
    }

    return saw_root && containers.empty() ? country : L"";
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
    struct ObjectFields {
        std::vector<std::wstring> ids;
        std::size_t country_names = 0;
        bool id_after_country_name = false;
    };

    std::vector<char> containers;
    std::vector<ObjectFields> objects;
    std::wstring candidate;
    bool ambiguous = false;
    bool saw_root = false;

    std::size_t pos = 0;
    while (pos < body.size()) {
        const char ch = body[pos];
        if (ch == '{') {
            containers.push_back(ch);
            objects.emplace_back();
            saw_root = true;
            ++pos;
            continue;
        }
        if (ch == '[') {
            containers.push_back(ch);
            saw_root = true;
            ++pos;
            continue;
        }
        if (ch == '}' || ch == ']') {
            if (containers.empty() ||
                (ch == '}' && containers.back() != '{') ||
                (ch == ']' && containers.back() != '[')) {
                return {};
            }
            if (ch == '}') {
                ObjectFields fields = objects.back();
                objects.pop_back();
                if (fields.id_after_country_name) {
                    ambiguous = true;
                } else if (!fields.ids.empty() && fields.country_names > 0) {
                    if (fields.ids.size() != 1 || fields.country_names != 1 ||
                        !candidate.empty()) {
                        ambiguous = true;
                    } else {
                        candidate = fields.ids.front();
                    }
                }
            }
            containers.pop_back();
            ++pos;
            continue;
        }
        if (ch != '"') {
            ++pos;
            continue;
        }

        std::string key;
        if (!ReadJsonString(body, pos, key)) {
            return {};
        }
        std::size_t value_pos = pos;
        SkipWhitespace(body, value_pos);
        if (objects.empty() || containers.empty() || containers.back() != '{' ||
            value_pos >= body.size() || body[value_pos] != ':') {
            continue;
        }
        ++value_pos;
        SkipWhitespace(body, value_pos);
        std::string value;
        if (!ReadJsonString(body, value_pos, value)) {
            if (key == "id" || key == "countryName") {
                return {};
            }
            continue;
        }
        if (key == "id") {
            const std::wstring id = NormalizeCountryCode(AsciiToWide(value));
            if (!id.empty()) {
                if (objects.back().country_names > 0) {
                    objects.back().id_after_country_name = true;
                } else {
                    objects.back().ids.push_back(id);
                }
            }
        } else if (key == "countryName") {
            ++objects.back().country_names;
        }
    }

    if (!saw_root || !containers.empty() || !objects.empty() || ambiguous) {
        return {};
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

} // namespace exit_detection
