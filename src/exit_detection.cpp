#pragma execution_character_set("utf-8")
#include "exit_detection.h"

#include <algorithm>
#include <cctype>

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
           (text[value_end] == ',' || text[value_end] == '}' || text[value_end] == ']');
}

bool IsInsideScriptLiteral(const std::string& text, std::size_t position) {
    const std::size_t script_start = text.rfind("<script", position);
    const std::size_t script_end = text.rfind("</script", position);
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

} // namespace exit_detection
