#pragma execution_character_set("utf-8")
#include "exit_detection.h"

#include <algorithm>
#include <cctype>

namespace exit_detection {
namespace {

std::wstring AsciiToWide(const std::string& value) {
    return std::wstring(value.begin(), value.end());
}

std::string ExtractJsonString(const std::string& text, const std::string& field) {
    const std::string key = "\"" + field + "\"";
    std::size_t key_pos = text.find(key);
    while (key_pos != std::string::npos) {
        std::size_t pos = key_pos + key.size();
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
            ++pos;
        }
        if (pos < text.size() && text[pos] == ':') {
            ++pos;
            while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
                ++pos;
            }
            if (pos < text.size() && text[pos] == '"') {
                const std::size_t end = text.find('"', pos + 1);
                if (end != std::string::npos) {
                    return text.substr(pos + 1, end - pos - 1);
                }
                return {};
            }
        }
        key_pos = text.find(key, key_pos + key.size());
    }
    return {};
}

std::wstring ParseJsonCountry(const std::string& body, const std::string& field) {
    return NormalizeCountryCode(AsciiToWide(ExtractJsonString(body, field)));
}

bool IsIpv4(const std::string& value) {
    if (value.empty()) {
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
    const std::size_t country_name = body.find("\"countryName\"");
    if (country_name == std::string::npos) {
        return {};
    }

    const std::size_t id = body.rfind("\"id\"", country_name);
    if (id == std::string::npos) {
        return {};
    }
    return ParseJsonCountry(body.substr(id, country_name - id), "id");
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
