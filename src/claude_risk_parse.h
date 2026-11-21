#pragma once

#include <string>

namespace claude_risk {

struct RiskFlags {
    bool proxy = false;
    bool hosting = false;
    bool mobile = false;
};

namespace detail {

// Small, bounded JSON reader: only the four top-level API fields affect risk.
// Validate the whole response so partial/error pages cannot look like low risk.
class RiskResponseReader {
public:
    explicit RiskResponseReader(const std::string& text) : text_(text) {}

    bool Read(RiskFlags& output) {
        if (!Take('{')) return false;
        unsigned seen = 0;
        std::string status;
        RiskFlags parsed;
        if (!Take('}')) {
            do {
                std::string key;
                if (!String(key) || !Take(':')) return false;
                unsigned bit = key == "status" ? 1u : key == "proxy" ? 2u
                             : key == "hosting" ? 4u : key == "mobile" ? 8u : 0u;
                if (bit != 0 && (seen & bit) != 0) return false;
                seen |= bit;
                if (bit == 1u) {
                    if (!String(status)) return false;
                } else if (bit == 2u) {
                    if (!Boolean(parsed.proxy)) return false;
                } else if (bit == 4u) {
                    if (!Boolean(parsed.hosting)) return false;
                } else if (bit == 8u) {
                    if (!Boolean(parsed.mobile)) return false;
                } else if (!Value(0)) {
                    return false;
                }
                if (Take('}')) break;
                if (!Take(',')) return false;
            } while (true);
        }
        Space();
        if (pos_ != text_.size() || seen != 15u || status != "success") return false;
        output = parsed;
        return true;
    }

private:
    void Space() {
        while (pos_ < text_.size() && (text_[pos_] == ' ' || text_[pos_] == '\t' ||
               text_[pos_] == '\r' || text_[pos_] == '\n')) ++pos_;
    }

    bool Take(char ch) {
        Space();
        if (pos_ >= text_.size() || text_[pos_] != ch) return false;
        ++pos_;
        return true;
    }

    bool Literal(const char* value) {
        Space();
        const std::size_t length = std::char_traits<char>::length(value);
        if (text_.compare(pos_, length, value) != 0) return false;
        pos_ += length;
        return true;
    }

    bool Boolean(bool& value) {
        if (Literal("true")) { value = true; return true; }
        if (Literal("false")) { value = false; return true; }
        return false;
    }

    bool String(std::string& value) {
        if (!Take('"')) return false;
        value.clear();
        while (pos_ < text_.size()) {
            const unsigned char ch = static_cast<unsigned char>(text_[pos_++]);
            if (ch == '"') return true;
            if (ch < 0x20) return false;
            if (ch != '\\') { value.push_back(static_cast<char>(ch)); continue; }
            if (pos_ == text_.size()) return false;
            const char escaped = text_[pos_++];
            if (escaped == '"' || escaped == '\\' || escaped == '/') value.push_back(escaped);
            else if (escaped == 'b') value.push_back('\b');
            else if (escaped == 'f') value.push_back('\f');
            else if (escaped == 'n') value.push_back('\n');
            else if (escaped == 'r') value.push_back('\r');
            else if (escaped == 't') value.push_back('\t');
            else if (escaped == 'u') {
                if (text_.size() - pos_ < 4) return false;
                unsigned code = 0;
                for (unsigned i = 0; i < 4; ++i) {
                    const char hex = text_[pos_++];
                    const int digit = hex >= '0' && hex <= '9' ? hex - '0'
                                    : hex >= 'a' && hex <= 'f' ? hex - 'a' + 10
                                    : hex >= 'A' && hex <= 'F' ? hex - 'A' + 10 : -1;
                    if (digit < 0) return false;
                    code = code * 16u + static_cast<unsigned>(digit);
                }
                // Required keys and status are ASCII; preserve other text as a marker.
                value.push_back(code < 128 ? static_cast<char>(code) : '?');
            } else return false;
        }
        return false;
    }

    bool Value(unsigned depth) {
        if (depth >= 32) return false;
        Space();
        if (pos_ == text_.size()) return false;
        if (text_[pos_] == '"') { std::string ignored; return String(ignored); }
        if (Take('{')) {
            if (Take('}')) return true;
            do {
                std::string ignored;
                if (!String(ignored) || !Take(':') || !Value(depth + 1)) return false;
                if (Take('}')) return true;
            } while (Take(','));
            return false;
        }
        if (Take('[')) {
            if (Take(']')) return true;
            do {
                if (!Value(depth + 1)) return false;
                if (Take(']')) return true;
            } while (Take(','));
            return false;
        }
        if (Literal("true") || Literal("false") || Literal("null")) return true;
        // JSON number grammar, including optional fraction and exponent.
        const auto digit = [this] { return pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9'; };
        if (text_[pos_] == '-') ++pos_;
        if (!digit()) return false;
        if (text_[pos_] == '0') ++pos_;
        else while (digit()) ++pos_;
        if (pos_ < text_.size() && text_[pos_] == '.') {
            ++pos_;
            if (!digit()) return false;
            while (digit()) ++pos_;
        }
        if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < text_.size() && (text_[pos_] == '+' || text_[pos_] == '-')) ++pos_;
            if (!digit()) return false;
            while (digit()) ++pos_;
        }
        return true;
    }

    const std::string& text_;
    std::size_t pos_ = 0;
};

} // namespace detail

inline bool ParseRiskResponse(const std::string& json, RiskFlags& flags) {
    if (json.size() > 64u * 1024u) return false;
    return detail::RiskResponseReader(json).Read(flags);
}

} // namespace claude_risk
