#pragma once

#include "ip_utils.h"
#include <initializer_list>
#include <utility>

namespace iputils {
namespace detail {

// Pure scheduling state: the worker owns this state under its short-lived mutex.
// Cache reads never advance the fast-refresh cycle or postpone a failed retry.
struct ExternalIpCacheState {
    using Clock = std::chrono::steady_clock;
    bool network_observed = false;
    bool has_success = false;
    bool last_attempt_failed = false;
    std::wstring internal_ip;
    Clock::time_point last_change{};
    Clock::time_point last_success{};
    Clock::time_point last_attempt{};
    int fast_cycles = 0;

    bool ObserveNetwork(const std::wstring& value, Clock::time_point now,
                        int adaptive_cycles) {
        if (!network_observed) {
            network_observed = true;
            internal_ip = value;
            last_change = now;
            return false;
        }
        if (internal_ip == value) return false;
        internal_ip = value;
        last_change = now;
        fast_cycles = adaptive_cycles > 0 ? adaptive_cycles : 0;
        return true;
    }

    bool ShouldRefresh(const ExternalIpOptions& options, Clock::time_point now,
                       bool force_refresh, bool network_changed) const {
        if (force_refresh || (network_changed && options.strategy != CacheStrategy::FIXED)) return true;
        if (last_attempt_failed) {
            return now - last_attempt >= std::chrono::seconds(30);
        }
        if (!has_success) return true;

        auto interval = options.min_refresh;
        switch (options.strategy) {
        case CacheStrategy::ADAPTIVE:
        case CacheStrategy::HYBRID:
            if (fast_cycles > 0) interval = options.fast_refresh;
            else if (now - last_change >= std::chrono::hours(1)) interval = options.max_refresh;
            break;
        case CacheStrategy::NETWORK_EVENT:
            interval = options.max_refresh;
            break;
        case CacheStrategy::FIXED:
            break;
        }
        return now - last_success >= interval;
    }

    void Complete(bool success, Clock::time_point now) {
        last_attempt = now;
        last_attempt_failed = !success;
        if (success) {
            has_success = true;
            last_success = now;
            if (fast_cycles > 0) --fast_cycles;
        }
    }
};

// Coalesce any number of forced requests into at most one follow-up per batch.
struct ExternalIpRefreshQueue {
    bool in_flight = false;
    bool pending_force = false;
    bool followup_started = false;

    void Start() {
        in_flight = true;
        pending_force = false;
        followup_started = false;
    }
    void RequestForce() {
        if (in_flight && !followup_started) pending_force = true;
    }
    bool Complete() {
        if (pending_force && !followup_started) {
            pending_force = false;
            followup_started = true;
            return true;
        }
        in_flight = false;
        pending_force = false;
        followup_started = false;
        return false;
    }
};

inline bool IsStrictIPv4(const std::string& value) {
    std::size_t pos = 0;
    for (int part = 0; part < 4; ++part) {
        const std::size_t begin = pos;
        unsigned octet = 0;
        while (pos < value.size() && value[pos] >= '0' && value[pos] <= '9') {
            octet = octet * 10 + static_cast<unsigned>(value[pos++] - '0');
            if (pos - begin > 3 || octet > 255) return false;
        }
        if (pos == begin || (pos - begin > 1 && value[begin] == '0')) return false;
        if (part < 3) {
            if (pos >= value.size() || value[pos++] != '.') return false;
        }
    }
    return pos == value.size();
}

inline std::string NormalizeCountry(const std::string& value) {
    if (value.size() != 2) return {};
    std::string result = value;
    for (char& ch : result) {
        if (ch >= 'a' && ch <= 'z') ch = static_cast<char>(ch - 'a' + 'A');
        else if (ch < 'A' || ch > 'Z') return {};
    }
    return result;
}

struct ExternalIpJsonFields {
    std::string ip;
    std::string origin;
    std::string country;
    std::string org;
};

// Validate the complete JSON document and only capture top-level string fields.
// In particular, an error message containing an escaped "ip" is not an address.
class ExternalIpJsonParser {
public:
    explicit ExternalIpJsonParser(const std::string& text) : text_(text) {}
    bool Parse(ExternalIpJsonFields& fields) {
        pos_ = 0;
        seen_fields_ = 0;
        ExternalIpJsonFields parsed;
        fields_ = &parsed;
        Space();
        if (!Object(0)) return false;
        Space();
        if (pos_ != text_.size()) return false;
        fields = std::move(parsed);
        return true;
    }

private:
    const std::string& text_;
    std::size_t pos_ = 0;
    unsigned seen_fields_ = 0;
    ExternalIpJsonFields* fields_ = nullptr;

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
    bool Hex(unsigned& value) {
        value = 0;
        for (int i = 0; i < 4; ++i) {
            if (pos_ >= text_.size()) return false;
            const char ch = text_[pos_++];
            unsigned digit;
            if (ch >= '0' && ch <= '9') digit = static_cast<unsigned>(ch - '0');
            else if (ch >= 'a' && ch <= 'f') digit = static_cast<unsigned>(ch - 'a' + 10);
            else if (ch >= 'A' && ch <= 'F') digit = static_cast<unsigned>(ch - 'A' + 10);
            else return false;
            value = value * 16 + digit;
        }
        return true;
    }
    static void AppendUtf8(std::string& result, unsigned code) {
        if (code <= 0x7F) result.push_back(static_cast<char>(code));
        else if (code <= 0x7FF) {
            result.push_back(static_cast<char>(0xC0 | (code >> 6)));
            result.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        } else if (code <= 0xFFFF) {
            result.push_back(static_cast<char>(0xE0 | (code >> 12)));
            result.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        } else {
            result.push_back(static_cast<char>(0xF0 | (code >> 18)));
            result.push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
            result.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        }
    }
    bool String(std::string& result) {
        if (!Take('"')) return false;
        result.clear();
        while (pos_ < text_.size()) {
            const unsigned char ch = static_cast<unsigned char>(text_[pos_++]);
            if (ch == '"') return true;
            if (ch < 0x20) return false;
            if (ch >= 0x80) {
                unsigned code;
                unsigned following;
                unsigned minimum;
                if (ch >= 0xC2 && ch <= 0xDF) { code = ch & 0x1F; following = 1; minimum = 0x80; }
                else if (ch >= 0xE0 && ch <= 0xEF) { code = ch & 0x0F; following = 2; minimum = 0x800; }
                else if (ch >= 0xF0 && ch <= 0xF4) { code = ch & 0x07; following = 3; minimum = 0x10000; }
                else return false;
                const std::size_t begin = pos_ - 1;
                for (unsigned i = 0; i < following; ++i) {
                    if (pos_ >= text_.size()) return false;
                    const unsigned char next = static_cast<unsigned char>(text_[pos_++]);
                    if (next < 0x80 || next > 0xBF) return false;
                    code = (code << 6) | (next & 0x3F);
                }
                if (code < minimum || code > 0x10FFFF || (code >= 0xD800 && code <= 0xDFFF)) return false;
                result.append(text_, begin, following + 1);
                continue;
            }
            if (ch != '\\') {
                result.push_back(static_cast<char>(ch));
                continue;
            }
            if (pos_ >= text_.size()) return false;
            switch (text_[pos_++]) {
            case '"': result.push_back('"'); break;
            case '\\': result.push_back('\\'); break;
            case '/': result.push_back('/'); break;
            case 'b': result.push_back('\b'); break;
            case 'f': result.push_back('\f'); break;
            case 'n': result.push_back('\n'); break;
            case 'r': result.push_back('\r'); break;
            case 't': result.push_back('\t'); break;
            case 'u': {
                unsigned code;
                if (!Hex(code)) return false;
                if (code >= 0xD800 && code <= 0xDBFF) {
                    if (pos_ + 2 > text_.size() || text_[pos_++] != '\\' || text_[pos_++] != 'u') return false;
                    unsigned low;
                    if (!Hex(low) || low < 0xDC00 || low > 0xDFFF) return false;
                    code = 0x10000 + ((code - 0xD800) << 10) + low - 0xDC00;
                } else if (code >= 0xDC00 && code <= 0xDFFF) return false;
                AppendUtf8(result, code);
                break;
            }
            default: return false;
            }
        }
        return false;
    }
    bool Object(unsigned depth) {
        if (depth > 32 || !Take('{')) return false;
        if (Take('}')) return true;
        for (;;) {
            std::string key, value;
            if (!String(key) || !Take(':')) return false;
            unsigned field = 0;
            if (depth == 0) {
                if (key == "ip") field = 1;
                else if (key == "origin") field = 2;
                else if (key == "country") field = 4;
                else if (key == "org") field = 8;
                if (seen_fields_ & field) return false;
                seen_fields_ |= field;
            }
            Space();
            const bool is_string = pos_ < text_.size() && text_[pos_] == '"';
            if (is_string ? !String(value) : !Value(depth + 1)) return false;
            if (depth == 0 && is_string) {
                if (key == "ip") fields_->ip = value;
                else if (key == "origin") fields_->origin = value;
                else if (key == "country") fields_->country = value;
                else if (key == "org") fields_->org = value;
            }
            if (Take('}')) return true;
            if (!Take(',')) return false;
        }
    }
    bool Value(unsigned depth) {
        if (depth > 32) return false;
        Space();
        if (pos_ >= text_.size()) return false;
        const char ch = text_[pos_];
        if (ch == '{') return Object(depth);
        if (ch == '"') { std::string ignored; return String(ignored); }
        if (ch == '[') {
            ++pos_;
            if (Take(']')) return true;
            for (;;) {
                if (!Value(depth + 1)) return false;
                if (Take(']')) return true;
                if (!Take(',')) return false;
            }
        }
        for (const char* literal : {"true", "false", "null"}) {
            const std::string token = literal;
            if (text_.compare(pos_, token.size(), token) == 0) {
                pos_ += token.size();
                return true;
            }
        }
        if (ch == '-') ++pos_;
        if (pos_ >= text_.size()) return false;
        if (text_[pos_] == '0') ++pos_;
        else {
            if (text_[pos_] < '1' || text_[pos_] > '9') return false;
            while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') ++pos_;
        }
        if (pos_ < text_.size() && text_[pos_] == '.') {
            const std::size_t begin = ++pos_;
            while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') ++pos_;
            if (pos_ == begin) return false;
        }
        if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < text_.size() && (text_[pos_] == '+' || text_[pos_] == '-')) ++pos_;
            const std::size_t begin = pos_;
            while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') ++pos_;
            if (pos_ == begin) return false;
        }
        return true;
    }
};

} // namespace detail
} // namespace iputils
