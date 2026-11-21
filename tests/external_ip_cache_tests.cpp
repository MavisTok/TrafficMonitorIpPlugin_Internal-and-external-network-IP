#include "../src/external_ip_cache.h"

#include <iostream>

namespace {
int failures = 0;
void Check(bool value, const char* expression, int line) {
    if (!value) {
        std::cerr << "external_ip_cache_tests.cpp:" << line << ": " << expression << '\n';
        ++failures;
    }
}
}
#define CHECK(expression) Check(static_cast<bool>(expression), #expression, __LINE__)

int main() {
    using namespace std::chrono;
    using namespace iputils;
    using namespace iputils::detail;
    const auto start = ExternalIpCacheState::Clock::time_point{};
    ExternalIpOptions options;
    ExternalIpCacheState cache;

    CHECK(!cache.ObserveNetwork(L"192.168.1.2", start, 6));
    CHECK(cache.ShouldRefresh(options, start, false, false));
    cache.Complete(true, start);
    CHECK(cache.has_success);
    CHECK(!cache.ShouldRefresh(options, start + seconds(119), false, false));
    CHECK(cache.ShouldRefresh(options, start + minutes(2), false, false));
    // The first stable hour starts with the first observation, not the clock epoch.
    cache.Complete(true, start + minutes(59));
    CHECK(!cache.ShouldRefresh(options, start + minutes(61), false, false));
    CHECK(cache.ShouldRefresh(options, start + minutes(64), false, false));

    const auto changed_at = start + minutes(65);
    CHECK(cache.ObserveNetwork(L"192.168.1.3", changed_at, 6));
    CHECK(cache.fast_cycles == 6);
    CHECK(cache.ShouldRefresh(options, changed_at, false, true));
    cache.Complete(true, changed_at);
    CHECK(cache.fast_cycles == 5);
    for (int second = 0; second < 30; ++second) {
        CHECK(!cache.ShouldRefresh(options, changed_at + seconds(second), false, false));
        CHECK(cache.fast_cycles == 5);
    }
    CHECK(cache.ShouldRefresh(options, changed_at + seconds(30), false, false));
    cache.Complete(true, changed_at + seconds(30));
    CHECK(cache.fast_cycles == 4);

    // Failure keeps the last successful schedule/snapshot and backs off retries.
    cache.Complete(false, changed_at + seconds(60));
    CHECK(cache.has_success);
    CHECK(cache.last_success == changed_at + seconds(30));
    CHECK(cache.fast_cycles == 4);
    CHECK(!cache.ShouldRefresh(options, changed_at + seconds(89), false, false));
    CHECK(cache.ShouldRefresh(options, changed_at + seconds(90), false, false));
    CHECK(cache.ShouldRefresh(options, changed_at + seconds(61), true, false));
    CHECK(cache.ShouldRefresh(options, changed_at + seconds(61), false, true));
    CHECK(cache.ObserveNetwork(L"", changed_at + seconds(62), 6));
    CHECK(!cache.ObserveNetwork(L"", changed_at + seconds(63), 6));
    CHECK(cache.ObserveNetwork(L"192.168.1.3", changed_at + seconds(64), 6));

    ExternalIpCacheState initially_offline;
    CHECK(!initially_offline.ObserveNetwork(L"", start, 6));
    initially_offline.Complete(false, start);
    CHECK(!initially_offline.ShouldRefresh(options, start + seconds(29), false, false));
    CHECK(initially_offline.ShouldRefresh(options, start + seconds(30), false, false));
    CHECK(initially_offline.ObserveNetwork(L"10.0.0.2", start + seconds(2), 6));

    options.strategy = CacheStrategy::FIXED;
    cache.Complete(true, changed_at + minutes(10));
    CHECK(!cache.ShouldRefresh(options, changed_at + seconds(601), false, true));
    CHECK(cache.ShouldRefresh(options, changed_at + seconds(601), true, true));
    CHECK(!cache.ShouldRefresh(options, changed_at + minutes(11), false, false));
    CHECK(cache.ShouldRefresh(options, changed_at + minutes(12), false, false));
    options.strategy = CacheStrategy::NETWORK_EVENT;
    CHECK(!cache.ShouldRefresh(options, changed_at + minutes(14), false, false));
    CHECK(cache.ShouldRefresh(options, changed_at + minutes(15), false, false));

    ExternalIpRefreshQueue queue;
    queue.Start();
    for (int i = 0; i < 100; ++i) queue.RequestForce();
    CHECK(queue.Complete());
    CHECK(queue.in_flight);
    for (int i = 0; i < 100; ++i) queue.RequestForce();
    CHECK(!queue.Complete());
    CHECK(!queue.in_flight);
    queue.Start();
    CHECK(!queue.Complete());
    queue.Start();
    queue.RequestForce();
    CHECK(queue.Complete());
    CHECK(!queue.Complete());

    for (const std::string value : {"0.0.0.0", "1.2.3.4", "255.255.255.255", "192.168.0.1"})
        CHECK(IsStrictIPv4(value));
    for (const std::string value : {"", "256.1.2.3", "1.2.3", "1.2.3.4.5", "1.2.3.4 ",
                                    " 1.2.3.4", "01.2.3.4", "1..3.4", "::1", "1.2.3.4, 5.6.7.8"})
        CHECK(!IsStrictIPv4(value));
    CHECK(NormalizeCountry("jp") == "JP");
    CHECK(NormalizeCountry("US") == "US");
    CHECK(NormalizeCountry("USA").empty());
    CHECK(NormalizeCountry("U1").empty());
    CHECK(NormalizeCountry("").empty());

    ExternalIpJsonFields fields;
    CHECK(ExternalIpJsonParser(R"({"ip":"1.2.3.4","country":"us","org":"AS1 Example"})").Parse(fields));
    CHECK(fields.ip == "1.2.3.4");
    CHECK(fields.country == "us");
    CHECK(fields.org == "AS1 Example");
    CHECK(ExternalIpJsonParser("{\n\"origin\" \n: \"1.2.3.4\", \"nested\": [true,false,null,-2.3e+4,{}]}\n").Parse(fields));
    CHECK(fields.origin == "1.2.3.4");
    CHECK(fields.ip.empty());
    // Keep escaped raw strings outside CHECK: MSVC's traditional preprocessor
    // does not stringify these literals correctly through #expression.
    const std::string escaped_json = R"({"ip":"\u0031.2.3.4","org":"A \"B\" \\ \u4e2d \ud83c\uddef"})";
    CHECK(ExternalIpJsonParser(escaped_json).Parse(fields));
    CHECK(fields.ip == "1.2.3.4");
    CHECK(fields.org == "A \"B\" \\ \xe4\xb8\xad \xf0\x9f\x87\xaf");
    const std::string nested_json = R"({"nested":{"ip":"1.2.3.4"},"message":"\"ip\":\"5.6.7.8\""})";
    CHECK(ExternalIpJsonParser(nested_json).Parse(fields));
    CHECK(fields.ip.empty());
    for (const std::string value : {
            R"({"ip":"1.2.3.4"})" " garbage",
            R"({"ip":"1.2.3.4")", R"({"ip":"1.2.3.4",})", R"({"ip" "1.2.3.4"})",
            R"({"ip":"1.2.3.4","ip":"5.6.7.8"})", R"({"ip":null,"ip":"5.6.7.8"})",
            R"({"country":"US","country":"JP"})", R"({"org":"A","org":"B"})",
            R"({"ip":"\uD800"})", R"({"ip":"\uDC00"})", R"({"ip":"\x31"})",
            R"({"x":01})", R"({"x":1.})", R"({"x":1e})", R"({"x":tru})", R"([])"})
        CHECK(!ExternalIpJsonParser(value).Parse(fields));
    const std::string nested = std::string(40, '[') + "0" + std::string(40, ']');
    CHECK(!ExternalIpJsonParser("{\"nested\":" + nested + "}").Parse(fields));
    CHECK(ExternalIpJsonParser("{\"org\":\"\xe4\xb8\xad\xf0\x9f\x87\xaf\"}").Parse(fields));
    for (const std::string bytes : {"\x80", "\xc0\xaf", "\xe0\x80\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80"})
        CHECK(!ExternalIpJsonParser("{\"org\":\"" + bytes + "\"}").Parse(fields));

    if (failures == 0) std::cout << "External IP cache and response parser tests passed.\n";
    return failures == 0 ? 0 : 1;
}
