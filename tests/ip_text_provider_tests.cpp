#include "../src/ip_item.h"

#include <iostream>

namespace {
int failures = 0;
int internal_calls = 0;
int external_calls = 0;
bool last_force = false;
std::wstring last_adapter;
std::wstring internal_value = L"192.168.1.8";
iputils::IpWithCountry external_value{L"203.0.113.8", L"JP", L"AS906 DMIT Cloud Services"};
iputils::ExternalIpOptions last_options;

void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        std::cerr << "line " << line << ": " << expression << '\n';
        ++failures;
    }
}

void ResetCounts() {
    internal_calls = 0;
    external_calls = 0;
}
} // namespace

#define CHECK(expression) Check(static_cast<bool>(expression), #expression, __LINE__)

// Substitute only the OS/network boundary. Exercise the production formatter.
namespace iputils {
std::wstring GetInternalIPv4(const std::wstring& adapter) {
    ++internal_calls;
    last_adapter = adapter;
    return internal_value;
}

IpWithCountry GetExternalIPv4WithCountry(const ExternalIpOptions& options, bool force) {
    ++external_calls;
    last_force = force;
    last_options = options;
    return external_value;
}
} // namespace iputils

int main() {
    using namespace std::chrono;
    PluginOptions options;
    options.preferred_adapter = L"Wi-Fi";
    options.external_refresh = minutes(3);
    options.fast_refresh = seconds(12);
    options.max_refresh = minutes(9);
    IpTextProvider provider(options);

    auto snapshot = provider.GetSnapshot(true);
    CHECK(internal_calls == 1);
    CHECK(external_calls == 1);
    CHECK(last_force);
    CHECK(last_adapter == L"Wi-Fi");
    CHECK(snapshot.internal == internal_value);
    CHECK(snapshot.external.ip == external_value.ip);
    CHECK(snapshot.text == L"192.168.1.8 | JP 203.0.113.8");
    CHECK(last_options.strategy == iputils::CacheStrategy::HYBRID);
    CHECK(last_options.min_refresh == minutes(3));
    CHECK(last_options.fast_refresh == seconds(12));
    CHECK(last_options.max_refresh == minutes(9));

    ResetCounts();
    options.enable_smart_cache = false;
    options.show_internal = false;
    provider.SetOptions(options);
    snapshot = provider.GetSnapshot();
    CHECK(internal_calls == 0);
    CHECK(external_calls == 1);
    CHECK(!last_force);
    CHECK(last_options.strategy == iputils::CacheStrategy::FIXED);
    CHECK(snapshot.internal.empty());
    CHECK(snapshot.text == L"DMIT Cloud | JP 203.0.113.8");

    external_value = {};
    snapshot = provider.GetSnapshot();
    CHECK(snapshot.text == L"N/A");
    CHECK(!snapshot.external.IsValid());

    ResetCounts();
    options.show_internal = true;
    options.show_external = false;
    provider.SetOptions(options);
    CHECK(provider.GetText() == internal_value);
    CHECK(internal_calls == 1);
    CHECK(external_calls == 0);

    internal_value.clear();
    CHECK(provider.GetSnapshot().text == L"N/A");

    ResetCounts();
    options.show_internal = false;
    provider.SetOptions(options);
    snapshot = provider.GetSnapshot(true);
    CHECK(snapshot.text == L"请启用IP显示");
    CHECK(internal_calls == 0);
    CHECK(external_calls == 0);

    // A separator may also occur in an address; raw fields remain independent.
    options.show_internal = true;
    options.show_external = true;
    options.separator = L".";
    internal_value = L"192.168.1.8";
    external_value = {L"203.0.113.8", L"JP", L""};
    provider.SetOptions(options);
    snapshot = provider.GetSnapshot();
    CHECK(snapshot.internal == L"192.168.1.8");
    CHECK(snapshot.external.GetDisplayString() == L"JP 203.0.113.8");

    if (failures != 0) return 1;
    std::cout << "IP text provider tests passed\n";
    return 0;
}
