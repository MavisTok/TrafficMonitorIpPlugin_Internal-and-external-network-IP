#include <iostream>
#include "../src/exit_detection.h"

using namespace exit_detection;

namespace {

int g_failures = 0;

void Check(bool condition, const char* expression, const char* file, int line) {
    if (!condition) {
        std::cerr << file << ':' << line << " CHECK failed: " << expression << '\n';
        ++g_failures;
    }
}

} // namespace

#define CHECK(expression) Check(static_cast<bool>(expression), #expression, __FILE__, __LINE__)

int main() {
    using namespace std::chrono;

    CHECK(EvaluateRefresh(false, false, steady_clock::duration::zero(), false) ==
          RefreshDecision::Start);
    CHECK(EvaluateRefresh(true, false, minutes(9), false) == RefreshDecision::Skip);
    CHECK(EvaluateRefresh(true, false, minutes(10), false) == RefreshDecision::Start);
    CHECK(EvaluateRefresh(true, false, minutes(1), true) == RefreshDecision::Start);
    CHECK(EvaluateRefresh(true, true, minutes(10), false) == RefreshDecision::Skip);
    CHECK(EvaluateRefresh(true, true, minutes(1), true) == RefreshDecision::QueueForced);
    CHECK(EvaluateRefresh(true, false, minutes(10) - steady_clock::duration(1), false) ==
          RefreshDecision::Skip);
    CHECK(EvaluateRefresh(true, false, minutes(10), false) == RefreshDecision::Start);
    CHECK(EvaluateRefresh(true, false, -minutes(1), false) == RefreshDecision::Skip);

    RefreshQueueState queue_state{};
    StartRefreshQueue(queue_state);
    CHECK(queue_state.refresh_in_flight);
    CHECK(QueueForcedRefresh(queue_state));
    CHECK(QueueForcedRefresh(queue_state));
    CHECK(CompleteRefreshIteration(queue_state) == RefreshCompletionDecision::RunAgain);
    CHECK(queue_state.refresh_in_flight);
    CHECK(!QueueForcedRefresh(queue_state));
    CHECK(CompleteRefreshIteration(queue_state) == RefreshCompletionDecision::Stop);
    CHECK(!queue_state.refresh_in_flight);

    CHECK(NormalizeCountryCode(L"jp") == L"JP");
    CHECK(NormalizeCountryCode(L"USA").empty());
    CHECK(NormalizeCountryCode(L"1P").empty());
    CHECK(NormalizeCountryCode(L"").empty());

    CHECK(ParseGoogleMappingIp("203.0.113.7 => cache.googlevideo.com\n") == L"203.0.113.7");
    CHECK(ParseGoogleMappingIp("not-an-ip => cache\n").empty());
    CHECK(ParseGoogleMappingIp("1.2.3.4. => cache\n").empty());
    CHECK(ParseGoogleMappingIp("").empty());

    CHECK(ParseYouTubeCountry(R"({"countryCode":"jp","premium":true})") == L"JP");
    CHECK(ParseYouTubeCountry(R"({"premium":true})").empty());
    CHECK(ParseYouTubeCountry(R"({"countryCode":"jp","nested":{"countryCode":"us"}})").empty());
    CHECK(ParseYouTubeCountry(R"({"countryCode":"jp","nested":{"countryCode":"JP"}})") == L"JP");
    CHECK(ParseYouTubeCountry("{\"note\":\"escaped \\\"countryCode\\\":\\\"us\\\"\",\"countryCode\":\"jp\"}") == L"JP");
    CHECK(ParseYouTubeCountry(R"({"countryCode":"jp})").empty());
    CHECK(ParseYouTubeCountry(R"(["countryCode":"jp"])").empty());
    CHECK(ParseYouTubeCountry(R"(<html>[ broken { <script>{"countryCode":"jp"}</script></html>)") == L"JP");
    CHECK(ParseYouTubeCountry("{\"countryCode\":\"j\\p\"}").empty());
    CHECK(ParseYouTubeCountry(R"({"note":"countryCode":"jp"})").empty());
    CHECK(ParseYouTubeCountry(R"({"countryCode":"US"garbage})").empty());
    CHECK(ParseYouTubeCountry(R"({"countryCode":"US"])").empty());
    CHECK(ParseYouTubeCountry(R"(<script>const fake='{"countryCode":"US"}';</script>)").empty());
    CHECK(ParseYouTubeCountry(R"(<script>const fake=`{"countryCode":"US"}`;</script>)").empty());
    CHECK(ParseYouTubeCountry(R"(<script>const fake='escaped\' quote {"countryCode":"US"}';</script>)").empty());
    CHECK(ParseYouTubeCountry(R"(<script>const data={"countryCode":"JP"};</script>)") == L"JP");
    CHECK(ParseYouTubeCountry(R"(<SCRIPT>const fake='{"countryCode":"US"}';</SCRIPT>)").empty());
    CHECK(ParseYouTubeCountry(R"(<ScRiPt>const fake=`{"countryCode":"US"}`;</sCrIpT>)").empty());
    CHECK(ParseYouTubeCountry(R"(<SCRIPT>const data={"countryCode":"JP"};</SCRIPT>)") == L"JP");
    CHECK(ParseYouTubeCountry(R"({"WEB_PLAYER_CONTEXT_CONFIG":{"contentRegion":"JP","hl":"ja_JP"}})") == L"JP");

    CHECK(ParseTraceCountry("ip=203.0.113.8\nloc=sg\ncolo=SIN\n") == L"SG");
    CHECK(ParseTraceCountry("location=US\n").empty());

    CHECK(ParseNetflixCountry(R"({"id":"HK","countryName":"Hong Kong"})") == L"HK");
    CHECK(ParseNetflixCountry(R"({"countryName":"Hong Kong"})").empty());
    CHECK(ParseNetflixCountry(R"({"a":{"id":"US"},"b":{"countryName":"Hong Kong"}})").empty());
    CHECK(ParseNetflixCountry(R"({"id":"HK","countryName":)").empty());
    CHECK(ParseNetflixCountry(R"({"id":"HK","countryName":"Hong Kong","countryName":})").empty());
    CHECK(ParseNetflixCountry(R"({"id":"US","countryName":"United States","id":"CA","countryName":"Canada"})").empty());
    CHECK(ParseNetflixCountry(R"({"countryName":"Hong Kong","id":"HK"})").empty());
    CHECK(ParseNetflixCountry(R"(<html>[ broken <script>{"id":"HK","countryName":"Hong Kong"}</script></html>)") == L"HK");
    CHECK(ParseNetflixCountry(R"({"id":"HK","countryName":"Hong Kong"garbage})").empty());
    CHECK(ParseNetflixCountry(R"(<html lang="en-US"><script>{"countryName":"United States","defaultLocale":"en","status":"ALLOW"}</script></html>)") == L"US");
    CHECK(ParseNetflixCountry(R"(<script>{"contentRegion":"JP"}</script>)") == L"JP");
    CHECK(ParseNetflixCountry(R"(<html><head><meta data-rh="true" property="og:locale" content="en-US"/></head></html>)") == L"US");
    CHECK(ParseNetflixCountry(R"(<html lang="en-JP"><meta property="og:locale" content="en-JP"/>)") == L"JP");
    CHECK(ParseNetflixCountry(R"(<html><meta property="og:locale" content="en-US"/>)") == L"US");

    CHECK(ParseIpInfoCountry(R"({"ip":"203.0.113.7","country":"us"})") == L"US");
    CHECK(ParseIpInfoCountry(R"({"country":"USA"})").empty());
    CHECK(ParseIpInfoCountry(R"({"country":"us","nested":{"country":"ca"}})").empty());
    CHECK(ParseIpInfoCountry("").empty());
    CHECK(ParseIpInfoCountry(R"(<html>} broken ] <script>{"country":"us"}</script></html>)") == L"US");
    CHECK(ParseIpInfoCountry("{\"country\":\"u\\s\"}").empty());
    CHECK(ParseIpInfoCountry(R"({"note":"country":"us"})").empty());
    CHECK(ParseIpInfoCountry(R"({"country":"JP":false})").empty());
    CHECK(ParseIpInfoCountry(R"({"country":"JP"])").empty());

    CHECK(CountryFlag(L"HK") == L"🇭🇰");
    CHECK(CountryFlag(L"JP") == L"🇯🇵");
    CHECK(CountryFlag(L"US") == L"🇺🇸");
    CHECK(CountryFlag(L"SG") == L"🇸🇬");
    CHECK(CountryFlag(L"zz").empty());
    CHECK(CountryFlag(L"1P").empty());

    CHECK(CountryName(L"HK") == L"Hong Kong");
    CHECK(CountryName(L"JP") == L"Japan");
    CHECK(CountryName(L"US") == L"United States");
    CHECK(CountryName(L"SG") == L"Singapore");
    CHECK(CountryName(L"ZZ") == L"ZZ");
    CHECK(CountryName(L"1P").empty());

    const Snapshot initial = MakeInitialSnapshot();
    CHECK(!initial.has_completed);
    CHECK(!initial.refresh_in_flight);
    CHECK(initial.sites.size() == 5);
    for (std::size_t i = 0; i < initial.sites.size(); ++i) {
        CHECK(initial.sites[i].site == static_cast<Site>(i));
        CHECK(initial.sites[i].state == ResultState::Pending);
        CHECK(initial.sites[i].country_code.empty());
    }

    const std::wstring initial_tooltip = FormatTooltip(initial);
    CHECK(initial_tooltip.find(L"---- Exit Check ----") != std::wstring::npos);
    CHECK(initial_tooltip.find(L"Google") != std::wstring::npos);
    CHECK(initial_tooltip.find(L"Google  ->") != std::wstring::npos);
    CHECK(initial_tooltip.find(L"YouTube ->") != std::wstring::npos);
    CHECK(initial_tooltip.find(L"Netflix ->") != std::wstring::npos);
    CHECK(initial_tooltip.find(L"->") != std::wstring::npos);
    CHECK(initial_tooltip.find(L"-- WAIT") != std::wstring::npos);
    CHECK(initial_tooltip.find(L"GitHub") == std::wstring::npos);
    CHECK(initial_tooltip.find(L'\t') == std::wstring::npos);

    Snapshot compact_ready = MakeInitialSnapshot();
    compact_ready.has_completed = true;
    compact_ready.sites[0] = {Site::Google, ResultState::Success, L"HK"};
    compact_ready.sites[1] = {Site::YouTube, ResultState::Success, L"JP"};
    compact_ready.sites[2] = {Site::OpenAI, ResultState::Success, L"US"};
    compact_ready.sites[3] = {Site::Claude, ResultState::Success, L"SG"};
    compact_ready.sites[4] = {Site::Netflix, ResultState::Success, L"JP"};
    const std::wstring compact_tooltip = FormatTooltip(compact_ready);
    CHECK(compact_tooltip.find(L"Google") != std::wstring::npos);
    CHECK(compact_tooltip.find(L"HK GGL") != std::wstring::npos);
    CHECK(compact_tooltip.find(L"JP GGL") != std::wstring::npos);
    CHECK(compact_tooltip.find(L"US CF") != std::wstring::npos);
    CHECK(compact_tooltip.find(L"SG CF") != std::wstring::npos);
    CHECK(compact_tooltip.find(L"JP NFLX") != std::wstring::npos);
    CHECK(compact_tooltip.find(L"\t") == std::wstring::npos);
    CHECK(compact_tooltip.find(L"🇭") == std::wstring::npos);

    compact_ready.sites[0] = {Site::Google, ResultState::Success, L"1P"};
    CHECK(FormatTooltip(compact_ready).find(L"-- ----") != std::wstring::npos);

    if (g_failures > 0) {
        std::cerr << g_failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "exit_detection parser tests passed\n";
    return 0;
}
