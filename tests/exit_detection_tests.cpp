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

    CHECK(ParseGitHubCountry("server: github.com\r\nx-frame-options: deny\r\n").empty());
    CHECK(ParseGitHubCountry("x-github-country: ca\r\n") == L"CA");
    CHECK(ParseGitHubCountry("X-GitHub-Country: jp\r\n") == L"JP");
    CHECK(ParseGitHubCountry("x-github-country-code: ca\r\n").empty());
    CHECK(ParseGitHubCountry("x-github-country").empty());
    CHECK(ParseGitHubCountry("").empty());

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
    for (std::size_t i = 0; i < initial.sites.size(); ++i) {
        CHECK(initial.sites[i].site == static_cast<Site>(i));
        CHECK(initial.sites[i].state == ResultState::Pending);
        CHECK(initial.sites[i].country_code.empty());
    }

    CHECK(FormatTooltip(initial) ==
          L"---- Exit Check ----\n"
          L"Google\t->\t-- WAIT\n"
          L"YouTube\t->\t-- WAIT\n"
          L"OpenAI\t->\t-- WAIT\n"
          L"Claude\t->\t-- WAIT\n"
          L"GitHub\t->\t-- WAIT\n"
          L"Netflix\t->\t-- WAIT");

    Snapshot compact_ready = MakeInitialSnapshot();
    compact_ready.has_completed = true;
    compact_ready.sites[0] = {Site::Google, ResultState::Success, L"HK"};
    compact_ready.sites[1] = {Site::YouTube, ResultState::Success, L"JP"};
    compact_ready.sites[2] = {Site::OpenAI, ResultState::Success, L"US"};
    compact_ready.sites[3] = {Site::Claude, ResultState::Success, L"SG"};
    compact_ready.sites[4] = {Site::GitHub, ResultState::Unknown, L""};
    compact_ready.sites[5] = {Site::Netflix, ResultState::Success, L"JP"};
    CHECK(FormatTooltip(compact_ready) ==
          L"---- Exit Check ----\n"
          L"Google\t->\tHK GGL\n"
          L"YouTube\t->\tJP GGL\n"
          L"OpenAI\t->\tUS CF\n"
          L"Claude\t->\tSG CF\n"
          L"GitHub\t->\t-- ----\n"
          L"Netflix\t->\tJP NFLX");

    compact_ready.sites[0] = {Site::Google, ResultState::Success, L"1P"};
    CHECK(FormatTooltip(compact_ready).find(L"Google\t->\t-- ----") != std::wstring::npos);

#if 0
    const std::wstring pending_tooltip = FormatTooltip(initial);
    CHECK(pending_tooltip.find(L"──────── 出口检测 ────────") != std::wstring::npos);
    CHECK(pending_tooltip.find(L"Google   → ⏳ Detecting...") != std::wstring::npos);
    CHECK(pending_tooltip.find(L"YouTube  → ⏳ Detecting...") != std::wstring::npos);

    Snapshot ready = MakeInitialSnapshot();
    ready.has_completed = true;
    ready.sites[0] = {Site::Google, ResultState::Success, L"HK"};
    ready.sites[1] = {Site::YouTube, ResultState::Success, L"JP"};
    ready.sites[2] = {Site::OpenAI, ResultState::Success, L"US"};
    ready.sites[3] = {Site::Claude, ResultState::Success, L"SG"};
    ready.sites[4] = {Site::GitHub, ResultState::Unknown, L""};
    ready.sites[5] = {Site::Netflix, ResultState::Success, L"JP"};
    CHECK(FormatTooltip(ready) ==
          L"──────── 出口检测 ────────\n"
          L"Google   → 🇭🇰 Hong Kong\n"
          L"YouTube  → 🇯🇵 Japan\n"
          L"OpenAI   → 🇺🇸 United States\n"
          L"Claude   → 🇸🇬 Singapore\n"
          L"GitHub   → ❔ Unknown\n"
          L"Netflix  → 🇯🇵 Japan");

    Snapshot first_batch = ready;
    first_batch.has_completed = false;
    CHECK(FormatTooltip(first_batch) ==
          L"──────── 出口检测 ────────\n"
          L"Google   → ⏳ Detecting...\n"
          L"YouTube  → ⏳ Detecting...\n"
          L"OpenAI   → ⏳ Detecting...\n"
          L"Claude   → ⏳ Detecting...\n"
          L"GitHub   → ⏳ Detecting...\n"
          L"Netflix  → ⏳ Detecting...");

    ready.sites[0] = {Site::Google, ResultState::Success, L"1P"};
    CHECK(FormatTooltip(ready).find(L"Google   → ❔ Unknown") != std::wstring::npos);

#endif

    if (g_failures > 0) {
        std::cerr << g_failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "exit_detection parser tests passed\n";
    return 0;
}
