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
    CHECK(ParseYouTubeCountry(R"({"note":"escaped \"countryCode\":\"us\"","countryCode":"jp"})") == L"JP");
    CHECK(ParseYouTubeCountry(R"({"countryCode":"jp})").empty());
    CHECK(ParseYouTubeCountry(R"(["countryCode":"jp"])").empty());
    CHECK(ParseYouTubeCountry(R"(<html>[ broken { <script>{"countryCode":"jp"}</script></html>)") == L"JP");
    CHECK(ParseYouTubeCountry(R"({"countryCode":"j\p"})").empty());
    CHECK(ParseYouTubeCountry(R"({"note":"countryCode":"jp"})").empty());
    CHECK(ParseYouTubeCountry(R"({"countryCode":"US"garbage})").empty());
    CHECK(ParseYouTubeCountry(R"(<script>const fake='{"countryCode":"US"}';</script>)").empty());
    CHECK(ParseYouTubeCountry(R"(<script>const fake=`{"countryCode":"US"}`;</script>)").empty());
    CHECK(ParseYouTubeCountry(R"(<script>const fake='escaped\' quote {"countryCode":"US"}';</script>)").empty());
    CHECK(ParseYouTubeCountry(R"(<script>const data={"countryCode":"JP"};</script>)") == L"JP");

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

    CHECK(ParseIpInfoCountry(R"({"ip":"203.0.113.7","country":"us"})") == L"US");
    CHECK(ParseIpInfoCountry(R"({"country":"USA"})").empty());
    CHECK(ParseIpInfoCountry(R"({"country":"us","nested":{"country":"ca"}})").empty());
    CHECK(ParseIpInfoCountry("").empty());
    CHECK(ParseIpInfoCountry(R"(<html>} broken ] <script>{"country":"us"}</script></html>)") == L"US");
    CHECK(ParseIpInfoCountry(R"({"country":"u\s"})").empty());
    CHECK(ParseIpInfoCountry(R"({"note":"country":"us"})").empty());
    CHECK(ParseIpInfoCountry(R"({"country":"JP":false})").empty());

    CHECK(ParseGitHubCountry("server: github.com\r\nx-frame-options: deny\r\n").empty());
    CHECK(ParseGitHubCountry("x-github-country: ca\r\n") == L"CA");
    CHECK(ParseGitHubCountry("X-GitHub-Country: jp\r\n") == L"JP");
    CHECK(ParseGitHubCountry("x-github-country-code: ca\r\n").empty());
    CHECK(ParseGitHubCountry("x-github-country").empty());
    CHECK(ParseGitHubCountry("").empty());

    if (g_failures > 0) {
        std::cerr << g_failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "exit_detection parser tests passed\n";
    return 0;
}
