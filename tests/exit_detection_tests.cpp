#include <cassert>
#include <iostream>
#include "../src/exit_detection.h"

using namespace exit_detection;

int main() {
    assert(NormalizeCountryCode(L"jp") == L"JP");
    assert(NormalizeCountryCode(L"USA").empty());
    assert(NormalizeCountryCode(L"1P").empty());
    assert(NormalizeCountryCode(L"").empty());

    assert(ParseGoogleMappingIp("203.0.113.7 => cache.googlevideo.com\n") == L"203.0.113.7");
    assert(ParseGoogleMappingIp("not-an-ip => cache\n").empty());
    assert(ParseGoogleMappingIp("1.2.3.4. => cache\n").empty());
    assert(ParseGoogleMappingIp("").empty());

    assert(ParseYouTubeCountry(R"({"countryCode":"jp","premium":true})") == L"JP");
    assert(ParseYouTubeCountry(R"({"premium":true})").empty());
    assert(ParseYouTubeCountry(R"({"countryCode":"jp","nested":{"countryCode":"us"}})").empty());
    assert(ParseYouTubeCountry(R"({"countryCode":"jp","nested":{"countryCode":"JP"}})") == L"JP");
    assert(ParseYouTubeCountry(R"({"note":"escaped \"countryCode\":\"us\"","countryCode":"jp"})") == L"JP");
    assert(ParseYouTubeCountry(R"({"countryCode":"jp})").empty());
    assert(ParseYouTubeCountry(R"(["countryCode":"jp"])").empty());

    assert(ParseTraceCountry("ip=203.0.113.8\nloc=sg\ncolo=SIN\n") == L"SG");
    assert(ParseTraceCountry("location=US\n").empty());

    assert(ParseNetflixCountry(R"({"id":"HK","countryName":"Hong Kong"})") == L"HK");
    assert(ParseNetflixCountry(R"({"countryName":"Hong Kong"})").empty());
    assert(ParseNetflixCountry(R"({"a":{"id":"US"},"b":{"countryName":"Hong Kong"}})").empty());
    assert(ParseNetflixCountry(R"({"id":"HK","countryName":)").empty());
    assert(ParseNetflixCountry(R"({"id":"US","countryName":"United States","id":"CA","countryName":"Canada"})").empty());
    assert(ParseNetflixCountry(R"({"countryName":"Hong Kong","id":"HK"})").empty());

    assert(ParseIpInfoCountry(R"({"ip":"203.0.113.7","country":"us"})") == L"US");
    assert(ParseIpInfoCountry(R"({"country":"USA"})").empty());
    assert(ParseIpInfoCountry(R"({"country":"us","nested":{"country":"ca"}})").empty());
    assert(ParseIpInfoCountry("").empty());

    assert(ParseGitHubCountry("server: github.com\r\nx-frame-options: deny\r\n").empty());
    assert(ParseGitHubCountry("x-github-country: ca\r\n") == L"CA");
    assert(ParseGitHubCountry("X-GitHub-Country: jp\r\n") == L"JP");
    assert(ParseGitHubCountry("x-github-country-code: ca\r\n").empty());
    assert(ParseGitHubCountry("x-github-country").empty());
    assert(ParseGitHubCountry("").empty());

    std::cout << "exit_detection parser tests passed\n";
    return 0;
}
