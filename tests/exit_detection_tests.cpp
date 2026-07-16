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

    assert(ParseYouTubeCountry(R"({"countryCode":"jp","premium":true})") == L"JP");
    assert(ParseYouTubeCountry(R"({"premium":true})").empty());

    assert(ParseTraceCountry("ip=203.0.113.8\nloc=sg\ncolo=SIN\n") == L"SG");
    assert(ParseTraceCountry("location=US\n").empty());

    assert(ParseNetflixCountry(R"({"id":"HK","countryName":"Hong Kong"})") == L"HK");
    assert(ParseNetflixCountry(R"({"countryName":"Hong Kong"})").empty());

    assert(ParseIpInfoCountry(R"({"ip":"203.0.113.7","country":"us"})") == L"US");
    assert(ParseIpInfoCountry(R"({"country":"USA"})").empty());

    assert(ParseGitHubCountry("server: github.com\r\nx-frame-options: deny\r\n").empty());
    assert(ParseGitHubCountry("x-github-country: ca\r\n") == L"CA");

    std::cout << "exit_detection parser tests passed\n";
    return 0;
}
