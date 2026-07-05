#include <cassert>
#include <iostream>

#include "src/ip_utils.cpp"

int main() {
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ie_proxy{};
    ie_proxy.lpszProxy = const_cast<LPWSTR>(L"http=127.0.0.1:10809;https=127.0.0.1:10809");
    ie_proxy.lpszProxyBypass = const_cast<LPWSTR>(L"localhost;127.*");

    WINHTTP_PROXY_INFO proxy_info{};
    bool has_proxy = BuildProxyInfoFromIeConfigForUrl(
        ie_proxy, L"https://ipinfo.io/json", proxy_info);

    assert(has_proxy);
    assert(proxy_info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY);
    assert(proxy_info.lpszProxy != nullptr);
    assert(std::wstring(proxy_info.lpszProxy).find(L"127.0.0.1:10809") != std::wstring::npos);
    assert(proxy_info.lpszProxyBypass != nullptr);
    assert(std::wstring(proxy_info.lpszProxyBypass).find(L"localhost") != std::wstring::npos);

    FreeProxyInfo(proxy_info);
    std::cout << "proxy config test passed\n";
    return 0;
}

