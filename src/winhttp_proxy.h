#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>
#include <memory>
#include <new>

namespace winhttp_proxy {

struct InternetHandleCloser {
    void operator()(void* handle) const noexcept {
        if (handle) WinHttpCloseHandle(handle);
    }
};
using InternetHandle = std::unique_ptr<void, InternetHandleCloser>;

inline wchar_t* DuplicateWideString(LPCWSTR value) {
    if (value == nullptr || *value == L'\0') {
        return nullptr;
    }
    const std::size_t length = wcslen(value);
    std::unique_ptr<wchar_t[]> copy(new (std::nothrow) wchar_t[length + 1]);
    if (!copy) {
        return nullptr;
    }
    wcscpy_s(copy.get(), length + 1, value);
    return copy.release();
}

inline void FreeProxyInfo(WINHTTP_PROXY_INFO& proxy_info) noexcept {
    delete[] proxy_info.lpszProxy;
    delete[] proxy_info.lpszProxyBypass;
    proxy_info = {};
}

inline void FreeIeProxyConfig(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG& ie_proxy) noexcept {
    if (ie_proxy.lpszAutoConfigUrl != nullptr) {
        GlobalFree(ie_proxy.lpszAutoConfigUrl);
    }
    if (ie_proxy.lpszProxy != nullptr) {
        GlobalFree(ie_proxy.lpszProxy);
    }
    if (ie_proxy.lpszProxyBypass != nullptr) {
        GlobalFree(ie_proxy.lpszProxyBypass);
    }
    ie_proxy = {};
}

struct ProxyInfoOwner {
    WINHTTP_PROXY_INFO value{};
    ~ProxyInfoOwner() { FreeProxyInfo(value); }
};

struct IeProxyConfigOwner {
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG value{};
    ~IeProxyConfigOwner() { FreeIeProxyConfig(value); }
};

inline bool BuildProxyInfoFromIeConfigForUrl(
    const WINHTTP_CURRENT_USER_IE_PROXY_CONFIG& ie_proxy,
    LPCWSTR url,
    WINHTTP_PROXY_INFO& proxy_info) {
    proxy_info = {};
    if (ie_proxy.lpszProxy != nullptr && *ie_proxy.lpszProxy != L'\0') {
        proxy_info.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        proxy_info.lpszProxy = DuplicateWideString(ie_proxy.lpszProxy);
        proxy_info.lpszProxyBypass = DuplicateWideString(ie_proxy.lpszProxyBypass);
        return proxy_info.lpszProxy != nullptr;
    }
    if (url == nullptr || *url == L'\0' ||
        (!ie_proxy.fAutoDetect && ie_proxy.lpszAutoConfigUrl == nullptr)) {
        return false;
    }

    WINHTTP_AUTOPROXY_OPTIONS options{};
    if (ie_proxy.fAutoDetect) {
        options.dwFlags |= WINHTTP_AUTOPROXY_AUTO_DETECT;
        options.dwAutoDetectFlags =
            WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
    }
    if (ie_proxy.lpszAutoConfigUrl != nullptr && *ie_proxy.lpszAutoConfigUrl != L'\0') {
        options.dwFlags |= WINHTTP_AUTOPROXY_CONFIG_URL;
        options.lpszAutoConfigUrl = ie_proxy.lpszAutoConfigUrl;
    }
    options.fAutoLogonIfChallenged = TRUE;

    InternetHandle session(WinHttpOpen(L"TrafficMonitorIpPlugin/1.0",
                                       WINHTTP_ACCESS_TYPE_NO_PROXY,
                                       WINHTTP_NO_PROXY_NAME,
                                       WINHTTP_NO_PROXY_BYPASS,
                                       0));
    if (!session) {
        return false;
    }

    WINHTTP_PROXY_INFO detected{};
    const bool found = !!WinHttpGetProxyForUrl(session.get(), url, &options, &detected);
    if (!found || detected.dwAccessType != WINHTTP_ACCESS_TYPE_NAMED_PROXY ||
        detected.lpszProxy == nullptr || *detected.lpszProxy == L'\0') {
        if (detected.lpszProxy != nullptr) GlobalFree(detected.lpszProxy);
        if (detected.lpszProxyBypass != nullptr) GlobalFree(detected.lpszProxyBypass);
        return false;
    }

    proxy_info.dwAccessType = detected.dwAccessType;
    proxy_info.lpszProxy = DuplicateWideString(detected.lpszProxy);
    proxy_info.lpszProxyBypass = DuplicateWideString(detected.lpszProxyBypass);
    GlobalFree(detected.lpszProxy);
    if (detected.lpszProxyBypass != nullptr) GlobalFree(detected.lpszProxyBypass);
    return proxy_info.lpszProxy != nullptr;
}

inline bool ApplyCurrentUserProxyForRequest(HINTERNET request, LPCWSTR url) {
    IeProxyConfigOwner ie_proxy;
    if (!WinHttpGetIEProxyConfigForCurrentUser(&ie_proxy.value)) {
        return false;
    }
    ProxyInfoOwner proxy_info;
    if (!BuildProxyInfoFromIeConfigForUrl(ie_proxy.value, url, proxy_info.value)) {
        return false;
    }
    return !!WinHttpSetOption(request,
                              WINHTTP_OPTION_PROXY,
                              &proxy_info.value,
                              sizeof(proxy_info.value));
}

} // namespace winhttp_proxy
