/**
 * @file ip_utils.cpp
 * @brief TrafficMonitor IP插件的IP地址获取工具实现
 * @details 包含内网IPv4地址获取和外网IPv4地址获取的核心功能
 *          内网IP获取支持智能优先级选择（优先192.168.x.x网段）
 *          外网IP获取支持缓存机制以减少网络请求
 * @author Lynn
 * @date 2025
 */

#include "ip_utils.h"
#include "external_ip_cache.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN  // 减少Windows头文件的包含内容，提高编译速度
#endif
#ifndef NOMINMAX
#define NOMINMAX  // 避免Windows.h中定义的min/max宏与std::min/max冲突
#endif

#include <windows.h>
#include <winsock2.h>  // Windows套接字API
#include <iphlpapi.h>  // IP Helper API，用于获取网络适配器信息
#include <ws2tcpip.h>  // TCP/IP辅助函数
#include <winhttp.h>   // Windows HTTP客户端API

#include <vector>
#include <mutex>       // 用于外网IP获取的线程同步
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <new>
#include <thread>

// 链接必需的系统库
#pragma comment(lib, "Iphlpapi.lib")  // IP Helper API库
#pragma comment(lib, "Ws2_32.lib")    // Winsock 2.0库
#pragma comment(lib, "Winhttp.lib")   // WinHTTP库

static wchar_t* DuplicateWideString(LPCWSTR value) {
    if (!value || !*value) return nullptr;
    const size_t length = wcslen(value);
    wchar_t* copy = new (std::nothrow) wchar_t[length + 1];
    if (!copy) return nullptr;
    wcscpy_s(copy, length + 1, value);
    return copy;
}

static void FreeProxyInfo(WINHTTP_PROXY_INFO& proxy_info) {
    delete[] proxy_info.lpszProxy;
    delete[] proxy_info.lpszProxyBypass;
    proxy_info = {};
}

static void FreeIeProxyConfig(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG& ie_proxy) {
    if (ie_proxy.lpszAutoConfigUrl) {
        GlobalFree(ie_proxy.lpszAutoConfigUrl);
        ie_proxy.lpszAutoConfigUrl = nullptr;
    }
    if (ie_proxy.lpszProxy) {
        GlobalFree(ie_proxy.lpszProxy);
        ie_proxy.lpszProxy = nullptr;
    }
    if (ie_proxy.lpszProxyBypass) {
        GlobalFree(ie_proxy.lpszProxyBypass);
        ie_proxy.lpszProxyBypass = nullptr;
    }
}

struct InternetHandleCloser {
    void operator()(void* handle) const noexcept {
        if (handle) WinHttpCloseHandle(handle);
    }
};
using InternetHandle = std::unique_ptr<void, InternetHandleCloser>;

struct ProxyInfoOwner {
    WINHTTP_PROXY_INFO value{};
    ~ProxyInfoOwner() { FreeProxyInfo(value); }
};

struct IeProxyConfigOwner {
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG value{};
    ~IeProxyConfigOwner() { FreeIeProxyConfig(value); }
};

static bool BuildProxyInfoFromIeConfigForUrl(
    const WINHTTP_CURRENT_USER_IE_PROXY_CONFIG& ie_proxy,
    LPCWSTR url,
    WINHTTP_PROXY_INFO& proxy_info) {
    proxy_info = {};

    if (ie_proxy.lpszProxy && *ie_proxy.lpszProxy) {
        proxy_info.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
        proxy_info.lpszProxy = DuplicateWideString(ie_proxy.lpszProxy);
        proxy_info.lpszProxyBypass = DuplicateWideString(ie_proxy.lpszProxyBypass);
        return proxy_info.lpszProxy != nullptr;
    }

    if (!url || !*url || (!ie_proxy.fAutoDetect && !ie_proxy.lpszAutoConfigUrl)) {
        return false;
    }

    WINHTTP_AUTOPROXY_OPTIONS auto_proxy_options{};
    if (ie_proxy.fAutoDetect) {
        auto_proxy_options.dwFlags |= WINHTTP_AUTOPROXY_AUTO_DETECT;
        auto_proxy_options.dwAutoDetectFlags =
            WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
    }
    if (ie_proxy.lpszAutoConfigUrl && *ie_proxy.lpszAutoConfigUrl) {
        auto_proxy_options.dwFlags |= WINHTTP_AUTOPROXY_CONFIG_URL;
        auto_proxy_options.lpszAutoConfigUrl = ie_proxy.lpszAutoConfigUrl;
    }
    auto_proxy_options.fAutoLogonIfChallenged = TRUE;

    InternetHandle hSession(WinHttpOpen(L"TrafficMonitorIpPlugin/1.0",
                                     WINHTTP_ACCESS_TYPE_NO_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0));
    if (!hSession) return false;
    if (!WinHttpSetTimeouts(hSession.get(), 3000, 3000, 3000, 5000)) return false;

    WINHTTP_PROXY_INFO detected_proxy{};
    const bool detected = !!WinHttpGetProxyForUrl(
        hSession.get(), url, &auto_proxy_options, &detected_proxy);

    if (!detected || detected_proxy.dwAccessType != WINHTTP_ACCESS_TYPE_NAMED_PROXY ||
        !detected_proxy.lpszProxy || !*detected_proxy.lpszProxy) {
        if (detected_proxy.lpszProxy) GlobalFree(detected_proxy.lpszProxy);
        if (detected_proxy.lpszProxyBypass) GlobalFree(detected_proxy.lpszProxyBypass);
        return false;
    }

    proxy_info.dwAccessType = detected_proxy.dwAccessType;
    proxy_info.lpszProxy = DuplicateWideString(detected_proxy.lpszProxy);
    proxy_info.lpszProxyBypass = DuplicateWideString(detected_proxy.lpszProxyBypass);
    GlobalFree(detected_proxy.lpszProxy);
    if (detected_proxy.lpszProxyBypass) GlobalFree(detected_proxy.lpszProxyBypass);
    return proxy_info.lpszProxy != nullptr;
}

static bool ApplyCurrentUserProxyForRequest(HINTERNET hRequest, LPCWSTR url) {
    IeProxyConfigOwner ie_proxy;
    if (!WinHttpGetIEProxyConfigForCurrentUser(&ie_proxy.value)) {
        return false;
    }

    ProxyInfoOwner proxy_info;
    const bool has_proxy = BuildProxyInfoFromIeConfigForUrl(ie_proxy.value, url, proxy_info.value);
    bool applied = false;
    if (has_proxy) {
        applied = !!WinHttpSetOption(
            hRequest, WINHTTP_OPTION_PROXY, &proxy_info.value, sizeof(proxy_info.value));
    }

    return applied;
}

namespace iputils {

/**
 * @brief 检查sockaddr是否为有效的IPv4地址
 * @param sa sockaddr结构指针
 * @return true表示是有效的IPv4地址，false表示无效
 * @details 过滤掉空地址、非IPv4地址、回环地址(127.0.0.1)和0.0.0.0地址
 */
static bool IsValidIPv4(const sockaddr* sa) {
    // 检查指针有效性和地址族
    if (!sa || sa->sa_family != AF_INET) return false;
    
    const sockaddr_in* sin = reinterpret_cast<const sockaddr_in*>(sa);
    const uint32_t addr = ntohl(sin->sin_addr.S_un.S_addr);  // 转换为主机字节序
    
    // 排除回环地址 127.0.0.1
    if (addr == 0x7F000001) return false; 
    
    // 排除0.0.0.0地址
    return sin->sin_addr.S_un.S_addr != 0;
}

/**
 * @brief IP地址优先级判断函数，用于选择最合适的内网IP地址
 * @param sa sockaddr结构指针
 * @return 优先级数值，数值越高优先级越高，0表示无效IP
 * @details 优先级策略：
 *          - 192.168.x.x (C类私网地址): 100 - 最高优先级，家用路由器常用
 *          - 10.x.x.x (A类私网地址): 50 - 中等优先级，企业网络常用
 *          - 172.16.x.x-172.31.x.x (B类私网地址): 30 - 较低优先级
 *          - 其他有效IP: 10 - 最低优先级
 */
static int GetIPPriority(const sockaddr* sa) {
    // 检查指针有效性和地址族
    if (!sa || sa->sa_family != AF_INET) return 0;
    
    const sockaddr_in* sin = reinterpret_cast<const sockaddr_in*>(sa);
    const uint32_t addr = ntohl(sin->sin_addr.S_un.S_addr);  // 转换为主机字节序
    
    // 192.168.x.x (C类私网地址) - 最高优先级 (家用路由器常用)
    // 地址范围: 192.168.0.0/16，掩码: 0xFFFF0000 (255.255.0.0)
    if ((addr & 0xFFFF0000) == 0xC0A80000) return 100;
    
    // 10.x.x.x (A类私网地址) - 中等优先级
    // 地址范围: 10.0.0.0/8，掩码: 0xFF000000 (255.0.0.0)
    if ((addr & 0xFF000000) == 0x0A000000) return 50;
    
    // 172.16.x.x - 172.31.x.x (B类私网地址) - 较低优先级
    // 地址范围: 172.16.0.0/12，掩码: 0xFFF00000 (255.240.0.0)
    if ((addr & 0xFFF00000) == 0xAC100000) return 30;
    
    // 其他有效IP - 最低优先级
    if (addr != 0x7F000001 && sin->sin_addr.S_un.S_addr != 0) return 10;
    
    return 0; // 无效IP
}

/**
 * @brief 获取内网IPv4地址，支持优先级选择和指定适配器
 * @param preferred_adapter 首选网络适配器名称（可为空）
 * @return 内网IPv4地址字符串，获取失败返回空字符串
 * @details 功能特性：
 *          1. 支持指定首选适配器（按FriendlyName或AdapterName匹配）
 *          2. 智能优先级选择（优先192.168.x.x，然后10.x.x.x，最后172.16-31.x.x）
 *          3. 自动排除回环地址、无效地址和非活动适配器
 *          4. 全局最优选择：从所有适配器中选择优先级最高的IP
 */
std::wstring GetInternalIPv4(const std::wstring& preferred_adapter) {
    // 设置GetAdaptersAddresses的参数
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;  // 包含前缀信息
    ULONG family = AF_INET;                 // 只获取IPv4地址

    // 初始化缓冲区大小（15KB通常足够）
    ULONG size = 15 * 1024;
    std::vector<BYTE> buffer(size);
    IP_ADAPTER_ADDRESSES* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    // 获取网络适配器地址信息
    ULONG ret = GetAdaptersAddresses(family, flags, nullptr, addrs, &size);
    
    // 如果缓冲区太小，调整大小后重新尝试
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size);
        addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        ret = GetAdaptersAddresses(family, flags, nullptr, addrs, &size);
    }
    
    // 如果获取失败，返回空字符串
    if (ret != NO_ERROR) return L"";

    /**
     * @brief Lambda函数：从指定适配器中选择优先级最高的IP地址
     * @param a 网络适配器地址结构指针
     * @return 优先级最高的IP地址字符串，无有效IP时返回空字符串
     */
    auto pick_from = [&](IP_ADAPTER_ADDRESSES* a) -> std::wstring {
        std::wstring best_ip;      // 当前找到的最佳IP地址
        int best_priority = 0;     // 当前最高优先级
        
        // 遍历当前适配器的所有单播地址
        for (auto ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            // 检查是否为有效的IPv4地址
            if (IsValidIPv4(ua->Address.lpSockaddr)) {
                int priority = GetIPPriority(ua->Address.lpSockaddr);
                
                // 如果当前地址优先级更高，更新最佳选择
                if (priority > best_priority) {
                    wchar_t buf[64] = {};  // IP地址字符串缓冲区
                    DWORD buflen = static_cast<DWORD>(std::size(buf));
                    
                    // 将sockaddr转换为字符串格式
                    if (WSAAddressToStringW(ua->Address.lpSockaddr, 
                                          (DWORD)ua->Address.iSockaddrLength, 
                                          nullptr, buf, &buflen) == 0) {
                        best_ip = std::wstring(buf);
                        best_priority = priority;
                    }
                }
            }
        }
        return best_ip;
    };

    // 第一步：如果指定了首选适配器，优先从该适配器获取IP
    if (!preferred_adapter.empty()) {
        for (auto a = addrs; a; a = a->Next) {
            // 跳过非活动适配器和回环适配器
            if (a->OperStatus != IfOperStatusUp || (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)) 
                continue;
            
            // 匹配适配器名称（优先使用FriendlyName，然后使用AdapterName）
            bool matches = false;
            
            // 首先尝试匹配友好名称（如"以太网"、"Wi-Fi"等）
            if (a->FriendlyName && preferred_adapter == std::wstring(a->FriendlyName)) {
                matches = true;
            } 
            // 如果友好名称不匹配，尝试匹配适配器名称
            else if (a->AdapterName) {
                // 将多字节适配器名称转换为宽字符串进行比较
                int len = MultiByteToWideChar(CP_UTF8, 0, a->AdapterName, -1, nullptr, 0);
                if (len > 0) {
                    std::wstring adapterName(len - 1, L'\0');
                    MultiByteToWideChar(CP_UTF8, 0, a->AdapterName, -1, &adapterName[0], len);
                    if (preferred_adapter == adapterName) {
                        matches = true;
                    }
                }
            }
            
            // 如果找到匹配的适配器，从中选择IP地址
            if (matches) {
                auto ip = pick_from(a);
                if (!ip.empty()) return ip;  // 找到有效IP，直接返回
            }
        }
    }

    // 第二步：Fallback策略 - 从所有活动适配器中选择全局最优IP
    // 当指定适配器未找到或未指定适配器时执行此逻辑
    std::wstring best_global_ip;       // 全局最佳IP地址
    int best_global_priority = 0;      // 全局最高优先级
    
    // 遍历所有网络适配器
    for (auto a = addrs; a; a = a->Next) {
        // 跳过非活动适配器和回环适配器
        if (a->OperStatus != IfOperStatusUp || (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)) 
            continue;
        
        // 遍历当前适配器的所有单播地址
        for (auto ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            // 检查是否为有效IPv4地址
            if (IsValidIPv4(ua->Address.lpSockaddr)) {
                int priority = GetIPPriority(ua->Address.lpSockaddr);
                
                // 如果发现更高优先级的IP地址，更新全局最佳选择
                if (priority > best_global_priority) {
                    wchar_t buf[64] = {};  // IP地址字符串缓冲区
                    DWORD buflen = static_cast<DWORD>(std::size(buf));
                    
                    // 将sockaddr转换为字符串格式
                    if (WSAAddressToStringW(ua->Address.lpSockaddr, 
                                          (DWORD)ua->Address.iSockaddrLength, 
                                          nullptr, buf, &buflen) == 0) {
                        best_global_ip = std::wstring(buf);
                        best_global_priority = priority;
                    }
                }
            }
        }
    }
    
    // 返回全局最优IP地址（可能为空字符串，表示未找到有效IP）
    return best_global_ip;
}


namespace {

constexpr std::size_t kMaximumExternalResponseBytes = 64u * 1024u;

std::wstring Utf8ToWide(const std::string& text) {
    if (text.empty()) return {};
    const int size = static_cast<int>(text.size());
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           text.data(), size, nullptr, 0);
    if (length <= 0) return {};
    std::wstring result(static_cast<std::size_t>(length), L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), size,
                             &result[0], length)) return {};
    return result;
}

IpWithCountry FetchExternalIPv4(const ExternalIpOptions& opt) {
    IpWithCountry result;
    InternetHandle hSession(WinHttpOpen(L"TrafficMonitorIpPlugin/1.0",
                                        WINHTTP_ACCESS_TYPE_NO_PROXY,
                                        WINHTTP_NO_PROXY_NAME,
                                        WINHTTP_NO_PROXY_BYPASS, 0));
    if (!hSession) return result;
    // WinHTTP takes resolve, connect, send, receive timeouts, in that order.
    if (!WinHttpSetTimeouts(hSession.get(), opt.connect_timeout_ms,
                            opt.connect_timeout_ms, opt.send_timeout_ms,
                            opt.receive_timeout_ms)) return result;
    InternetHandle hConnect(WinHttpConnect(hSession.get(), opt.host,
                                            INTERNET_DEFAULT_HTTPS_PORT, 0));
    if (!hConnect) return result;
    InternetHandle request(WinHttpOpenRequest(hConnect.get(), L"GET", opt.path, nullptr,
                                             WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             WINHTTP_FLAG_SECURE));
    if (!request) return result;
    HINTERNET hRequest = request.get();
    std::wstring request_url = L"https://";
    request_url += opt.host;
    request_url += opt.path;
    ApplyCurrentUserProxyForRequest(hRequest, request_url.c_str());
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, nullptr)) return result;
    DWORD status = 0;
    DWORD status_size = sizeof(status);
    if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                             WINHTTP_NO_HEADER_INDEX) || status != 200) return result;

    std::string data;
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &available)) return result;
        if (available == 0) break;
        if (available > kMaximumExternalResponseBytes - data.size()) return result;
        const std::size_t old_size = data.size();
        data.resize(old_size + available);
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, &data[old_size], available, &read) || read == 0) return result;
        data.resize(old_size + read);
    }

    detail::ExternalIpJsonFields fields;
    if (!detail::ExternalIpJsonParser(data).Parse(fields)) return result;
    const std::string& ip = fields.ip.empty() ? fields.origin : fields.ip;
    if (!detail::IsStrictIPv4(ip)) return result;
    result.ip.assign(ip.begin(), ip.end());
    const std::string country = detail::NormalizeCountry(fields.country);
    result.country.assign(country.begin(), country.end());
    result.as_name = Utf8ToWide(fields.org);
    return result;
}

struct OwnedExternalIpOptions {
    ExternalIpOptions values;
    std::wstring host;
    std::wstring path;

    explicit OwnedExternalIpOptions(const ExternalIpOptions& options)
        : values(options), host(options.host ? options.host : L""),
          path(options.path ? options.path : L"") {}

    ExternalIpOptions View() const {
        ExternalIpOptions result = values;
        result.host = host.c_str();
        result.path = path.c_str();
        return result;
    }
};

struct ExternalIpWorkerState {
    std::mutex mutex;
    std::condition_variable condition;
    std::thread worker;
    bool stopping = false;
    bool check_requested = false;
    bool force_requested = false;
    std::uint64_t endpoint_generation = 0;
    std::shared_ptr<const OwnedExternalIpOptions> options =
        std::make_shared<OwnedExternalIpOptions>(ExternalIpOptions{});
    detail::ExternalIpCacheState cache;
    detail::ExternalIpRefreshQueue queue;
    IpWithCountry snapshot;
};

ExternalIpWorkerState& ExternalWorker() {
    // This DLL is pinned for the process lifetime. Explicit shutdown is available
    // for callers with an ordinary, non-loader-lock teardown point.
    static ExternalIpWorkerState* state = new ExternalIpWorkerState;
    return *state;
}

void RunExternalIpWorker(ExternalIpWorkerState& state) {
    std::unique_lock<std::mutex> lock(state.mutex);
    for (;;) {
        state.condition.wait(lock, [&] { return state.stopping || state.check_requested; });
        if (state.stopping) return;
        state.queue.Start();
        bool forced = state.force_requested;
        state.force_requested = false;
        state.check_requested = false;
        for (;;) {
            const auto owned = state.options;
            const auto options = owned->View();
            const std::uint64_t generation = state.endpoint_generation;
            lock.unlock();

            IpWithCountry fetched;
            bool attempted = false;
            try {
                const std::wstring internal = GetInternalIPv4();
                const auto now = detail::ExternalIpCacheState::Clock::now();
                lock.lock();
                bool refresh = false;
                if (generation == state.endpoint_generation && !state.stopping) {
                    const bool changed = state.cache.ObserveNetwork(internal, now, options.adaptive_cycles);
                    refresh = state.cache.ShouldRefresh(options, now, forced, changed);
                }
                lock.unlock();
                if (refresh) {
                    attempted = true;
                    fetched = FetchExternalIPv4(options);
                }
            } catch (...) {
                // A failed allocation or request must not terminate the host.
                if (lock.owns_lock()) lock.unlock();
                attempted = true;
            }

            lock.lock();
            if (attempted && generation == state.endpoint_generation) {
                state.cache.Complete(fetched.IsValid(), detail::ExternalIpCacheState::Clock::now());
                if (fetched.IsValid()) state.snapshot = std::move(fetched);
            }
            if (state.stopping) return;
            if (!state.queue.Complete()) break;
            // The follow-up uses the newest endpoint/options, so it also consumes
            // an endpoint-change request queued while the old request was active.
            state.check_requested = false;
            state.force_requested = false;
            forced = true;
        }
    }
}

} // namespace

IpWithCountry GetExternalIPv4WithCountry(const ExternalIpOptions& opt, bool force_refresh) {
    auto& state = ExternalWorker();
    auto owned = std::make_shared<OwnedExternalIpOptions>(opt);
    if (owned->host.empty() || owned->path.empty()) return {};
    std::lock_guard<std::mutex> lock(state.mutex);
    if (state.stopping) return state.snapshot;
    const bool endpoint_changed = owned->host != state.options->host || owned->path != state.options->path;
    state.options = std::move(owned);
    if (endpoint_changed) {
        ++state.endpoint_generation;
        state.snapshot = {};
        state.cache = {};
        state.check_requested = true;
        state.force_requested = true;
    }
    if (state.queue.in_flight) {
        if (force_refresh) state.queue.RequestForce();
    } else {
        state.check_requested = true;
        state.force_requested = state.force_requested || force_refresh;
    }
    if (!state.worker.joinable()) {
        try {
            state.worker = std::thread(RunExternalIpWorker, std::ref(state));
        } catch (...) {
            // The next host update can retry starting the worker.
            return state.snapshot;
        }
    }
    state.condition.notify_one();
    return state.snapshot;
}

void ShutdownExternalIpWorker() {
    auto& state = ExternalWorker();
    std::thread worker;
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        state.stopping = true;
        state.check_requested = false;
        worker = std::move(state.worker);
        state.condition.notify_one();
    }
    if (worker.joinable()) worker.join();
}

/**
 * @brief 获取外网IPv4地址（兼容性函数）
 * @param opt 外网IP获取选项配置
 * @param force_refresh 是否强制刷新（跳过缓存）
 * @return 外网IPv4地址字符串，获取失败返回空字符串
 * @details 为保持兼容性，调用GetExternalIPv4WithCountry并只返回IP部分
 */
std::wstring GetExternalIPv4(const ExternalIpOptions& opt, bool force_refresh) {
    auto result = GetExternalIPv4WithCountry(opt, force_refresh);
    return result.ip;
}

} // namespace iputils



