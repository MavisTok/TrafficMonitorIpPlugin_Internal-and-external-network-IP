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

// 链接必需的系统库
#pragma comment(lib, "Iphlpapi.lib")  // IP Helper API库
#pragma comment(lib, "Ws2_32.lib")    // Winsock 2.0库
#pragma comment(lib, "Winhttp.lib")   // WinHTTP库

namespace iputils {

/**
 * @brief 简单的JSON字段提取函数
 * @param json JSON字符串
 * @param field 要提取的字段名
 * @return 字段值，如果未找到返回空字符串
 * @details 简单实现，只处理字符串字段，格式："field":"value"
 */
static std::string ExtractJsonField(const std::string& json, const std::string& field) {
    // 构造查找模式："field"，允许冒号后有可选空格
    std::string pattern = "\"" + field + "\"";
    size_t start = json.find(pattern);
    if (start == std::string::npos) return "";
    
    // 跳过字段名
    start += pattern.length();
    
    // 跳过冒号和可能的空格
    while (start < json.length() && (json[start] == ':' || json[start] == ' ' || json[start] == '\t')) {
        start++;
    }
    
    // 检查是否为字符串值（以"开始）
    if (start >= json.length() || json[start] != '"') return "";
    start++; // 跳过开始的引号
    
    // 查找结束引号
    size_t end = json.find("\"", start);
    if (end == std::string::npos) return "";
    
    return json.substr(start, end - start);
}

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


/**
 * @brief 获取外网IPv4地址和国家信息，支持缓存和强制刷新
 * @param opt 外网IP获取选项配置
 * @param force_refresh 是否强制刷新（跳过缓存）
 * @return IpWithCountry结构，包含IP地址和国家代码，获取失败返回空的结构
 * @details 使用ipinfo.io服务获取IP地址和地理位置信息
 *          使用进程内缓存机制避免频繁网络请求，默认缓存5分钟
 *          支持自定义服务器和超时参数
 */
IpWithCountry GetExternalIPv4WithCountry(const ExternalIpOptions& opt, bool force_refresh) {
    // 静态变量用于缓存机制（线程安全）
    static std::mutex mtx;                                      // 互斥锁保护缓存
    static IpWithCountry cached_result;                         // 缓存的IP和国家信息
    static std::chrono::steady_clock::time_point last_fetch{};  // 上次获取时间
    static std::chrono::steady_clock::time_point last_change{}; // 上次IP变化时间
    static int fast_mode_counter = 0;                           // 快速模式计数器
    static std::wstring last_internal_ip;                       // 上次内网IP（用于变化检测）

    const auto now = std::chrono::steady_clock::now();
    
    // 智能缓存策略检查
    {
        std::lock_guard<std::mutex> lk(mtx);
        
        // 检测内网IP变化（网络适配器变化的指示器）
        std::wstring current_internal_ip = GetInternalIPv4();
        bool network_changed = false;
        if (!last_internal_ip.empty() && current_internal_ip != last_internal_ip) {
            network_changed = true;
            last_change = now;
            fast_mode_counter = opt.adaptive_cycles;  // 启动快速模式
            last_internal_ip = current_internal_ip;
        } else if (last_internal_ip.empty()) {
            last_internal_ip = current_internal_ip;
        }
        
        // 如果强制刷新或网络发生变化，跳过缓存检查
        if (force_refresh || network_changed) {
            // 继续执行网络请求
        }
        // 否则检查缓存策略
        else if (cached_result.IsValid() && last_fetch.time_since_epoch().count() != 0) {
            std::chrono::milliseconds refresh_interval;
            
            // 根据策略选择刷新间隔
            switch (opt.strategy) {
                case CacheStrategy::FIXED:
                    refresh_interval = opt.min_refresh;
                    break;
                    
                case CacheStrategy::ADAPTIVE:
                case CacheStrategy::HYBRID:
                    if (fast_mode_counter > 0) {
                        refresh_interval = opt.fast_refresh;  // 快速模式：30秒
                        fast_mode_counter--;
                    } else {
                        // 根据稳定时间逐渐延长间隔
                        auto stable_time = now - last_change;
                        if (stable_time > std::chrono::hours(1)) {
                            refresh_interval = opt.max_refresh;  // 超过1小时稳定：15分钟
                        } else {
                            refresh_interval = opt.min_refresh;  // 标准间隔：5分钟
                        }
                    }
                    break;
                    
                case CacheStrategy::NETWORK_EVENT:
                    refresh_interval = opt.max_refresh;  // 仅在网络事件时刷新
                    break;
            }
            
            if (now - last_fetch < refresh_interval) {
                return cached_result;  // 返回缓存的结果
            }
        }
    }

    IpWithCountry result;  // 存储从服务器获取的IP和国家信息

    // 步骤1: 初始化WinHTTP会话
    HINTERNET hSession = WinHttpOpen(L"TrafficMonitorIpPlugin/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return result;  // 会话创建失败

    // 设置超时参数
    WinHttpSetTimeouts(hSession, opt.connect_timeout_ms, opt.send_timeout_ms, 
                      opt.receive_timeout_ms, opt.receive_timeout_ms);

    // 步骤2: 连接到目标服务器（使用HTTPS端口443）
    HINTERNET hConnect = WinHttpConnect(hSession, opt.host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { 
        WinHttpCloseHandle(hSession); 
        return result; 
    }

    // 步骤3: 创建HTTPS请求
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", opt.path, nullptr,
                                            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                            WINHTTP_FLAG_SECURE);
    if (!hRequest) { 
        WinHttpCloseHandle(hConnect); 
        WinHttpCloseHandle(hSession); 
        return result; 
    }

    // 步骤4: 发送HTTP请求并接收响应
    bool ok = !!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (ok) ok = !!WinHttpReceiveResponse(hRequest, nullptr);

    // 步骤5: 读取响应数据
    if (ok) {
        std::string data;  // 存储从服务器读取的原始数据
        DWORD dwSize = 0;
        
        // 循环读取所有可用数据
        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;  // 查询可用数据大小
            if (dwSize == 0) break;  // 没有更多数据
            
            size_t old = data.size();
            data.resize(old + dwSize);  // 扩展缓冲区
            DWORD dwRead = 0;
            
            // 读取数据到缓冲区
            if (!WinHttpReadData(hRequest, const_cast<char*>(data.data()) + old, dwSize, &dwRead)) 
                break;
            data.resize(old + dwRead);  // 调整实际读取的大小
        } while (dwSize > 0);

        // 步骤6: 解析JSON响应数据（ipinfo.io格式）
        auto begin = data.find_first_not_of(" \t\r\n");  // 找到第一个非空白字符
        auto end = data.find_last_not_of(" \t\r\n");    // 找到最后一个非空白字符
        std::string trimmed = (begin == std::string::npos) ? std::string() : data.substr(begin, end - begin + 1);
        
        if (!trimmed.empty()) {
            // 提取IP地址和国家代码字段（尝试多种API格式）
            std::string ip = ExtractJsonField(trimmed, "ip");
            if (ip.empty()) {
                ip = ExtractJsonField(trimmed, "origin");  // httpbin.org格式备用
            }
            std::string country = ExtractJsonField(trimmed, "country");
            
            if (!ip.empty()) {
                // 将UTF-8编码的IP地址转换为宽字符串
                int wlen = MultiByteToWideChar(CP_UTF8, 0, ip.c_str(), (int)ip.size(), nullptr, 0);
                if (wlen > 0) {
                    std::wstring wip(wlen, L'\0');
                    MultiByteToWideChar(CP_UTF8, 0, ip.c_str(), (int)ip.size(), 
                                      const_cast<wchar_t*>(wip.data()), wlen);
                    result.ip = std::move(wip);
                }
            }
            
            if (!country.empty()) {
                // 将UTF-8编码的国家代码转换为宽字符串
                int wlen = MultiByteToWideChar(CP_UTF8, 0, country.c_str(), (int)country.size(), nullptr, 0);
                if (wlen > 0) {
                    std::wstring wcountry(wlen, L'\0');
                    MultiByteToWideChar(CP_UTF8, 0, country.c_str(), (int)country.size(), 
                                      const_cast<wchar_t*>(wcountry.data()), wlen);
                    result.country = std::move(wcountry);
                }
            }
        }
    }

    // 步骤7: 清理资源
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    // 步骤8: 更新缓存（如果获取成功）
    if (result.IsValid()) {
        std::lock_guard<std::mutex> lk(mtx);
        cached_result = result;   // 更新缓存的结果
        last_fetch = now;         // 更新获取时间
    }

    return result;  // 返回获取到的IP和国家信息（可能为空）
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

