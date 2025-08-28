/**
 * @file ip_utils.h
 * @brief TrafficMonitor IP插件的IP地址获取工具头文件
 * @details 提供内网和外网IPv4地址获取的接口声明和相关配置结构
 *          - GetInternalIPv4: 智能获取内网IPv4地址（优先192.168.x.x网段）
 *          - GetExternalIPv4: 通过公共服务获取外网IPv4地址（支持缓存）
 * @author Lynn
 * @date 2025
 */

#pragma once

#include <string>
#include <chrono>

namespace iputils {

/**
 * @brief IP地址和国家信息结构
 * @details 存储IP地址和对应的国家代码信息
 */
struct IpWithCountry {
    std::wstring ip;        ///< IP地址
    std::wstring country;   ///< 国家代码（如US、CN、JP等）
    std::wstring as_name;   ///< 机器供应商（DMIT）
    
    /**
     * @brief 检查IP信息是否有效
     * @return true表示包含有效的IP地址
     */
    bool IsValid() const {
        return !ip.empty();
    }
    
    /**
     * @brief 获取格式化的显示字符串
     * @return 格式化的字符串，如"US 8.8.8.8"或仅"8.8.8.8"（如果没有国家信息）
     */
    std::wstring GetDisplayString() const {
        if (country.empty()) {
            return ip;
        }
        return country + L" " + ip;
    }
    
    /**
     * @brief 从as_name(org)中提取公司名称主体
     * @return 提取的公司主体名称，如"AS906 DMIT Cloud Services"返回"DMIT Cloud Services"
     */
    std::wstring GetCompanyName() const {
        if (as_name.empty()) {
            return L"";
        }
        
        std::wstring name = as_name;
        
        // 去除首尾空格
        while (!name.empty() && (name.front() == L' ' || name.front() == L'\t')) {
            name.erase(0, 1);
        }
        while (!name.empty() && (name.back() == L' ' || name.back() == L'\t')) {
            name.pop_back();
        }
        
        // 如果以AS开头，去除AS号码部分（如"AS906 DMIT Cloud Services"）
        if (name.substr(0, 2) == L"AS") {
            size_t space_pos = name.find(L' ');
            if (space_pos != std::wstring::npos && space_pos + 1 < name.length()) {
                name = name.substr(space_pos + 1);
                // 去除前导空格
                while (!name.empty() && (name.front() == L' ' || name.front() == L'\t')) {
                    name.erase(0, 1);
                }
            }
        }
        
        // 查找逗号，截取前半部分（如"Cloudflare, Inc."）
        size_t comma_pos = name.find(L',');
        if (comma_pos != std::wstring::npos) {
            std::wstring front = name.substr(0, comma_pos);
            // 去除前半部分的尾部空格
            while (!front.empty() && (front.back() == L' ' || front.back() == L'\t')) {
                front.pop_back();
            }
            if (!front.empty()) {
                name = front;
            }
        }
        
        // 去除常见后缀
        const std::wstring suffixes[] = {L" Inc.", L" LLC", L" Ltd.", L" Corp.", L" Corporation", L" Services"};
        for (const auto& suffix : suffixes) {
            size_t pos = name.rfind(suffix);
            if (pos != std::wstring::npos && pos + suffix.length() == name.length()) {
                std::wstring without_suffix = name.substr(0, pos);
                // 去除后缀后的尾部空格
                while (!without_suffix.empty() && (without_suffix.back() == L' ' || without_suffix.back() == L'\t')) {
                    without_suffix.pop_back();
                }
                if (!without_suffix.empty()) {
                    name = without_suffix;
                    break;
                }
            }
        }
        
        // 如果最终结果为空，返回原始as_name
        return name.empty() ? as_name : name;
    }
};

/**
 * @brief 外网IP获取选项配置结构
 * @details 配置外网IP获取服务的各项参数，包括服务器地址、超时时间和缓存策略
 */
/**
 * @brief 智能缓存策略枚举
 */
enum class CacheStrategy {
    FIXED,          ///< 固定间隔（当前默认）
    ADAPTIVE,       ///< 自适应间隔（网络变化时加速）
    NETWORK_EVENT,  ///< 基于网络事件触发
    HYBRID         ///< 混合模式（推荐）
};

struct ExternalIpOptions {
    const wchar_t* host = L"ipinfo.io";                                // 服务器主机名
    const wchar_t* path = L"/json";                                     // 请求路径（返回JSON格式）
    unsigned connect_timeout_ms = 3000;                                 // 连接超时时间（毫秒）
    unsigned send_timeout_ms = 3000;                                    // 发送超时时间（毫秒）
    unsigned receive_timeout_ms = 5000;                                 // 接收超时时间（毫秒）
    
    // 智能缓存配置
    CacheStrategy strategy = CacheStrategy::HYBRID;                     // 缓存策略
    std::chrono::milliseconds min_refresh{ std::chrono::minutes(5) };   // 标准刷新间隔
    std::chrono::milliseconds fast_refresh{ std::chrono::seconds(30) }; // 快速刷新间隔
    std::chrono::milliseconds max_refresh{ std::chrono::minutes(15) };  // 最大刷新间隔
    int adaptive_cycles = 6;                                            // 快速模式持续周期数
};

/**
 * @brief 获取内网IPv4地址（支持智能优先级选择）
 * @param preferred_adapter 首选网络适配器名称（可选）
 * @return IPv4地址字符串（如"192.168.1.12"），获取失败返回空字符串
 * @details 优先级策略：192.168.x.x > 10.x.x.x > 172.16-31.x.x > 其他
 *          支持通过FriendlyName或AdapterName指定首选适配器
 */
std::wstring GetInternalIPv4(const std::wstring& preferred_adapter = L"");

/**
 * @brief 获取外网IPv4地址和国家信息（支持缓存和强制刷新）
 * @param opt 外网IP获取选项配置
 * @param force_refresh 是否强制刷新（跳过缓存）
 * @return IpWithCountry结构，包含IP地址和国家代码，获取失败返回空的结构
 * @details 使用ipinfo.io服务获取IP地址和地理位置信息
 *          使用进程内缓存机制避免频繁网络请求，默认缓存5分钟
 *          支持自定义服务器和超时参数
 */
IpWithCountry GetExternalIPv4WithCountry(const ExternalIpOptions& opt = {}, bool force_refresh = false);

/**
 * @brief 获取外网IPv4地址（兼容性函数）
 * @param opt 外网IP获取选项配置
 * @param force_refresh 是否强制刷新（跳过缓存）
 * @return 外网IPv4地址字符串，获取失败返回空字符串
 * @details 为保持兼容性，调用GetExternalIPv4WithCountry并只返回IP部分
 */
std::wstring GetExternalIPv4(const ExternalIpOptions& opt = {}, bool force_refresh = false);

}

