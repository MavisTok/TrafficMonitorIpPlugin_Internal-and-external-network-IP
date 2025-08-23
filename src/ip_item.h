/**
 * @file ip_item.h
 * @brief TrafficMonitor IP插件的文本提供器类定义
 * @details 定义IpTextProvider类，负责根据配置选项生成显示文本
 *          处理内网/外网IP地址的格式化和错误状态显示
 * @author Lynn
 * @date 2025
 */

#pragma once

#include <string>
#include "plugin_options.h"
#include "ip_utils.h"

/**
 * @brief IP地址文本提供器类
 * @details 负责根据用户配置生成要显示的IP地址文本
 *          支持内网/外网IP的单独或组合显示，包含错误状态处理
 */
class IpTextProvider {
public:
    /**
     * @brief 构造函数
     * @param opts 插件配置选项
     */
    explicit IpTextProvider(PluginOptions opts = {}) : options_(std::move(opts)) {}

    /**
     * @brief 设置配置选项
     * @param opts 新的配置选项
     */
    void SetOptions(const PluginOptions& opts) { options_ = opts; }
    
    /**
     * @brief 获取当前配置选项
     * @return 当前的配置选项引用
     */
    const PluginOptions& GetOptions() const { return options_; }

    /**
     * @brief 获取格式化的IP地址显示文本
     * @param force_external_refresh 是否强制刷新外网IP
     * @return 格式化的IP地址文本，根据配置可能包含内网、外网或两者
     * @details 根据配置选项决定显示内容：
     *          - 仅内网：返回内网IP
     *          - 仅外网：返回外网IP  
     *          - 内外网：返回"内网IP分隔符外网IP"格式
     *          - 都不启用：返回提示信息
     *          - 获取失败：显示"N/A"而不是空白
     */
    std::wstring GetText(bool force_external_refresh = false) {
        std::wstring internal;  // 内网IP地址
        std::wstring external;  // 外网IP地址

        // 获取内网IP（如果启用）
        if (options_.show_internal) {
            internal = iputils::GetInternalIPv4(options_.preferred_adapter);
            if (internal.empty()) {
                internal = L"N/A";  // 显示获取失败状态，而不是空白
            }
        }

        // 获取外网IP（如果启用）
        if (options_.show_external) {
            iputils::ExternalIpOptions opt;
            opt.min_refresh = options_.external_refresh;  // 使用配置的刷新间隔
            auto result = iputils::GetExternalIPv4WithCountry(opt, force_external_refresh);
            if (result.IsValid()) {
                external = result.GetDisplayString();  // 使用格式化字符串（包含国家代码）
            } else {
                external = L"N/A";  // 显示获取失败状态，而不是空白
            }
        }

        // 根据配置组合显示文本
        if (options_.show_internal && options_.show_external) {
            // 同时显示内网和外网IP，用分隔符连接
            return internal + options_.separator + external;
        }
        if (options_.show_internal) {
            // 仅显示内网IP
            return internal;
        }
        if (options_.show_external) {
            // 仅显示外网IP
            return external;
        }
        
        // 如果两个都没有启用，显示提示信息
        return L"请启用IP显示";
    }

private:
    PluginOptions options_{};
};

