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
#include <utility>
#include "plugin_options.h"
#include "ip_utils.h"

/**
 * @brief IP地址文本提供器类
 * @details 负责根据用户配置生成要显示的IP地址文本
 *          支持内网/外网IP的单独或组合显示，包含错误状态处理
 */
class IpTextProvider {
public:
    struct Snapshot {
        std::wstring internal;
        iputils::IpWithCountry external;
        std::wstring text;
    };

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
    Snapshot GetSnapshot(bool force_external_refresh = false) {
        Snapshot snapshot;
        std::wstring external;  // 外网IP地址

        // 获取内网IP（如果启用）
        if (options_.show_internal) {
            snapshot.internal = iputils::GetInternalIPv4(options_.preferred_adapter);
            if (snapshot.internal.empty()) {
                snapshot.internal = L"N/A";
            }
        }

        // 获取外网IP（如果启用）
        std::wstring company_name;
        auto& result = snapshot.external;
        if (options_.show_external) {
            iputils::ExternalIpOptions opt;
            opt.strategy = options_.enable_smart_cache
                ? iputils::CacheStrategy::HYBRID : iputils::CacheStrategy::FIXED;
            opt.min_refresh = options_.external_refresh;  // 使用配置的刷新间隔
            opt.fast_refresh = options_.fast_refresh;
            opt.max_refresh = options_.max_refresh;
            result = iputils::GetExternalIPv4WithCountry(opt, force_external_refresh);
            if (result.IsValid()) {
                external = result.GetDisplayString();  // 使用格式化字符串（包含国家代码）
                company_name = result.GetCompanyName();  // 获取公司名称
            } else {
                external = L"N/A";  // 显示获取失败状态，而不是空白
            }
        }

        // 根据配置组合显示文本
        if (options_.show_internal && options_.show_external) {
            // 同时显示内网和外网IP，用分隔符连接
            snapshot.text = snapshot.internal + options_.separator + external;
        } else if (options_.show_internal) {
            // 仅显示内网IP
            snapshot.text = snapshot.internal;
        } else if (options_.show_external) {
            // 仅显示外网IP时，如果有公司信息则在内网位置显示，外网位置显示IP
            if (!result.as_name.empty() && external != L"N/A") {
                // 先尝试使用处理过的公司名称
                if (!company_name.empty()) {
                    snapshot.text = company_name + options_.separator + external;
                } else {
                    snapshot.text = result.as_name + options_.separator + external;
                }
            } else {
                snapshot.text = external;
            }
        } else {
            snapshot.text = L"请启用IP显示";
        }
        return snapshot;
    }

    std::wstring GetText(bool force_external_refresh = false) {
        return GetSnapshot(force_external_refresh).text;
    }

private:
    PluginOptions options_{};
};

