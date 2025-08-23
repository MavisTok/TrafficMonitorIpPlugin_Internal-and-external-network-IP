/**
 * @file plugin_options.h
 * @brief TrafficMonitor IP插件的配置选项结构定义
 * @details 定义插件的所有可配置参数，包括显示选项、网络设置和界面配置
 * @author Lynn
 * @date 2025
 */

#pragma once

#include <string>
#include <chrono>

/**
 * @brief 插件配置选项结构
 * @details 包含插件的所有用户可配置参数，用于个性化定制插件行为
 *          配置会自动保存到INI文件中，程序重启后自动恢复
 */
struct PluginOptions {
    // === 显示选项 ===
    bool show_internal = true;                          ///< 是否显示内网IP地址
    bool show_external = true;                          ///< 是否显示外网IP地址
    
    // === 网络设置 ===
    std::wstring preferred_adapter;                     ///< 首选网络适配器（FriendlyName或AdapterName）
    std::chrono::minutes external_refresh{5};          ///< 外网IP标准刷新间隔（分钟）
    
    // === 智能缓存设置 ===
    bool enable_smart_cache = true;                     ///< 启用智能缓存（推荐）
    std::chrono::seconds fast_refresh{30};             ///< 网络变化后快速刷新间隔（秒）
    std::chrono::minutes max_refresh{15};              ///< 稳定期最大刷新间隔（分钟）
    
    // === 界面配置 ===
    std::wstring separator = L" | ";                   ///< 内外网IP之间的分隔符
};

