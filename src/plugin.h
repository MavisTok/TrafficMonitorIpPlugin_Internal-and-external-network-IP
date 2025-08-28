/**
 * @file plugin.h
 * @brief TrafficMonitor IP插件的主要类声明
 * @details 定义插件的核心类：IpPluginItem和TMIpPlugin
 *          实现TrafficMonitor插件接口，提供IP地址显示功能
 * @author Lynn  
 * @date 2025
 */

#pragma once
#pragma execution_character_set("utf-8")  // 设置源代码字符集为UTF-8

#include <string>
#include <vector>
#include <memory>
#include <windows.h>
#include "PluginInterface.h"  // TrafficMonitor插件接口定义
#include "ip_item.h"          // IP文本提供器

extern HINSTANCE g_hInst;    // 全局实例句柄

/**
 * @brief IP插件显示项目类
 * @details 实现IPluginItem接口，负责向TrafficMonitor提供IP地址显示功能
 *          包括项目标识、显示文本和更新机制
 */
class IpPluginItem : public IPluginItem {
public:
    /**
     * @brief 构造函数
     * @param provider IP文本提供器指针
     */
    explicit IpPluginItem(IpTextProvider* provider) : provider_(provider) {}

    // === IPluginItem接口实现 ===
    const wchar_t* GetItemName() const override { return L"内外网IP显示"; }                        ///< 项目名称
    const wchar_t* GetItemId() const override { return L"internal_external_ip"; }            ///< 项目唯一标识符
    const wchar_t* GetItemLableText() const override { return L""; }                         ///< 标签文本（空，因为使用自定义绘制）
    const wchar_t* GetItemValueText() const override { return value_.c_str(); }              ///< 显示的IP地址值（备用）
    const wchar_t* GetItemValueSampleText() const override {                                 ///< 示例文本（自定义绘制时不使用）
        return L""; 
    }

    // === 自定义绘制接口实现 ===
    bool IsCustomDraw() const override { return true; }                                      ///< 启用自定义绘制模式
    int GetItemWidth() const override;                                                       ///< 获取显示区域宽度
    void DrawItem(void* hDC, int x, int y, int w, int h, bool dark_mode) override;          ///< 自定义绘制函数

    /**
     * @brief 更新IP地址数据
     * @param force_external_refresh 是否强制刷新外网IP
     * @details 通过IP文本提供器获取最新的IP地址信息，分别存储内网和外网IP
     */
    void Update(bool force_external_refresh) {
        if (!provider_) { 
            value_.clear();
            internal_ip_.clear();
            external_ip_.clear();
            return; 
        }
        
        // 获取完整文本（备用）
        value_ = provider_->GetText(force_external_refresh);
        
        // 分别获取内网和外网IP用于垂直显示
        const auto& options = provider_->GetOptions();
        
        // 获取外网IP和公司信息（无论是否显示内网都需要获取）
        iputils::IpWithCountry ext_result;
        if (options.show_external) {
            iputils::ExternalIpOptions opt;
            // 配置智能缓存策略
            if (options.enable_smart_cache) {
                opt.strategy = iputils::CacheStrategy::HYBRID;
                opt.min_refresh = options.external_refresh;
                opt.fast_refresh = options.fast_refresh;
                opt.max_refresh = options.max_refresh;
            } else {
                opt.strategy = iputils::CacheStrategy::FIXED;
                opt.min_refresh = options.external_refresh;
            }
            
            ext_result = iputils::GetExternalIPv4WithCountry(opt, force_external_refresh);
        }
        
        if (options.show_internal) {
            // 显示内网IP
            internal_ip_ = iputils::GetInternalIPv4(options.preferred_adapter);
            if (internal_ip_.empty()) internal_ip_ = L"N/A";
        } else if (options.show_external && ext_result.IsValid() && !ext_result.as_name.empty()) {
            // 内网关闭但外网开启时，在内网位置显示公司名称
            internal_ip_ = ext_result.GetCompanyName();
        } else {
            internal_ip_.clear();
        }
        
        if (options.show_external) {
            if (ext_result.IsValid()) {
                external_ip_ = ext_result.GetDisplayString();  // 使用格式化字符串（包含国家代码）
            } else {
                external_ip_ = L"N/A";
            }
        } else {
            external_ip_.clear();
        }
    }

    /**
     * @brief 获取原始IP地址值
     * @return IP地址字符串的常量引用
     */
    const std::wstring& RawValue() const { return value_; }

private:
    IpTextProvider* provider_{};  ///< IP文本提供器指针
    std::wstring value_;          ///< 缓存的IP地址显示文本（备用）
    std::wstring internal_ip_;    ///< 内网IP地址（用于垂直显示）
    std::wstring external_ip_;    ///< 外网IP地址（用于垂直显示）
};

/**
 * @brief TrafficMonitor IP插件主类
 * @details 实现ITMPlugin接口，提供完整的插件功能：
 *          - IP地址获取和显示
 *          - 配置管理（保存/加载）
 *          - 用户交互界面（选项对话框）
 *          - 插件命令处理（显示切换、刷新等）
 *          - 工具提示信息
 */
class TMIpPlugin : public ITMPlugin {
public:
    /**
     * @brief 构造函数
     * @details 初始化插件实例并加载配置
     */
    TMIpPlugin();

    // === ITMPlugin核心接口实现 ===
    IPluginItem* GetItem(int index) override;                                    ///< 获取显示项目
    void DataRequired() override;                                                 ///< 数据更新回调
    OptionReturn ShowOptionsDialog(void* hParent) override;                       ///< 显示选项对话框
    const wchar_t* GetInfo(PluginInfoIndex index) override;                      ///< 获取插件信息
    void OnInitialize(ITrafficMonitor* pApp) override;                           ///< 插件初始化
    const wchar_t* GetTooltipInfo() override;                                    ///< 获取工具提示

    // === 插件命令接口实现 ===
    int GetCommandCount() override { return 3; }                                 ///< 命令数量（3个：切换内网、切换外网、强制刷新）
    const wchar_t* GetCommandName(int command_index) override;                   ///< 获取命令名称
    void OnPluginCommand(int command_index, void* hWnd, void* para) override;    ///< 处理插件命令
    int IsCommandChecked(int command_index) override;                            ///< 命令是否选中状态

private:
    // === 私有辅助方法 ===
    void LoadOptions();                                                           ///< 从配置文件加载选项
    void SaveOptions();                                                           ///< 保存选项到配置文件

private:
    // === 插件状态和组件 ===
    ITrafficMonitor* app_{};                          ///< TrafficMonitor应用程序接口指针
    std::wstring config_dir_;                         ///< 配置文件目录路径
    PluginOptions options_{};                         ///< 当前配置选项
    IpTextProvider text_provider_{ options_ };       ///< IP文本提供器
    IpPluginItem item_{ &text_provider_ };           ///< 显示项目实例
    bool force_refresh_next_ = false;                 ///< 下次更新是否强制刷新外网IP
    std::wstring tooltip_;                            ///< 工具提示文本缓存
};
