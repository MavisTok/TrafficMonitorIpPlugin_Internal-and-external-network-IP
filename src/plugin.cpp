/**
 * @file plugin.cpp
 * @brief TrafficMonitor IP插件的主要实现文件
 * @details 包含TMIpPlugin类的完整实现，负责插件的核心功能：
 *          - IP地址获取和显示
 *          - 配置文件管理
 *          - 用户界面交互
 *          - 插件命令处理
 * @author Lynn
 * @date 2025
 */

#pragma execution_character_set("utf-8")  // 设置源代码字符集为UTF-8

#include "plugin.h"
#include <Shlwapi.h>        // Shell轻量级实用程序API（用于路径操作）
#include "options_dialog.h"  // 选项对话框
#include "claude_risk.h"
#include "exit_detection.h"
#include "proxy_watch.h"     // 代理软件窗口打开/关闭监控

#pragma comment(lib, "Shlwapi.lib")  // 链接Shell轻量级实用程序库

/**
 * @brief 路径连接辅助函数
 * @param a 基础路径
 * @param b 要连接的路径或文件名
 * @return 连接后的完整路径
 * @details 自动处理路径分隔符，确保路径格式正确
 */
static std::wstring JoinPath(const std::wstring& a, const std::wstring& b) {
    if (a.empty()) return b;
    std::wstring r = a;
    // 确保路径末尾有分隔符
    if (!r.empty() && r.back() != L'\\' && r.back() != L'/') 
        r.push_back(L'\\');
    r += b;
    return r;
}

static std::wstring FormatProviderName(const std::wstring& as_name) {
    if (as_name.empty()) return L"";
    iputils::IpWithCountry info;
    info.as_name = as_name;
    std::wstring company = info.GetCompanyName();
    return company.empty() ? as_name : company;
}

/**
 * @brief TMIpPlugin构造函数
 * @details 初始化插件实例，加载配置选项
 */
TMIpPlugin::TMIpPlugin() {
    LoadOptions();  // 从配置文件加载用户设置
}

TMIpPlugin::~TMIpPlugin() {
    exit_detection::ShutdownRefreshWorker();
}

/**
 * @brief 获取插件显示项目
 * @param index 项目索引（当前插件只有一个显示项）
 * @return 显示项目指针，无效索引时返回nullptr
 * @details 实现ITMPlugin接口，告诉TrafficMonitor插件提供的显示项目
 */
IPluginItem* TMIpPlugin::GetItem(int index) {
    if (index == 0) return &item_;  // 返回IP显示项目
    return nullptr;  // 无效索引
}

void TMIpPlugin::DataRequired() {
    text_provider_.SetOptions(options_);
    bool force_refresh_requested = force_refresh_next_ || proxywatch::ConsumeTriggerFlag();
    item_.Update(force_refresh_requested);
    force_refresh_next_ = false;

    if (options_.enable_claude_risk_check) {
        claude_risk::RequestClaudeRiskRefreshAsync(
            config_dir_, item_.ExternalIpRaw(), item_.ExternalCountryRaw(), force_refresh_requested);
    }
    if (options_.enable_exit_detection) {
        exit_detection::RequestRefreshAsync(force_refresh_requested);
    }

    const auto& v = item_.RawValue();

    // 确保即使值为空也能提供有意义的显示
    if (v.empty()) {
        // 如果值为空，设置一个默认提示
        if (options_.show_internal && options_.show_external) {
            tooltip_ = L"内网: N/A\n外网: N/A";
        } else if (options_.show_internal) {
            tooltip_ = L"内网: N/A";
        } else if (options_.show_external) {
            tooltip_ = L"外网: N/A";
        } else {
            tooltip_ = L"请在选项中启用IP显示";
        }
        AppendClaudeRiskTooltip();
        AppendExitDetectionTooltip();
        return;
    }

    if (options_.show_internal && options_.show_external) {
        // Split for tooltip if both enabled
        // Format: 内网: x\n外网: y
        std::wstring internal, external;
        size_t pos = v.find(options_.separator);
        if (pos != std::wstring::npos) {
            internal = v.substr(0, pos);
            external = v.substr(pos + options_.separator.size());
        } else {
            internal = v;
        }
        tooltip_.clear();
        if (!internal.empty()) {
            tooltip_ += L"内网: ";
            tooltip_ += internal;
        }
        if (!external.empty()) {
            if (!tooltip_.empty()) tooltip_ += L"\n";
            tooltip_ += L"外网: ";
            tooltip_ += external;
        }
    } else if (options_.show_internal) {
        tooltip_ = L"内网: ";
        tooltip_ += v;
    } else if (options_.show_external) {
        tooltip_ = L"外网: ";
        tooltip_ += v;
    } else {
        tooltip_ = L"请在选项中启用IP显示";
    }

    AppendClaudeRiskTooltip();
    AppendExitDetectionTooltip();
}

void TMIpPlugin::AppendClaudeRiskTooltip() {
    if (!options_.enable_claude_risk_check) return;

    auto risk = claude_risk::GetClaudeRiskSnapshot();
    if (!tooltip_.empty()) tooltip_ += L"\n";
    tooltip_ += L"——Claude IP风险——";

    if (!risk.valid) {
        tooltip_ += L"\n检测中…";
        return;
    }

    tooltip_ += L"\nClaude出口: ";
    if (!risk.cf_trace_ok) {
        tooltip_ += L"未知（请求失败）";
    } else {
        tooltip_ += risk.cf_ip.empty() ? L"未知" : risk.cf_ip;
        if (!risk.cf_colo.empty()) {
            tooltip_ += L" (";
            tooltip_ += risk.cf_colo;
            tooltip_ += L"机房)";
        }
    }

    tooltip_ += L"\n网络运营商: ";
    std::wstring provider_name = FormatProviderName(risk.cf_as_name);
    tooltip_ += provider_name.empty() ? L"未知" : provider_name;

    tooltip_ += L"\n受限地区: ";
    if (risk.country_restricted) {
        tooltip_ += L"命中：";
        tooltip_ += risk.restricted_country_code;
        tooltip_ += L"（仅供参考）";
    } else {
        tooltip_ += L"未命中";
    }

    tooltip_ += L"\n直连Claude: ";
    switch (risk.direct_reachability) {
        case claude_risk::Reachability::Reachable: tooltip_ += L"可达"; break;
        case claude_risk::Reachability::Blocked: tooltip_ += L"被屏蔽(403)"; break;
        default: tooltip_ += L"未知"; break;
    }

    tooltip_ += L"\n风险属性: ";
    if (!risk.risk_query_ok) {
        tooltip_ += L"未知（查询失败）";
    } else if (risk.is_proxy || risk.is_hosting) {
        tooltip_ += L"疑似";
        if (risk.is_proxy) tooltip_ += L"代理/VPN ";
        if (risk.is_hosting) tooltip_ += L"机房IP";
    } else {
        tooltip_ += L"无明显风险";
    }

    tooltip_ += L"\nIP波动: 近30天";
    tooltip_ += std::to_wstring(risk.distinct_ip_count_30d);
    tooltip_ += L"个IP";
    switch (risk.rotation_level) {
        case claude_risk::RotationLevel::Notice: tooltip_ += L"（注意）"; break;
        case claude_risk::RotationLevel::Warning: tooltip_ += L"（警告）"; break;
        case claude_risk::RotationLevel::Severe: tooltip_ += L"（严重警告）"; break;
        default: break;
    }
}

void TMIpPlugin::AppendExitDetectionTooltip() {
    if (!options_.enable_exit_detection) return;

    const std::wstring exit_tooltip =
        exit_detection::FormatTooltip(exit_detection::GetSnapshot());
    if (exit_tooltip.empty()) return;
    if (!tooltip_.empty()) tooltip_ += L"\n";
    tooltip_ += exit_tooltip;
}

void TMIpPlugin::ShowClaudeRiskReport(HWND hWnd) {
    if (!options_.enable_claude_risk_check) {
        MessageBoxW(hWnd, L"请先在插件设置中启用\"Claude IP风险检测\"。",
                    L"Claude IP风险详情", MB_OK | MB_ICONINFORMATION);
        return;
    }

    auto risk = claude_risk::GetClaudeRiskSnapshot();
    std::wstring report;
    if (!risk.valid) {
        report = L"检测中，请稍后重试。";
    } else {
        report = L"出口IP(Cloudflare视角): " + (risk.cf_ip.empty() ? L"未知" : risk.cf_ip) + L"\n";
        report += L"机房代号: " + (risk.cf_colo.empty() ? L"未知" : risk.cf_colo) + L"\n";
        std::wstring provider_name = FormatProviderName(risk.cf_as_name);
        report += L"网络运营商: " + (provider_name.empty() ? std::wstring(L"未知") : provider_name) + L"\n";
        report += L"受限地区: ";
        report += risk.country_restricted ? (L"命中 " + risk.restricted_country_code) : L"未命中";
        report += L"\n直连api.anthropic.com: ";
        switch (risk.direct_reachability) {
            case claude_risk::Reachability::Reachable: report += L"可达"; break;
            case claude_risk::Reachability::Blocked: report += L"被屏蔽(HTTP 403)"; break;
            default: report += L"未知"; break;
        }
        report += L"\nVPN/代理: ";
        report += risk.is_proxy ? L"是" : L"否";
        report += L"\n机房/数据中心: ";
        report += risk.is_hosting ? L"是" : L"否";
        report += L"\n移动网络: ";
        report += risk.is_mobile ? L"是" : L"否";
        report += L"\n近30天出现过的不同外网IP数: " + std::to_wstring(risk.distinct_ip_count_30d);
        report += L"\n\n注：受限地区名单与直连探测逻辑均为社区经验整理，不代表Anthropic官方实时政策，仅供参考。";
    }

    MessageBoxW(hWnd, report.c_str(), L"Claude IP风险详情", MB_OK | MB_ICONINFORMATION);
}

const wchar_t* TMIpPlugin::GetInfo(PluginInfoIndex index) {
    switch (index) {
    case TMI_NAME: return L"IP 地址显示";
    case TMI_DESCRIPTION: return L"显示内网/外网 IPv4 地址，可切换显示";
    case TMI_AUTHOR: return L"Lynn";
    case TMI_COPYRIGHT: return L"© 2025";
    case TMI_VERSION: return L"1.0.0";
    case TMI_URL: return L"";
    default: return L"";
    }
}

void TMIpPlugin::OnInitialize(ITrafficMonitor* pApp) {
    app_ = pApp;
    if (app_ && app_->GetAPIVersion() >= 1) {
        const wchar_t* dir = app_->GetPluginConfigDir();
        if (dir) config_dir_ = dir;
    }
    LoadOptions();
    proxywatch::StartWatching();
}

const wchar_t* TMIpPlugin::GetTooltipInfo() {
    return tooltip_.c_str();
}

ITMPlugin::OptionReturn TMIpPlugin::ShowOptionsDialog(void* hParent) {
    PluginOptions tmp = options_;
    bool changed = ShowIpOptionsDialog((HWND)hParent, tmp);
    if (changed) {
        options_ = tmp;
        text_provider_.SetOptions(options_);  // Update text provider with new options
        SaveOptions();
        return OR_OPTION_CHANGED;
    }
    return OR_OPTION_UNCHANGED;
}

const wchar_t* TMIpPlugin::GetCommandName(int command_index) {
    switch (command_index) {
    case 0: return L"显示内网IP"; // toggle
    case 1: return L"显示外网IP"; // toggle
    case 2: return L"刷新外网IP"; // one-shot refresh
    case 3: return L"查看Claude IP风险详情";
    default: return L"";
    }
}

void TMIpPlugin::OnPluginCommand(int command_index, void* hWnd, void* /*para*/) {
    switch (command_index) {
    case 0:
        options_.show_internal = !options_.show_internal;
        SaveOptions();
        break;
    case 1:
        options_.show_external = !options_.show_external;
        SaveOptions();
        break;
    case 2:
        force_refresh_next_ = true;
        break;
    case 3:
        ShowClaudeRiskReport((HWND)hWnd);
        break;
    default:
        break;
    }
}

int TMIpPlugin::IsCommandChecked(int command_index) {
    switch (command_index) {
    case 0: return options_.show_internal ? 1 : 0;
    case 1: return options_.show_external ? 1 : 0;
    default: return 0;
    }
}

void TMIpPlugin::LoadOptions() {
    // Defaults already set in options_. Try reading from ini if available
    std::wstring ini;
    if (!config_dir_.empty()) ini = JoinPath(config_dir_, L"tm_ip_plugin.ini");

    if (!ini.empty() && PathFileExistsW(ini.c_str())) {
        options_.show_internal = GetPrivateProfileIntW(L"ip", L"show_internal", options_.show_internal ? 1 : 0, ini.c_str()) != 0;
        options_.show_external = GetPrivateProfileIntW(L"ip", L"show_external", options_.show_external ? 1 : 0, ini.c_str()) != 0;

        wchar_t buf[256]{};
        GetPrivateProfileStringW(L"ip", L"preferred_adapter", L"", buf, (DWORD)std::size(buf), ini.c_str());
        options_.preferred_adapter = buf;

        int minutes = GetPrivateProfileIntW(L"ip", L"external_refresh_minutes", (int)options_.external_refresh.count(), ini.c_str());
        if (minutes <= 0) minutes = 2;
        options_.external_refresh = std::chrono::minutes(minutes);

        GetPrivateProfileStringW(L"ip", L"separator", L" | ", buf, (DWORD)std::size(buf), ini.c_str());
        options_.separator = buf;

        options_.enable_claude_risk_check = GetPrivateProfileIntW(
            L"ip", L"enable_claude_risk_check", options_.enable_claude_risk_check ? 1 : 0, ini.c_str()) != 0;
        options_.enable_exit_detection = GetPrivateProfileIntW(
            L"ip", L"enable_exit_detection", options_.enable_exit_detection ? 1 : 0, ini.c_str()) != 0;
    }
}

void TMIpPlugin::SaveOptions() {
    if (config_dir_.empty()) return;
    std::wstring ini = JoinPath(config_dir_, L"tm_ip_plugin.ini");
    WritePrivateProfileStringW(L"ip", L"show_internal", options_.show_internal ? L"1" : L"0", ini.c_str());
    WritePrivateProfileStringW(L"ip", L"show_external", options_.show_external ? L"1" : L"0", ini.c_str());
    WritePrivateProfileStringW(L"ip", L"preferred_adapter", options_.preferred_adapter.c_str(), ini.c_str());
    wchar_t tmp[32];
    _itow_s((int)options_.external_refresh.count(), tmp, 10);
    WritePrivateProfileStringW(L"ip", L"external_refresh_minutes", tmp, ini.c_str());
    WritePrivateProfileStringW(L"ip", L"separator", options_.separator.c_str(), ini.c_str());
    WritePrivateProfileStringW(L"ip", L"enable_claude_risk_check",
                                options_.enable_claude_risk_check ? L"1" : L"0", ini.c_str());
    WritePrivateProfileStringW(L"ip", L"enable_exit_detection",
                                options_.enable_exit_detection ? L"1" : L"0", ini.c_str());
}

// === IpPluginItem 自定义绘制函数实现 ===

/**
 * @brief 获取显示区域所需的宽度
 * @return 显示区域宽度（像素，96 DPI基准）
 * @details 计算能容纳最长IP地址的宽度，考虑垂直排列只需要单行宽度
 */
int IpPluginItem::GetItemWidth() const {
    // 返回能容纳"255.255.255.255"的宽度，约120像素（96 DPI下）
    // TrafficMonitor会根据当前DPI自动缩放
    int base = 120;
    if (provider_ && provider_->GetOptions().enable_claude_risk_check) {
        base += 14; // 多预留一个字符宽度给紧凑风险标记（⚠）
    }
    return base;
}

/**
 * @brief 自定义绘制函数 - 垂直排列显示内网和外网IP
 * @param hDC 设备上下文句柄
 * @param x 绘制区域左上角X坐标
 * @param y 绘制区域左上角Y坐标  
 * @param w 绘制区域宽度
 * @param h 绘制区域高度
 * @param dark_mode 是否为深色模式
 * @details 内网IP显示在上方，外网IP显示在下方，减少水平空间占用
 */
void IpPluginItem::DrawItem(void* hDC, int x, int y, int w, int h, bool dark_mode) {
    if (!hDC) return;
    
    HDC dc = static_cast<HDC>(hDC);
    
    // 设置文本颜色（深色模式用白色，浅色模式用黑色）
    COLORREF textColor = dark_mode ? RGB(255, 255, 255) : RGB(0, 0, 0);
    ::SetTextColor(dc, textColor);
    ::SetBkMode(dc, TRANSPARENT);  // 透明背景
    
    // 计算字体高度和行间距
    TEXTMETRIC tm;
    ::GetTextMetrics(dc, &tm);
    int lineHeight = tm.tmHeight;
    int totalLines = 0;
    
    // 统计要显示的行数
    if (!internal_ip_.empty()) totalLines++;
    if (!external_ip_.empty()) totalLines++;
    
    if (totalLines == 0) {
        // 没有可显示的内容，显示提示
        RECT rect = {x, y, x + w, y + h};
        ::DrawText(dc, L"请启用IP显示", -1, &rect, 
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        return;
    }
    
    // 计算垂直居中的起始位置
    int totalHeight = totalLines * lineHeight;
    int startY = y + (h - totalHeight) / 2;
    int currentY = startY;
    
    // 绘制内网IP（如果存在）
    if (!internal_ip_.empty()) {
        RECT rect = {x, currentY, x + w, currentY + lineHeight};
        ::DrawText(dc, internal_ip_.c_str(), -1, &rect, 
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        currentY += lineHeight;
    }
    
    // 绘制外网IP（如果存在）
    if (!external_ip_.empty()) {
        std::wstring display = external_ip_;
        if (provider_ && provider_->GetOptions().enable_claude_risk_check) {
            auto risk = claude_risk::GetClaudeRiskSnapshot();
            if (risk.valid && risk.HasAnyRisk()) display += L" ⚠";
        }
        RECT rect = {x, currentY, x + w, currentY + lineHeight};
        ::DrawText(dc, display.c_str(), -1, &rect,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        currentY += lineHeight;
    }
}

// === 插件工厂导出函数 ===

// Exported factory
extern "C" __declspec(dllexport) ITMPlugin* TMPluginGetInstance() {
    static TMIpPlugin s_plugin;
    return &s_plugin;
}
