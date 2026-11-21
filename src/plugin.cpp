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
#include <algorithm>
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

static bool EnsureDirectoryExists(const std::wstring& dir) {
    if (dir.empty()) {
        return false;
    }
    if (PathIsDirectoryW(dir.c_str())) {
        return true;
    }

    std::wstring normalized = dir;
    while (normalized.size() > 3 &&
           (normalized.back() == L'\\' || normalized.back() == L'/')) {
        normalized.pop_back();
    }

    const std::size_t slash = normalized.find_last_of(L"\\/");
    if (slash != std::wstring::npos && slash > 2) {
        if (!EnsureDirectoryExists(normalized.substr(0, slash))) {
            return false;
        }
    }

    if (CreateDirectoryW(normalized.c_str(), nullptr)) {
        return true;
    }
    return GetLastError() == ERROR_ALREADY_EXISTS &&
           PathIsDirectoryW(normalized.c_str());
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
    proxywatch::StopWatching();
    iputils::ShutdownExternalIpWorker();
    claude_risk::ShutdownRefreshWorker();
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
    const bool proxy_refresh_requested = proxywatch::ConsumeTriggerFlag();
    bool force_refresh_requested = force_refresh_next_ || proxy_refresh_requested;
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
        // 直接读取快照字段，分隔符即使出现在IP里也不会破坏提示文本。
        const auto& internal = item_.InternalText();
        const auto& external = item_.ExternalText();
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
        report += !risk.risk_query_ok ? L"未知（查询失败）" : risk.is_proxy ? L"是" : L"否";
        report += L"\n机房/数据中心: ";
        report += !risk.risk_query_ok ? L"未知（查询失败）" : risk.is_hosting ? L"是" : L"否";
        report += L"\n移动网络: ";
        report += !risk.risk_query_ok ? L"未知（查询失败）" : risk.is_mobile ? L"是" : L"否";
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
        SetConfigDirectory(app_->GetPluginConfigDir());
    }
    proxywatch::StartWatching();
}

void TMIpPlugin::OnExtenedInfo(ExtendedInfoIndex index, const wchar_t* data) {
    if (index == EI_CONFIG_DIR) SetConfigDirectory(data);
}

void TMIpPlugin::SetConfigDirectory(const wchar_t* directory) {
    if (!directory || !*directory) return;
    std::wstring path = directory;
    if (PathIsRelativeW(path.c_str())) {
        // 开机自启和手动启动的工作目录可能不同，相对路径固定以宿主EXE为基准。
        wchar_t executable[32768]{};
        const DWORD length = GetModuleFileNameW(nullptr, executable, (DWORD)std::size(executable));
        if (length == 0 || length >= std::size(executable)) return;
        const std::wstring executable_path(executable, length);
        const auto slash = executable_path.find_last_of(L"\\/");
        if (slash == std::wstring::npos) return;
        path = JoinPath(executable_path.substr(0, slash), path);
    }
    const DWORD required = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (required == 0) return;
    std::wstring absolute(required, L'\0');
    const DWORD length = GetFullPathNameW(path.c_str(), required, &absolute[0], nullptr);
    if (length == 0 || length >= required) return;
    absolute.resize(length);
    while (absolute.size() > 3 && (absolute.back() == L'\\' || absolute.back() == L'/')) {
        absolute.pop_back();
    }
    if (absolute == config_dir_) return;
    config_dir_ = std::move(absolute);
    LoadOptions();
    text_provider_.SetOptions(options_);
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
        if (!SaveOptions()) ReportSaveError((HWND)hParent);
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
        if (!SaveOptions()) ReportSaveError((HWND)hWnd);
        break;
    case 1:
        options_.show_external = !options_.show_external;
        if (!SaveOptions()) ReportSaveError((HWND)hWnd);
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
        minutes = std::min(minutes, 1440);
        options_.external_refresh = std::chrono::minutes(minutes);

        options_.enable_smart_cache = GetPrivateProfileIntW(
            L"ip", L"enable_smart_cache", options_.enable_smart_cache ? 1 : 0, ini.c_str()) != 0;
        int fast_seconds = GetPrivateProfileIntW(
            L"ip", L"fast_refresh_seconds", (int)options_.fast_refresh.count(), ini.c_str());
        options_.fast_refresh = std::chrono::seconds(std::clamp(fast_seconds, 1, 3600));
        int max_minutes = GetPrivateProfileIntW(
            L"ip", L"max_refresh_minutes", (int)options_.max_refresh.count(), ini.c_str());
        options_.max_refresh = std::chrono::minutes(std::clamp(max_minutes, minutes, 1440));

        GetPrivateProfileStringW(L"ip", L"separator", L" | ", buf, (DWORD)std::size(buf), ini.c_str());
        options_.separator = buf;
        if (options_.separator.empty()) options_.separator = L" | ";

        options_.enable_claude_risk_check = GetPrivateProfileIntW(
            L"ip", L"enable_claude_risk_check", options_.enable_claude_risk_check ? 1 : 0, ini.c_str()) != 0;
        options_.enable_exit_detection = GetPrivateProfileIntW(
            L"ip", L"enable_exit_detection", options_.enable_exit_detection ? 1 : 0, ini.c_str()) != 0;
    }
}

bool TMIpPlugin::SaveOptions() {
    if (config_dir_.empty()) {
        SetLastError(ERROR_PATH_NOT_FOUND);
        return false;
    }
    if (!EnsureDirectoryExists(config_dir_)) return false;
    std::wstring ini = JoinPath(config_dir_, L"tm_ip_plugin.ini");
    if (!WritePrivateProfileStringW(L"ip", L"show_internal", options_.show_internal ? L"1" : L"0", ini.c_str())) return false;
    if (!WritePrivateProfileStringW(L"ip", L"show_external", options_.show_external ? L"1" : L"0", ini.c_str())) return false;
    if (!WritePrivateProfileStringW(L"ip", L"preferred_adapter", options_.preferred_adapter.c_str(), ini.c_str())) return false;
    wchar_t tmp[32];
    _itow_s((int)options_.external_refresh.count(), tmp, 10);
    if (!WritePrivateProfileStringW(L"ip", L"external_refresh_minutes", tmp, ini.c_str())) return false;
    if (!WritePrivateProfileStringW(L"ip", L"enable_smart_cache",
                                options_.enable_smart_cache ? L"1" : L"0", ini.c_str())) return false;
    if (!WritePrivateProfileStringW(L"ip", L"fast_refresh_seconds",
                                std::to_wstring(options_.fast_refresh.count()).c_str(), ini.c_str())) return false;
    if (!WritePrivateProfileStringW(L"ip", L"max_refresh_minutes",
                                std::to_wstring(options_.max_refresh.count()).c_str(), ini.c_str())) return false;
    if (!WritePrivateProfileStringW(L"ip", L"separator", options_.separator.c_str(), ini.c_str())) return false;
    if (!WritePrivateProfileStringW(L"ip", L"enable_claude_risk_check",
                                options_.enable_claude_risk_check ? L"1" : L"0", ini.c_str())) return false;
    if (!WritePrivateProfileStringW(L"ip", L"enable_exit_detection",
                                options_.enable_exit_detection ? L"1" : L"0", ini.c_str())) return false;
    // flush的返回值与普通写入不同，成功刷新缓存也可能返回0，不将其当作写入失败。
    WritePrivateProfileStringW(nullptr, nullptr, nullptr, ini.c_str());
    return true;
}

void TMIpPlugin::ReportSaveError(HWND parent) {
    const DWORD error = GetLastError();
    std::wstring message = L"当前显示已应用，但配置保存失败，重新启动后可能恢复原来的选择。\n\n";
    if (config_dir_.empty()) {
        message += L"宿主尚未提供插件配置目录。";
    } else {
        message += L"配置文件：" + JoinPath(config_dir_, L"tm_ip_plugin.ini");
        message += L"\n请检查此目录和文件是否允许当前用户写入。";
    }
    message += L"\n错误代码：" + std::to_wstring(error);
    MessageBoxW(parent, message.c_str(), L"IP插件配置未保存", MB_OK | MB_ICONWARNING);
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
    // API没有卸载回调。将模块及单例保留到进程退出，避免DLL卸载时仍有
    // worker执行，或静态析构在loader lock中等待线程。替换DLL需要重启宿主。
    static TMIpPlugin* s_plugin = []() -> TMIpPlugin* {
        HMODULE module = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_PIN,
                               reinterpret_cast<LPCWSTR>(&g_hInst), &module)) {
            return nullptr;
        }
        try {
            return new TMIpPlugin;
        } catch (...) {
            return nullptr;
        }
    }();
    return s_plugin;
}
