/**
 * @file claude_risk.h
 * @brief Claude IP风险检测模块接口声明
 * @details 整合受限地区检测、直连可达性探测、VPN/代理/机房风险查询、
 *          IP波动追踪四项风险检测，外加Cloudflare出口信息纯展示（不参与风险判定）。
 *          所有网络检测在后台线程异步执行，调用方只读取缓存快照，不阻塞。
 * @author Lynn
 * @date 2026
 */

#pragma once

#include <string>
#include <chrono>

namespace claude_risk {

enum class Reachability { Unknown, Reachable, Blocked };
enum class RotationLevel { None, Notice, Warning, Severe };

struct ClaudeRiskInfo {
    bool valid = false;                 ///< 是否已完成至少一次检测
    std::chrono::system_clock::time_point checked_at{};

    // 1. Cloudflare出口信息（纯展示，不参与风险判定——很多用户故意只为Claude域名走分流代理，
    //    出口IP与本机检测到的外网IP不一致是正常现象，不代表风险）
    std::wstring cf_ip;                 ///< claude.ai/cdn-cgi/trace 的 ip=
    std::wstring cf_colo;                ///< colo= (机房代号，如LAX)
    std::wstring cf_loc;                 ///< loc=  (Cloudflare判定的国家代码，仍用于受限地区检测)
    std::wstring cf_as_name;             ///< Claude出口IP对应的网络运营商(org)
    bool cf_warp = false;                ///< warp=on/off
    bool cf_trace_ok = false;            ///< trace请求是否成功

    // 2. 受限地区检测
    bool country_restricted = false;
    std::wstring restricted_country_code;

    // 3. 直连可达性
    Reachability direct_reachability = Reachability::Unknown;

    // 4. VPN/代理/机房风险（ip-api.com）
    bool is_proxy = false;
    bool is_hosting = false;
    bool is_mobile = false;
    bool risk_query_ok = false;          ///< ip-api.com请求是否成功

    // 5. IP波动追踪
    int distinct_ip_count_30d = 0;
    RotationLevel rotation_level = RotationLevel::None;

    /// 是否命中任意一项风险（用于紧凑标记显示判断）
    bool HasAnyRisk() const {
        return country_restricted
            || direct_reachability == Reachability::Blocked
            || is_proxy || is_hosting
            || rotation_level == RotationLevel::Warning
            || rotation_level == RotationLevel::Severe;
    }
};

/// 返回当前缓存的快照（非阻塞，立即返回，内部加锁拷贝）
ClaudeRiskInfo GetClaudeRiskSnapshot();

/// 检查是否到达刷新间隔（或外网IP变化/强制刷新），需要时异步启动一次检测（非阻塞）
void RequestClaudeRiskRefreshAsync(const std::wstring& config_dir,
                                    const std::wstring& current_external_ip,
                                    const std::wstring& current_country,
                                    bool force_refresh);

// === 以下为内部纯逻辑函数，声明在头文件中以便独立验证 ===

/// 解析cdn-cgi/trace纯文本响应（key=value逐行），取出指定字段；未找到返回空字符串
std::wstring ParseTraceField(const std::string& trace_text, const std::string& field);

/// 解析ipinfo.io JSON响应中的org字段；未找到返回空字符串
std::wstring ParseIpInfoOrgField(const std::string& json);

/// 判断国家代码（不区分大小写）是否在受限名单中
bool IsRestrictedCountry(const std::wstring& country_code);

/// 根据30天内不同IP数量计算波动等级（1=None, 2-3=Notice, 4-6=Warning, 7+=Severe）
RotationLevel ComputeRotationLevel(int distinct_ip_count);

} // namespace claude_risk
