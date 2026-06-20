# Claude IP 风险检测功能设计

## 背景

用户希望参考 `https://ip.net.coffee/claude/` 页面"对IP做风险评估"的思路，集成到本插件中，并提供设置开关。

对该页面进行HAR抓包分析后确认：**该功能与Claude大模型本身无关**，是该网站自有的私有风控后端（`/api/iprisk/{ip}`），不应被本插件直接调用（无文档、无授权、易被封锁）。但页面中调用的 `claude.ai/cdn-cgi/trace`（Cloudflare公开诊断端点）是可以合法复用的公开数据源。

进一步结合用户指定的参考项目 `https://github.com/cso1z/claude-ip-guard`（MIT许可，Claude Code Hook脚本，做IP地理合规检测+IP波动追踪），扩展为一个综合的"Claude IP风险检测"功能。

## 范围

新增一个默认关闭的可选功能，整合5项检测，通过悬浮提示、紧凑标记和右键菜单命令展示，不对任何网络请求做实际拦截（本插件只读展示，不像claude-ip-guard会真正阻断Claude Code的请求）。

## 架构

新增独立模块 `src/claude_risk.h` / `src/claude_risk.cpp`，与现有 `ip_utils`（基础IP获取）解耦。

由于本功能串联4类额外网络请求（Cloudflare trace、直连探测、ip-api.com风险查询、历史文件IO），若同步阻塞执行，最坏情况会让 `DataRequired()` 阻塞十几秒，可能冻结TrafficMonitor主界面。因此采用**后台线程异步刷新 + 互斥锁保护的缓存快照**模式：

- `ClaudeRiskInfo GetClaudeRiskSnapshot()`：非阻塞，直接返回缓存的最新结果（结构体拷贝，内部加锁）。
- `void RequestClaudeRiskRefreshAsync(const std::wstring& config_dir, const std::wstring& current_external_ip, const std::wstring& current_country, bool force)`：检查是否到达刷新间隔（或强制刷新/外网IP变化），如需刷新且当前没有正在进行的刷新，则启动一个**detached** `std::thread`执行完整检测流程，完成后加锁写回缓存快照。否则直接返回（不阻塞）。
- **缓存快照的存储位置**：与 `ip_utils.cpp::GetExternalIPv4WithCountry` 完全一致的模式——缓存变量（`ClaudeRiskInfo` + `mutex` + 上次刷新时间 + "是否有刷新线程在途"标志）是 `claude_risk.cpp` 内的**函数级 `static`**，归属进程/模块生命周期，**不是** `TMIpPlugin` 或 `IpPluginItem` 的成员。这样即使某个 `TMIpPlugin` 实例的生命周期结束，detached线程写回的目标（静态变量）依然有效，不存在对象生命周期耦合的use-after-free问题；其风险等级与现有外网IP缓存的"DLL被宿主卸载时线程仍在执行"风险严格等价，没有引入新的风险类别。
- 线程内部短生命周期（每次刷新对应一个线程，做完即退出，不常驻），进一步降低悬挂线程概率。
- **调用链（明确调用点，避免歧义）**：触发刷新的调用点是 `TMIpPlugin::DataRequired()`（因为只有它持有 `config_dir_`），而不是 `IpPluginItem::Update()`。具体顺序：
  1. `TMIpPlugin::DataRequired()` 先调用 `item_.Update(force_refresh_next_)`（现有逻辑不变）。
  2. 紧接着，若 `options_.enable_claude_risk_check` 为真，调用 `claude_risk::RequestClaudeRiskRefreshAsync(config_dir_, item_.ExternalIpRaw(), item_.ExternalCountryRaw(), force_refresh_next_)`（非阻塞，仅在需要时才真正启动线程）。
  3. 需要给 `IpPluginItem` 新增两个只读 getter：`const std::wstring& ExternalIpRaw() const`（返回 `Update()` 内部已经拿到的 `ext_result.ip`，需要把 `ext_result` 提升为成员变量而不是局部变量）、`const std::wstring& ExternalCountryRaw() const`（对应 `ext_result.country`）。
  4. 展示侧（tooltip拼接、紧凑标记）统一通过 `claude_risk::GetClaudeRiskSnapshot()` 读快照，与"是否刚刚触发了刷新"无关——首次启用、快照为空时（`valid == false`）展示"检测中…"。

刷新间隔固定为30分钟（不在UI中开放配置，保持开关粒度简单），但当检测到外网IP变化时提前触发一次刷新（复用 `ip_utils` 现有"网络变化"检测信号的思路）。

**单次刷新内部的一致性**：一次后台线程执行完整走完全部5项检测，最终一次性加锁写入整个 `ClaudeRiskInfo` 结构体（而不是逐字段更新），保证结构体内各字段（尤其是 `cf_loc` 与受限地区判定结果）始终来自同一个时间点的同一次检测，不会出现"用旧的国家代码判定，却显示新的Cloudflare colo"之类的跨时间点矛盾。受限地区判定优先使用本次检测刚取到的 `cf_loc`；若Cloudflare trace请求失败，则回退使用调用方传入的 `current_external_ip` 对应的 `current_country`参数（同一次调用传入的值，时间点上与本次检测一致）。

## 数据结构

```cpp
namespace claude_risk {

enum class Reachability { Unknown, Reachable, Blocked };
enum class RotationLevel { None, Notice, Warning, Severe };

struct ClaudeRiskInfo {
    bool valid = false;                 // 是否已完成至少一次检测
    std::chrono::system_clock::time_point checked_at{};

    // 1. Cloudflare出口视角对比
    std::wstring cf_ip;                 // claude.ai/cdn-cgi/trace 的 ip=
    std::wstring cf_colo;               // colo=  (机房代号，如LAX)
    std::wstring cf_loc;                // loc=   (Cloudflare判定的国家代码)
    bool cf_warp = false;               // warp=on/off
    bool ip_mismatch = false;           // cf_ip 与插件检测到的外网IP是否不一致

    // 2. 受限地区检测
    bool country_restricted = false;
    std::wstring restricted_country_code;

    // 3. 直连可达性
    Reachability direct_reachability = Reachability::Unknown;

    // 4. VPN/代理/机房风险（ip-api.com）
    bool is_proxy = false;
    bool is_hosting = false;
    bool is_mobile = false;
    bool risk_query_ok = false;         // ip-api.com请求是否成功（区分"无风险"和"未知"）

    // 5. IP波动追踪
    int distinct_ip_count_30d = 0;
    RotationLevel rotation_level = RotationLevel::None;
};

ClaudeRiskInfo GetClaudeRiskSnapshot();
void RequestClaudeRiskRefreshAsync(const std::wstring& config_dir,
                                   const std::wstring& current_external_ip,
                                   const std::wstring& current_country,
                                   bool force_refresh);

} // namespace claude_risk
```

## 各检测项实现细节

### 1. Cloudflare出口视角对比
- `GET https://claude.ai/cdn-cgi/trace`（WinHTTP，HTTPS，复用现有连接模式）
- 响应为纯文本 `key=value` 逐行格式，解析 `ip=`、`colo=`、`loc=`、`warp=`
- 与传入的 `current_external_ip` 比较，不一致则 `ip_mismatch = true`

示例响应：
```
ip=69.63.196.167
colo=LAX
loc=US
warp=off
```

### 2. 受限地区检测
硬编码19国名单（来源：`claude-ip-guard` 项目的 `BLOCKED_COUNTRIES`，综合Anthropic官方支持地区+OFAC出口管制名单）：

```
CN RU KP IR SY CU BY VE MM LY SO YE ML CF SS CD ER AF UA
```

用 `cf_loc`（优先，更贴近Claude视角）或缺失时用 `current_country` 与名单比对。**仅展示提示，不做任何拦截**。需在UI文案中注明"名单仅供参考，可能与Anthropic实际政策存在出入"。

### 3. 直连可达性探测
- `POST https://api.anthropic.com/v1/messages`
- Headers: `Content-Type: application/json`, `anthropic-version: 2023-06-01`, `x-api-key: sk-ant-api03-dummy`（固定占位字符串，非真实凭据）
- Body: `{"model":"claude-3-5-sonnet-20240620","max_tokens":16,"messages":[{"role":"user","content":"ping"}]}`
- 超时：connect/send/receive 各5秒
- 判定：HTTP 403 → `Blocked`；请求失败/超时 → `Unknown`；其余任意HTTP响应（如401，证明请求穿透到了API层只是key无效）→ `Reachable`
- 来源：`claude-ip-guard` 项目同款探测手法，复用其判定逻辑

### 4. VPN/代理/机房风险
- `GET http://ip-api.com/json/{ip}?fields=status,proxy,hosting,mobile`（注意：明文HTTP，免费版不支持HTTPS，已与用户确认此取舍——仅用于非敏感的诊断性展示）
- 解析JSON字段 `proxy`、`hosting`、`mobile`（布尔值）
- 免费版限频45次/分钟，本功能30分钟一次的调用频率远低于限制

### 5. IP波动追踪
- 历史文件：`<config_dir>\tm_ip_plugin_iphistory.log`，与 `tm_ip_plugin.ini` 同目录
- 格式：每行 `<unix秒时间戳>|<IP>|<国家代码>`，纯文本（项目无JSON库，保持与现有代码风格一致）
- 写入逻辑：当 `current_external_ip` 与历史文件中**已存在的任意一条IP**不重复时，追加一行新记录（去重逻辑对齐 `claude-ip-guard`：同一个IP只记一次，用于统计"过去30天用过几个不同IP"）
- 读取逻辑：每次刷新时读取文件，过滤出30天内的记录，去重计数得到 `distinct_ip_count_30d`，同时丢弃超过30天的旧记录并原子重写文件（写临时文件 + `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` 重命名，避免并发损坏）。由于"是否有刷新线程在途"标志保证同一时刻最多只有一个检测线程在跑，不会出现两个线程同时读写历史文件的竞争。
- 分级阈值（与 `claude-ip-guard` 一致）：1个→`None`；2-3个→`Notice`；4-6个→`Warning`；7+个→`Severe`

## UI展示

### 悬浮提示（Tooltip）
在 `TMIpPlugin::DataRequired()` 现有tooltip拼接逻辑基础上，当 `options_.enable_claude_risk_check` 为真时追加一段：

```
——Claude IP风险——
出口对比: 一致 (LAX机房)        // 或 "不一致，可能存在分流代理"
受限地区: 未命中                 // 或 "命中：CN（仅供参考）"
直连Claude: 可达                 // 或 "被屏蔽(403)" / "未知"
风险属性: 无明显风险             // 或 "疑似机房/代理IP"
IP波动: 近30天1个IP              // 或 "近30天4个IP（警告）"
```

### 紧凑标记
现有自绘两行布局不变。当任一项命中风险时，在 `external_ip_` 行末尾追加一个简短后缀（如 ` ⚠`），平时不显示。

**宽度处理**：`IpPluginItem::GetItemWidth()` 当前固定返回120（按"255.255.255.255"估算）。追加的警示符若不预留空间，会被 `DrawItem` 里的 `DT_END_ELLIPSIS` 截断，导致警示符显示不出来，失去意义。修改为：当 `provider_->GetOptions().enable_claude_risk_check == true` 时返回 `120 + 14`（多预留一个字符宽度给警示符），否则仍返回120，不影响未启用该功能的用户。

### 新增右键菜单命令
`GetCommandCount()` 从3改为4，新增命令"查看Claude IP风险详情"，点击后 `MessageBoxW` 展示完整报告文本（即tooltip中风险段落的完整版，含更详细的字段如colo、ip-api查询状态等）。

## 配置项

`PluginOptions` 新增：
```cpp
bool enable_claude_risk_check = false;   // 总开关，默认关闭
```

`options_dialog` 新增一个勾选框控件，新增资源ID `IDC_CHECK_CLAUDE_RISK`（在 `res/resource.h` 中接续现有编号，定义为 `1006`）。

**对话框布局调整（具体坐标）**：当前 `res/plugin.rc` 中 `IDD_OPTIONS` 尺寸为 `250x150`，现有控件已排到 `y=115`（确定/取消按钮），`y=85~99`（分隔符行）和 `y=115`之间只有约15px空隙，不足以放下一个新勾选框。改为：
- 对话框尺寸由 `250, 150` 改为 `250, 165`（高度+15）。
- 新增控件：`CONTROL "启用Claude IP风险检测", IDC_CHECK_CLAUDE_RISK, "Button", BS_AUTOCHECKBOX | WS_TABSTOP, 10, 100, 180, 12`（插入在"分隔符"行下方，按钮行上方）。
- 现有 `DEFPUSHBUTTON`/`PUSHBUTTON` 的 `y` 坐标从 `115` 下移到 `130`（即 `110, 130, 50, 14` 与 `170, 130, 50, 14`），为新勾选框让出空间。

`options_dialog.cpp` 的 `WM_INITDIALOG`/`IDOK` 分支按现有 `SetCheck`/`GetCheck` 模式新增对 `IDC_CHECK_CLAUDE_RISK` 的读写，并纳入 `changed` 比较表达式。

INI新增键：`[ip] enable_claude_risk_check=0/1`，读写逻辑对齐现有 `LoadOptions`/`SaveOptions` 模式。

不单独开放刷新间隔配置（保持"一个总开关"的简单性，已与用户确认）。

**新模块的字符集声明**：`claude_risk.cpp`（及如有需要的 `claude_risk.h`）必须在文件顶部加 `#pragma execution_character_set("utf-8")`，与 `plugin.cpp`/`plugin.h` 的现有约定一致，否则文件内的中文提示文案（风险报告文案、MessageBox文本）在非UTF-8源文件下会乱码。

## README更新

新增"参考与致谢"小节：
- `https://ip.net.coffee/claude/` —— Cloudflare出口IP对比思路的灵感来源
- `https://github.com/cso1z/claude-ip-guard`（MIT License）—— 受限地区名单、直连探测方法、IP波动分级阈值参考自该项目

## 风险与权衡（需在README/设置文案中明确告知用户）

1. ip-api.com风险查询走明文HTTP，存在被路径中间人窃听/篡改诊断结果的理论风险（不涉及账号密钥等敏感信息，纯展示用途）。
2. 直连探测使用固定占位API Key字符串发起请求，不消耗真实账号额度，但本质是对`api.anthropic.com`的真实网络请求；功能默认关闭，用户需主动开启。
3. 受限地区名单为社区整理版本，不代表Anthropic官方实时政策，仅供参考。
4. **新增后台线程是本项目首次引入的并发模式**：`ip_utils.cpp`现有的外网IP获取是同步阻塞调用，没有用到线程；本功能的`claude_risk.cpp::DoRefresh`是项目里第一处detached `std::thread`。若DLL在某次检测仍在进行（最坏情况约5项请求×5秒超时≈25秒）时被宿主意外卸载，该线程会在已卸载的DLL代码/数据上继续执行，存在崩溃风险——这是一个**新增的**风险点，而非"和现有代码等量级"（此前版本的描述不准确，已修正）。接受该风险的理由是：TrafficMonitor插件在实践中通常随主程序进程同生命周期（仅在进程退出时整体卸载，此时所有线程一并终止，不存在悬挂问题），且未观察到主程序支持"运行期单独卸载某个插件DLL"的机制；同时通过单飞锁（`g_refresh_in_flight`）保证同一时刻最多一个检测线程在跑，限制暴露窗口。若未来发现TrafficMonitor确实支持运行期热卸载插件，需要重新评估此设计。
5. **直连探测的判定逻辑依赖Anthropic API未公开承诺的行为**（"403=区域/WAF拦截，其余响应（含401）=可达"），这是参考`claude-ip-guard`项目观察到的现状推测出的经验规则，不是Anthropic官方文档行为；若Anthropic未来调整WAF/限流策略，该判定可能失效（如改用其他状态码拦截），需要在README/设置说明中标注为"经验性探测，结果仅供参考"，并作为后续维护时优先检查的点。

## 不做的事（YAGNI）

- 不复刻 `ip.net.coffee` 的DNS泄露测试（需要自建权威DNS服务器，超出本插件范围）。
- 不调用 `ip.net.coffee` 的私有 `/api/iprisk` 接口。
- 不引入需要用户注册/申请Key的第三方风险API。
- 不在UI中开放刷新间隔等细粒度配置。
- 不做任何实际拦截/阻断行为，仅展示。
