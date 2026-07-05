# TrafficMonitor 智能IP地址显示插件

一个功能完整的TrafficMonitor插件，智能显示内网和外网IPv4地址，支持国家代码标识和自适应刷新策略。

## 🌟 主要功能

- **双IP显示**：同时显示内网IP和外网IP（含国家代码）
- **供应商显示**：内网关闭时智能显示外网IP供应商名称
- **垂直布局**：内网IP在上，外网IP在下，节省任务栏空间
- **智能缓存**：网络变化时快速响应（30秒），稳定时节能运行（2-5分钟）
- **国家标识**：外网IP前显示国家代码（CN、US、JP等）
- **网络优先级**：智能选择最佳内网IP（192.168.x.x > 10.x.x.x > 172.16-31.x.x）
- **代理软件监控**：检测到Clash、V2rayN等常见代理软件窗口打开/关闭/切换前台时，自动触发一次外网IP强制刷新，切换代理节点后无需等待缓存过期
- **Claude IP风险检测**（可选，默认关闭）：对比Cloudflare出口IP、检测受限地区、探测Claude直连可达性、识别VPN/代理/机房IP、追踪30天IP波动

## 📦 快速安装

1. 下载 `TrafficMonitorIpPlugin.dll` 
2. 复制到TrafficMonitor的 `plugins` 目录
3. 重启TrafficMonitor
4. 在设置中启用"内外网IP显示"插件

## 🎮 使用方法

### 任务栏显示效果

**同时显示内外网IP：**
```
192.168.1.100      ← 内网IP
CN 121.12.34.56    ← 外网IP + 国家代码
```

**仅显示外网IP时（内网关闭）：**
```
DMIT Cloud         ← 供应商名称
JP 154.31.113.180  ← 外网IP + 国家代码
```

### 工具提示信息

**双IP模式：**
```
内网: 192.168.1.100
外网: CN 121.12.34.56
```

**仅外网模式：**
```
外网: DMIT Cloud
JP 154.31.113.180
```

### 右键菜单命令
- **显示内网IP**：切换内网IP显示
- **显示外网IP**：切换外网IP显示  
- **刷新外网IP**：立即强制刷新
- **查看Claude IP风险详情**：弹窗展示完整的Claude IP风险检测报告（需先在设置中启用该功能）

## 🏢 供应商显示功能

### 功能说明
当关闭内网IP显示时，插件会智能地在原内网IP位置显示外网IP的供应商名称，保持垂直布局的美观性。

### 支持的供应商格式
| API返回格式 | 处理后显示 |
|------------|-----------|
| AS906 DMIT Cloud Services | DMIT Cloud |
| AS13335 Cloudflare, Inc. | Cloudflare |
| AS15169 Google LLC | Google |
| AS16509 Amazon.com, Inc. | Amazon.com |

### 处理规则
1. **去除AS前缀**：自动移除"AS"开头的自治系统号码
2. **截取主要名称**：逗号前的部分作为主要名称
3. **去除后缀**：移除常见的公司后缀（Inc.、LLC、Services等）
4. **保持简洁**：确保显示内容适合任务栏空间

## 🛰️ 代理软件自动检测刷新

切换代理节点（如Clash分流规则）后，外网出口IP会变化，但插件默认按缓存间隔刷新，可能要等几分钟才能看到新IP。为此插件会在后台注册一个全局窗口事件钩子，监控常见代理软件窗口的**前台切换 / 显示或隐藏 / 最小化还原**，命中时立即触发一次外网IP强制刷新（无需等待缓存过期）。

### 已支持的代理软件（按可执行文件名匹配）
`clash.exe`、`clash-verge.exe`、`Clash Verge.exe`、`clash-verge-service.exe`、`mihomo.exe`、`mihomo-party.exe`、`Clash Party.exe`（Mihomo Party改名后的可执行文件）、`FlClash.exe`、`v2rayN.exe`、`v2rayNG.exe`、`Netch.exe`、`Qv2ray.exe`、`nekoray.exe`、`NekoBox.exe`、`sagernet.exe`、`Shadowsocks.exe`、`ss-win.exe`、`Proxifier.exe`、`ClashX.exe`

### 注意事项
- 该功能无需配置，插件初始化时自动在独立线程启动，随进程退出自然回收。
- 如果你使用的代理软件不在上述列表中，或软件更新后重命名了可执行文件（例如"Mihomo Party"目前的可执行文件名是`Clash Party.exe`而非`mihomo-party.exe`），自动触发会失效，需要在`src/proxy_watch.cpp`的`kWatchedProcessNames`数组中补充对应文件名后重新编译；也可以直接用右键菜单"刷新外网IP"手动触发。
- 全局窗口钩子受Windows UIPI限制：若代理软件以管理员权限运行，而TrafficMonitor以普通用户权限运行，钩子将无法收到该软件的窗口事件（这是Windows的完整性级别隔离机制，非插件缺陷）。

## 🔍 Claude IP风险检测（可选功能）

默认关闭，需在插件设置中勾选"启用Claude IP风险检测"。启用后会增加以下检测，结果显示在悬浮提示和右键菜单"查看Claude IP风险详情"中：

| 检测项 | 说明 |
|--------|------|
| Cloudflare出口信息 | 请求 `claude.ai/cdn-cgi/trace`，展示Cloudflare看到的访问claude.ai时的出口IP与机房代号；纯展示，不作风险判断（许多用户特意为Claude配置分流代理，出口IP与本机外网IP不同是正常现象） |
| 受限地区检测 | 将出口国家代码与Anthropic受限地区/OFAC制裁名单比对，仅提示不拦截 |
| 直连可达性探测 | 对`api.anthropic.com`发起一次轻量探测请求（使用占位假Key，不消耗真实账号），判断网络层是否被屏蔽 |
| VPN/代理/机房风险 | 通过`ip-api.com`查询当前外网IP是否为VPN/代理/数据中心/移动网络出口 |
| IP波动追踪 | 本地记录外网IP变化历史，统计近30天出现过的不同IP数量并分级提示 |

**已知取舍**：
- VPN/代理/机房风险查询走明文HTTP（`ip-api.com`免费版不支持HTTPS），不涉及账号密钥等敏感信息，纯展示用途。
- 受限地区名单与直连探测的判定逻辑均为社区经验整理，不代表Anthropic官方实时政策，仅供参考。
- 该功能会引入额外的后台网络请求和一个后台线程，默认关闭，需用户主动启用。

## ⚙️ 配置选项

打开TrafficMonitor设置 → 插件 → IP地址显示 → 选项：

- **显示设置**：选择显示内网IP、外网IP或两者
- **网络适配器**：指定首选网络适配器或自动选择
- **刷新间隔**：外网IP标准刷新间隔（默认5分钟）
- **智能缓存**：启用网络变化检测和自适应刷新
- **分隔符**：自定义IP间分隔符

## 🚀 智能特性

### 供应商名称显示
- 自动从外网IP获取供应商信息（如DMIT Cloud、Cloudflare等）
- 智能处理供应商名称格式，去除AS号码和公司后缀
- 内网关闭时在上层位置显示供应商名称，保持垂直布局

### 网络变化检测
- 自动检测内网IP变化（网络切换、VPN连接等）
- 变化时立即获取新的外网IP，然后进入30秒快速验证模式
- 连续6次验证后恢复正常2分钟间隔

### 响应速度对比
| 场景 | 传统固定模式 | 智能模式 |
|------|------------|---------|
| 网络切换 | 最长2分钟 | **立即+30秒** |
| VPN切换 | 最长2分钟 | **立即+30秒** |  
| 代理软件窗口事件 | 需等缓存过期 | **立即触发刷新** |
| 稳定使用 | 2分钟固定 | 2-5分钟自适应 |

## 🔧 技术特性

- **安全通信**：使用HTTPS连接获取外网IP（ipinfo.io API）
- **供应商解析**：从ipinfo.io的org字段获取供应商信息
- **智能处理**：自动处理"AS906 DMIT Cloud Services"格式，提取主要名称
- **多API支持**：ipinfo.io主服务 + httpbin.org备用服务
- **线程安全**：完整的多线程保护和缓存机制
- **容错处理**：网络异常时显示"N/A"，包含详细的错误处理

## 💾 配置文件

位置：`%TrafficMonitor%\plugins\config\tm_ip_plugin.ini`

```ini
[ip]
show_internal=1                # 显示内网IP
show_external=1                # 显示外网IP  
preferred_adapter=             # 首选网络适配器
external_refresh_minutes=2     # 标准刷新间隔
separator= | #                 # IP分隔符
enable_smart_cache=1           # 启用智能缓存
fast_refresh_seconds=30        # 快速刷新间隔
max_refresh_minutes=5          # 最大刷新间隔
enable_claude_risk_check=0     # 启用Claude IP风险检测（默认关闭）
```

## 🐛 故障排除

### 外网IP显示"N/A"
1. 检查网络连接是否正常
2. 确认防火墙未阻止TrafficMonitor的HTTPS连接
3. 右键菜单选择"刷新外网IP"手动更新
4. 检查企业网络是否需要代理设置

### 内网IP显示不正确  
1. 在插件设置中指定首选网络适配器
2. 选择状态为"已连接"的适配器
3. 重启TrafficMonitor重新检测网络

### 切换代理节点后外网IP没有自动刷新
1. 确认所用代理软件的可执行文件名在"代理软件自动检测刷新"一节的已支持列表中——软件更新可能改了可执行文件名（例如"Mihomo Party"目前叫`Clash Party.exe`）
2. 若不在列表中，右键菜单选择"刷新外网IP"手动触发，或在`src/proxy_watch.cpp`补充文件名后重新编译
3. 确认代理软件与TrafficMonitor的运行权限一致（都不以管理员身份运行，或都以管理员身份运行）——Windows的UIPI机制会阻止普通权限进程接收管理员权限窗口的事件
4. **重新编译后别忘了替换`plugins`目录里的DLL并重启TrafficMonitor**——Windows不会热更新已加载的插件文件

## 📊 系统要求

- **操作系统**：Windows 7/8/10/11 (x64)
- **TrafficMonitor**：支持插件API的版本
- **网络连接**：需要Internet连接获取外网IP和国家信息
- **运行时库**：Visual C++ 2022 Redistributable (x64)

---

## 🙏 参考与致谢

"Claude IP风险检测"功能的设计参考了以下项目，特此致谢：

- [ip.net.coffee/claude](https://ip.net.coffee/claude/) —— Cloudflare出口IP对比思路的灵感来源
- [cso1z/claude-ip-guard](https://github.com/cso1z/claude-ip-guard)（MIT License）—— 受限地区名单、直连可达性探测方法、IP波动分级阈值参考自该项目

## 🛠️ 开发者信息

### 构建环境 (Visual Studio 2022)
- 打开 `TrafficMonitorIpPlugin.vcxproj`
- 配置：`Debug|x64` 或 `Release|x64`
- 工具集：v143，Windows SDK 10.0
- 字符编码：UTF-8 with BOM
- 输出：`bin\x64\<Config>\TrafficMonitorIpPlugin.dll`

### 项目结构
- `PluginInterface.h`：TrafficMonitor插件接口
- `src/ip_utils.h/.cpp`：IP获取和智能缓存逻辑
- `src/proxy_watch.h/.cpp`：代理软件窗口打开/关闭监控，命中时触发外网IP强制刷新
- `src/claude_risk.h/.cpp`：Claude IP风险检测逻辑（Cloudflare对比、受限地区、直连探测、VPN/代理识别、IP波动追踪）
- `src/plugin_options.h`：用户配置选项定义  
- `src/plugin.h/.cpp`：插件主体实现
- `src/options_dialog.h/.cpp`：设置对话框

### 技术实现
- **内网IP**：使用GetAdaptersAddresses API，支持优先级选择
- **外网IP**：ipinfo.io HTTPS API，JSON解析，支持国家代码
- **供应商名称**：从org字段提取并智能处理供应商信息
- **智能缓存**：基于内网IP变化检测的自适应刷新策略
- **UI绘制**：自定义绘制支持垂直布局和深色模式

### 依赖库
- `Iphlpapi.lib`：IP Helper API
- `Ws2_32.lib`：Winsock 2.0
- `Winhttp.lib`：HTTP客户端
- `Shlwapi.lib`：Shell实用工具

### 版本信息
- **作者**：Lynn
- **版本**：v1.0.0
- **开发时间**：2025年
- **许可**：开源，仅供学习和个人使用

---

**让TrafficMonitor更智能，让IP显示更便捷！** 🚀
