# TrafficMonitor 智能IP地址显示插件

一个功能完整的TrafficMonitor插件，智能显示内网和外网IPv4地址，支持国家代码标识和自适应刷新策略。

## 🌟 主要功能

- **双IP显示**：同时显示内网IP和外网IP（含国家代码）
- **垂直布局**：内网IP在上，外网IP在下，节省任务栏空间
- **智能缓存**：网络变化时快速响应（30秒），稳定时节能运行（5-15分钟）
- **国家标识**：外网IP前显示国家代码（CN、US、JP等）
- **网络优先级**：智能选择最佳内网IP（192.168.x.x > 10.x.x.x > 172.16-31.x.x）

## 📦 快速安装

1. 下载 `TrafficMonitorIpPlugin.dll` 
2. 复制到TrafficMonitor的 `plugins` 目录
3. 重启TrafficMonitor
4. 在设置中启用"内外网IP显示"插件

## 🎮 使用方法

### 任务栏显示效果
```
192.168.1.100      ← 内网IP
CN 121.12.34.56    ← 外网IP + 国家代码
```

### 工具提示信息
```
内网: 192.168.1.100
外网: CN 121.12.34.56
```

### 右键菜单命令
- **显示内网IP**：切换内网IP显示
- **显示外网IP**：切换外网IP显示  
- **刷新外网IP**：立即强制刷新

## ⚙️ 配置选项

打开TrafficMonitor设置 → 插件 → IP地址显示 → 选项：

- **显示设置**：选择显示内网IP、外网IP或两者
- **网络适配器**：指定首选网络适配器或自动选择
- **刷新间隔**：外网IP标准刷新间隔（默认5分钟）
- **智能缓存**：启用网络变化检测和自适应刷新
- **分隔符**：自定义IP间分隔符

## 🚀 智能特性

### 网络变化检测
- 自动检测内网IP变化（网络切换、VPN连接等）
- 变化时立即获取新的外网IP，然后进入30秒快速验证模式
- 连续6次验证后恢复正常5分钟间隔

### 响应速度对比
| 场景 | 传统固定模式 | 智能模式 |
|------|------------|---------|
| 网络切换 | 最长5分钟 | **立即+30秒** |
| VPN切换 | 最长5分钟 | **立即+30秒** |  
| 稳定使用 | 5分钟固定 | 5-15分钟自适应 |

## 🔧 技术特性

- **安全通信**：使用HTTPS连接获取外网IP（ipinfo.io API）
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
external_refresh_minutes=5     # 标准刷新间隔
separator= | #                 # IP分隔符
enable_smart_cache=1           # 启用智能缓存
fast_refresh_seconds=30        # 快速刷新间隔
max_refresh_minutes=15         # 最大刷新间隔
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

## 📊 系统要求

- **操作系统**：Windows 7/8/10/11 (x64)
- **TrafficMonitor**：支持插件API的版本
- **网络连接**：需要Internet连接获取外网IP和国家信息
- **运行时库**：Visual C++ 2022 Redistributable (x64)

---

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
- `src/plugin_options.h`：用户配置选项定义  
- `src/plugin.h/.cpp`：插件主体实现
- `src/options_dialog.h/.cpp`：设置对话框

### 技术实现
- **内网IP**：使用GetAdaptersAddresses API，支持优先级选择
- **外网IP**：ipinfo.io HTTPS API，JSON解析，支持国家代码
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
