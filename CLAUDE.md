# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 构建系统

这是一个Visual Studio 2022的C++项目，输出为TrafficMonitor插件DLL。

### 构建命令
```bash
# 构建Debug版本
msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64

# 构建Release版本  
msbuild TrafficMonitorIpPlugin.sln /p:Configuration=Release /p:Platform=x64

# 或使用完整路径（如果msbuild不在PATH中）
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" TrafficMonitorIpPlugin.sln /p:Configuration=Debug /p:Platform=x64
```

### 输出位置
- Debug版本：`bin\x64\Debug\TrafficMonitorIpPlugin.dll`
- Release版本：`bin\x64\Release\TrafficMonitorIpPlugin.dll`

## 代码架构

### 核心组件

#### 1. 插件接口层
- `PluginInterface.h`: TrafficMonitor官方插件接口定义
- `plugin.h/.cpp`: 主插件类`TMIpPlugin`，实现`ITMPlugin`接口

#### 2. IP获取层 (`ip_utils.h/.cpp`)
- `GetInternalIPv4()`: 内网IP获取，支持网络适配器优先级
- `GetExternalIPv4WithCountry()`: 外网IP获取，包含国家和供应商信息
- `IpWithCountry`: IP数据结构，包含ip、country、as_name字段
- 智能缓存机制：基于网络变化检测的自适应刷新策略

#### 3. 显示逻辑层 (`ip_item.h`)
- `IpTextProvider`: IP文本格式化器
- `IpPluginItem`: 插件显示项目，处理垂直布局和自定义绘制

#### 4. 配置管理层
- `plugin_options.h`: 配置选项结构`PluginOptions`
- `options_dialog.h/.cpp`: 设置对话框UI
- INI文件存储：`%TrafficMonitor%\plugins\config\tm_ip_plugin.ini`

### 关键设计模式

#### 垂直布局实现
插件使用自定义绘制实现垂直布局，通过两个独立字段：
- `internal_ip_`: 上层显示内容（内网IP或供应商名称）
- `external_ip_`: 下层显示内容（外网IP）

#### 供应商显示逻辑
当内网显示关闭时：
1. 获取外网IP的`org`字段（格式：`AS906 DMIT Cloud Services`）
2. 通过`GetCompanyName()`处理：去除AS前缀、公司后缀，提取主要名称
3. 在`internal_ip_`位置显示处理后的公司名称
4. 在`external_ip_`位置显示完整外网IP信息

#### 智能缓存策略
- **HYBRID模式**（推荐）：网络变化时30秒快速刷新，稳定后5-15分钟自适应
- **FIXED模式**：固定间隔刷新
- 基于内网IP变化检测触发缓存刷新

## 依赖系统库

编译时需要链接以下Windows系统库：
- `Iphlpapi.lib`: IP Helper API（获取网络适配器信息）
- `Ws2_32.lib`: Winsock 2.0（网络套接字）  
- `Winhttp.lib`: WinHTTP（HTTPS通信）
- `Shlwapi.lib`: Shell实用程序（路径操作）

## 关键文件说明

### 核心实现文件
- `src/plugin.cpp`: 插件主入口，配置管理，TrafficMonitor接口实现
- `src/ip_utils.cpp`: IP获取核心逻辑，网络API调用，JSON解析
- `src/ip_item.h`: 显示文本生成器（头文件实现）

### 外部API集成
- 主服务：`ipinfo.io/json` (获取IP、country、org字段)
- 备用服务：`httpbin.org/ip` (仅IP地址)
- 使用WinHTTP进行HTTPS通信，包含完整的错误处理

## 开发注意事项

### 字符编码
- 源代码：UTF-8 with BOM
- 字符串：使用`std::wstring`（Unicode）
- API响应：UTF-8，需要转换为宽字符

### 线程安全
- 外网IP获取使用独立线程
- 缓存操作有完整的互斥锁保护
- TrafficMonitor的UI回调在主线程中执行

### 配置文件格式
INI格式，关键配置项：
```ini
[ip]
show_internal=1
show_external=1
external_refresh_minutes=5
enable_smart_cache=1
separator= | 
```