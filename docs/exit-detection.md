# 出口检测

出口检测用于在悬浮提示框底部显示常见网站的出口国家：

```text
──────── 出口检测 ────────
Google   → 🇭🇰 Hong Kong
YouTube  → 🇯🇵 Japan
OpenAI   → 🇺🇸 United States
Claude   → 🇸🇬 Singapore
GitHub   → 🇭🇰 Hong Kong
Netflix  → 🇯🇵 Japan
```

- 默认关闭，需要在插件设置中勾选“启用出口检测”。
- 设置会保存到 `tm_ip_plugin.ini` 的 `[ip] enable_exit_detection`，重启后保持用户选择。
- 开启后首次悬浮提示会显示 `Detecting`，检测完成后显示国旗和英文国家名。
- 单个网站检测失败时只显示该网站为 `Unknown`，不会影响其他网站。
- 检测结果缓存 10 分钟；点击“刷新外网IP”或代理窗口变化会强制触发下一次出口检测刷新。
