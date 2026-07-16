# README 出口检测说明更新设计

## 目标

更新中文 `README.md`，准确记录已经实现的常用站点出口检测功能、启用方式、输出格式、配置键和代码位置，然后将本地 `master` 同步到 GitHub。

## 更新范围

- 在“主要功能”增加一条可选的常用站点出口检测说明，注明默认关闭。
- 新增“常用站点出口检测”章节，说明支持 Google、YouTube、OpenAI、Claude、Netflix，不包含 GitHub。
- 展示固定列宽 Tooltip 示例：

```text
──── 出口检测 ────
Google  ->  US GGL
YouTube ->  JP GGL
OpenAI  ->  US CF
Claude  ->  US CF
Netflix ->  JP NFLX
```

- 解释两列结果：两位国家/地区代码与网络标识（GGL、CF、NFLX）；等待或失败时显示占位值。
- 在配置示例加入 `enable_exit_detection=0`，说明默认关闭。
- 在开发者项目结构加入 `src/exit_detection.h/.cpp`。
- 不改写与本功能无关的现有 README 内容，不虚构 GitHub 检测支持。

## 验证与同步

- 检查 README 中五个站点、配置键、代码路径和示例格式是否与代码一致。
- 运行现有出口检测配置验证脚本并检查 Markdown 差异。
- 提交 README 更新，确认本地分支相对远端仅包含预期提交后，推送 `master` 到 `origin`。
