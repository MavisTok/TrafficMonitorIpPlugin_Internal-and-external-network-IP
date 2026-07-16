# 出口检测 Tooltip 固定列宽设计

## 目标

在不改变出口检测请求、缓存和结果判定逻辑的前提下，调整 Tooltip 中的出口检测区块，使站点名称、箭头和检测结果形成稳定的三列文本。GitHub 检测不恢复。

目标输出：

```text
──── 出口检测 ────
Google  ->  US GGL
YouTube ->  JP GGL
OpenAI  ->  US CF
Claude  ->  US CF
Netflix ->  JP NFLX
```

## 设计

- 标题固定为 `──── 出口检测 ────`。
- 第一列宽度固定为 7 个字符，即当前最长站点名 `YouTube` 和 `Netflix` 的长度。
- 较短的站点名在右侧补 ASCII 空格到 7 个字符。
- 列分隔固定为 ` ->  `：箭头前一个空格，箭头后两个空格。
- 第三列继续使用现有的 `国家代码 网络代码`、等待值或失败占位值。
- 保留 Google、YouTube、OpenAI、Claude、Netflix 五项及现有顺序，不增加 GitHub。

## 代码范围

- 修改 `src/exit_detection.cpp` 中 Tooltip 标题和行格式化逻辑。
- 修改 `tests/exit_detection_tests.cpp`，用精确字符串断言覆盖五个站点的成功结果和列对齐。
- 不修改网络探测、国家解析、刷新线程、配置项和 UI 开关。

## 验证

遵循测试驱动流程：先写目标输出断言并确认其在旧实现上失败，再修改格式化实现使测试通过。最后运行出口检测测试、配置验证脚本，并重新构建 `Release | x64` 插件 DLL。
