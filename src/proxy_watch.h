/**
 * @file proxy_watch.h
 * @brief 代理软件窗口打开/关闭监控模块接口声明
 * @details 通过全局WinEvent钩子监听常见代理软件（Clash、V2rayN等）的窗口
 *          前台切换、显示/隐藏、最小化/还原事件，命中时置位刷新标志，
 *          供DataRequired()下次调用时消费，触发一次外网IP强制刷新。
 * @author Lynn
 * @date 2026
 */

#pragma once

namespace proxywatch {

/**
 * @brief 启动代理软件窗口监控（幂等，重复调用无副作用）
 * @details 在独立的后台线程中注册WinEvent钩子并运行消息循环，
 *          线程随进程退出自然回收，不提供显式停止接口。
 */
void StartWatching();

/**
 * @brief 取出并清零"需要刷新"标志
 * @return true表示自上次调用以来监测到一次代理软件窗口打开或关闭
 */
bool ConsumeTriggerFlag();

} // namespace proxywatch
