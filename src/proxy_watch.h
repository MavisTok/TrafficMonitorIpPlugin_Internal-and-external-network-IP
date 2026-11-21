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
 *          通过StopWatching()显式停止；启动失败后允许重试。
 */
void StartWatching();

/**
 * @brief 停止监控、注销钩子并等待后台线程退出（幂等）
 * @details 在宿主正常生命周期中调用，不得从DllMain中调用。
 */
void StopWatching();

/**
 * @brief 合并代理软件窗口事件，静默2秒后消费，刷新至少间隔5秒
 * @return true表示有待处理事件且已达到去抖和刷新间隔
 */
bool ConsumeTriggerFlag();

} // namespace proxywatch
