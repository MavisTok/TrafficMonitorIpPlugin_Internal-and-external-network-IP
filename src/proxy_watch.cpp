/**
 * @file proxy_watch.cpp
 * @brief 代理软件窗口打开/关闭监控模块实现
 * @details 使用全局WinEvent钩子（WINEVENT_OUTOFCONTEXT，无需注入目标进程）
 *          监听前台窗口切换、窗口显示/隐藏、最小化/还原三类事件，
 *          在独立线程中运行消息循环。命中已知代理软件进程名时
 *          置位原子标志，供插件主循环下次DataRequired()时消费。
 * @author Lynn
 * @date 2026
 */

#include "proxy_watch.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <shlwapi.h>   // PathFindFileNameW

#include <atomic>
#include <thread>
#include <cstddef>

#pragma comment(lib, "Shlwapi.lib")

namespace proxywatch {

namespace {

// 已知代理软件可执行文件名（不含路径，大小写不敏感）。
// 想监控其他软件时在此追加后重新编译即可。
const wchar_t* const kWatchedProcessNames[] = {
    L"clash.exe",
    L"clash-verge.exe",
    L"Clash Verge.exe",
    L"clash-verge-service.exe",
    L"mihomo.exe",
    L"mihomo-party.exe",
    L"Clash Party.exe",   // Mihomo Party 改名后的可执行文件名
    L"FlClash.exe",
    L"v2rayN.exe",
    L"v2rayNG.exe",
    L"Netch.exe",
    L"Qv2ray.exe",
    L"nekoray.exe",
    L"NekoBox.exe",
    L"sagernet.exe",
    L"Shadowsocks.exe",
    L"ss-win.exe",
    L"Proxifier.exe",
    L"ClashX.exe",
};

std::atomic<bool>& TriggerFlag() {
    static std::atomic<bool> flag{false};
    return flag;
}

bool IsWatchedProcess(DWORD pid) {
    if (pid == 0) return false;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return false;

    wchar_t path[MAX_PATH]{};
    DWORD size = static_cast<DWORD>(std::size(path));
    bool ok = QueryFullProcessImageNameW(hProcess, 0, path, &size) != 0;
    CloseHandle(hProcess);
    if (!ok) return false;

    const wchar_t* filename = PathFindFileNameW(path);
    if (!filename) return false;

    for (const wchar_t* watched : kWatchedProcessNames) {
        if (_wcsicmp(filename, watched) == 0) return true;
    }
    return false;
}

void CALLBACK WinEventProc(HWINEVENTHOOK /*hWinEventHook*/, DWORD /*event*/, HWND hwnd,
                            LONG idObject, LONG idChild, DWORD /*idEventThread*/,
                            DWORD /*dwmsEventTime*/) {
    // 只关心窗口本身的事件，过滤光标/菜单等子对象事件
    if (idObject != OBJID_WINDOW || idChild != CHILDID_SELF) return;
    if (!hwnd) return;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (!IsWatchedProcess(pid)) return;

    TriggerFlag().store(true, std::memory_order_relaxed);
}

void WatcherThreadProc() {
    // WINEVENT_OUTOFCONTEXT：事件通过消息投递到本线程，无需注入目标进程
    // WINEVENT_SKIPOWNPROCESS：跳过宿主进程（TrafficMonitor.exe）自身事件
    const DWORD flags = WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS;

    HWINEVENTHOOK hForeground = SetWinEventHook(
        EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, nullptr, WinEventProc, 0, 0, flags);
    HWINEVENTHOOK hMinimize = SetWinEventHook(
        EVENT_SYSTEM_MINIMIZESTART, EVENT_SYSTEM_MINIMIZEEND, nullptr, WinEventProc, 0, 0, flags);
    HWINEVENTHOOK hShowHide = SetWinEventHook(
        EVENT_OBJECT_SHOW, EVENT_OBJECT_HIDE, nullptr, WinEventProc, 0, 0, flags);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (hForeground) UnhookWinEvent(hForeground);
    if (hMinimize) UnhookWinEvent(hMinimize);
    if (hShowHide) UnhookWinEvent(hShowHide);
}

} // namespace

void StartWatching() {
    static std::atomic<bool> started{false};
    bool expected = false;
    if (!started.compare_exchange_strong(expected, true)) return;  // 已启动，幂等跳过

    std::thread(WatcherThreadProc).detach();
}

bool ConsumeTriggerFlag() {
    return TriggerFlag().exchange(false, std::memory_order_relaxed);
}

} // namespace proxywatch
