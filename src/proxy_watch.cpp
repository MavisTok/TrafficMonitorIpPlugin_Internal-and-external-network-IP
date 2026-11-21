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
#include <mutex>
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

struct WatcherState {
    std::mutex lifecycle_mutex;
    std::thread worker;
    HANDLE stop_event = nullptr;
    std::atomic<bool> running{false};

    std::mutex trigger_mutex;
    bool pending = false;
    ULONGLONG last_event_tick = 0;
    ULONGLONG last_trigger_tick = 0;
    bool has_triggered = false;
};

WatcherState& SharedState() {
    // StopWatching owns thread/handle cleanup. Keep the synchronization objects
    // alive until process teardown regardless of static destruction order.
    static WatcherState* state = new WatcherState;
    return *state;
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

    WatcherState& state = SharedState();
    std::lock_guard<std::mutex> lock(state.trigger_mutex);
    state.pending = true;
    state.last_event_tick = GetTickCount64();
}

void WatcherThreadProc(HANDLE stop_event) {
    // WINEVENT_OUTOFCONTEXT：事件通过消息投递到本线程，无需注入目标进程
    // WINEVENT_SKIPOWNPROCESS：跳过宿主进程（TrafficMonitor.exe）自身事件
    const DWORD flags = WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS;

    HWINEVENTHOOK hForeground = SetWinEventHook(
        EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, nullptr, WinEventProc, 0, 0, flags);
    HWINEVENTHOOK hMinimize = SetWinEventHook(
        EVENT_SYSTEM_MINIMIZESTART, EVENT_SYSTEM_MINIMIZEEND, nullptr, WinEventProc, 0, 0, flags);
    HWINEVENTHOOK hShowHide = SetWinEventHook(
        EVENT_OBJECT_SHOW, EVENT_OBJECT_HIDE, nullptr, WinEventProc, 0, 0, flags);

    if (hForeground || hMinimize || hShowHide) {
        bool quit = false;
        while (!quit) {
            // The event can wake this thread even before its message queue has
            // been created, unlike PostThreadMessage(WM_QUIT).
            const DWORD wait = MsgWaitForMultipleObjects(
                1, &stop_event, FALSE, INFINITE, QS_ALLINPUT);
            if (wait != WAIT_OBJECT_0 + 1) break;

            MSG msg{};
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                if (msg.message == WM_QUIT ||
                    WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0) {
                    quit = true;
                    break;
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    if (hForeground) UnhookWinEvent(hForeground);
    if (hMinimize) UnhookWinEvent(hMinimize);
    if (hShowHide) UnhookWinEvent(hShowHide);
    SharedState().running.store(false, std::memory_order_release);
}

} // namespace

void StartWatching() {
    WatcherState& state = SharedState();
    std::lock_guard<std::mutex> lock(state.lifecycle_mutex);
    if (state.running.load(std::memory_order_acquire)) return;

    // A previous worker may have stopped after hook registration failed.
    if (state.worker.joinable()) state.worker.join();
    if (state.stop_event) {
        CloseHandle(state.stop_event);
        state.stop_event = nullptr;
    }

    state.stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!state.stop_event) return;

    state.running.store(true, std::memory_order_release);
    try {
        state.worker = std::thread(WatcherThreadProc, state.stop_event);
    } catch (...) {
        state.running.store(false, std::memory_order_release);
        CloseHandle(state.stop_event);
        state.stop_event = nullptr;
    }
}

void StopWatching() {
    WatcherState& state = SharedState();
    std::lock_guard<std::mutex> lock(state.lifecycle_mutex);
    if (state.stop_event) SetEvent(state.stop_event);
    if (state.worker.joinable()) state.worker.join();
    if (state.stop_event) {
        CloseHandle(state.stop_event);
        state.stop_event = nullptr;
    }
    state.running.store(false, std::memory_order_release);

    std::lock_guard<std::mutex> trigger_lock(state.trigger_mutex);
    state.pending = false;
    state.has_triggered = false;
}

bool ConsumeTriggerFlag() {
    WatcherState& state = SharedState();
    std::lock_guard<std::mutex> lock(state.trigger_mutex);
    if (!state.pending) return false;

    const ULONGLONG now = GetTickCount64();
    constexpr ULONGLONG kDebounceMilliseconds = 2000;
    constexpr ULONGLONG kMinimumRefreshMilliseconds = 5000;
    if (now - state.last_event_tick < kDebounceMilliseconds ||
        (state.has_triggered &&
         now - state.last_trigger_tick < kMinimumRefreshMilliseconds)) {
        // Retain the pending event so the final event in a burst is not lost.
        return false;
    }

    state.pending = false;
    state.last_trigger_tick = now;
    state.has_triggered = true;
    return true;
}

} // namespace proxywatch
