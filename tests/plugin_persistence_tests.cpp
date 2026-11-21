// Exercise the real plugin callbacks and Windows INI APIs. Replace only UI and
// network boundaries; no test uses the factory or starts a background thread.
#include <windows.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {
int message_count = 0;
std::wstring last_message;
int WINAPI CaptureMessageBoxW(HWND, LPCWSTR text, LPCWSTR, UINT) {
    ++message_count;
    last_message = text ? text : L"";
    return IDOK;
}
}

#define MessageBoxW CaptureMessageBoxW
#include "../src/plugin.cpp"
#undef MessageBoxW

HINSTANCE g_hInst = nullptr;

namespace {
int failures = 0;
bool apply_dialog_options = false;
PluginOptions desired_options;
PluginOptions observed_options;

void Check(bool condition, const char* expression, int line) {
    if (!condition) {
        std::cerr << "Persistence check failed at line " << line << ": " << expression << '\n';
        ++failures;
    }
}
}
#define CHECK(expression) Check(static_cast<bool>(expression), #expression, __LINE__)

bool ShowIpOptionsDialog(HWND, PluginOptions& options) {
    observed_options = options;
    if (!apply_dialog_options) return false;
    apply_dialog_options = false;
    options = desired_options;
    return true;
}

namespace iputils {
std::wstring GetInternalIPv4(const std::wstring&) { return L"192.0.2.1"; }
IpWithCountry GetExternalIPv4WithCountry(const ExternalIpOptions&, bool) { return {}; }
void ShutdownExternalIpWorker() {}
}
namespace claude_risk {
ClaudeRiskInfo GetClaudeRiskSnapshot() { return {}; }
void RequestClaudeRiskRefreshAsync(const std::wstring&, const std::wstring&, const std::wstring&, bool) {}
void ShutdownRefreshWorker() {}
}
namespace exit_detection {
Snapshot GetSnapshot() { return {}; }
std::wstring FormatTooltip(const Snapshot&) { return {}; }
void RequestRefreshAsync(bool) {}
void ShutdownRefreshWorker() {}
}
namespace proxywatch {
void StartWatching() {}
void StopWatching() {}
bool ConsumeTriggerFlag() { return false; }
}

namespace {

class Host final : public ITrafficMonitor {
public:
    explicit Host(std::wstring directory) : directory_(std::move(directory)) {}
    int GetAPIVersion() override { return 1; }
    const wchar_t* GetVersion() override { return L"test"; }
    double GetMonitorValue(MonitorItem) override { return 0; }
    const wchar_t* GetMonitorValueString(MonitorItem, int) override { return L""; }
    void ShowNotifyMessage(const wchar_t*) override {}
    unsigned short GetLanguageId() const override { return 0x0409; }
    const wchar_t* GetPluginConfigDir() const override { return directory_.c_str(); }
    int GetDPI(DPIType) const override { return 96; }
    unsigned int GetThemeColor() const override { return 0; }
private:
    std::wstring directory_;
};

PluginOptions OptionsForMask(unsigned mask) {
    PluginOptions options;
    options.show_internal = (mask & 1u) != 0;
    options.show_external = (mask & 2u) != 0;
    options.enable_claude_risk_check = (mask & 4u) != 0;
    options.enable_exit_detection = (mask & 8u) != 0;
    options.enable_smart_cache = false;
    options.preferred_adapter = L"persist-test-adapter";
    options.separator = L"::";
    options.external_refresh = std::chrono::minutes(7);
    options.fast_refresh = std::chrono::seconds(17);
    options.max_refresh = std::chrono::minutes(11);
    return options;
}

void CheckOptions(TMIpPlugin& plugin, const PluginOptions& expected) {
    apply_dialog_options = false;
    CHECK(plugin.ShowOptionsDialog(nullptr) == ITMPlugin::OR_OPTION_UNCHANGED);
    CHECK(observed_options.show_internal == expected.show_internal);
    CHECK(observed_options.show_external == expected.show_external);
    CHECK(observed_options.enable_claude_risk_check == expected.enable_claude_risk_check);
    CHECK(observed_options.enable_exit_detection == expected.enable_exit_detection);
    CHECK(observed_options.enable_smart_cache == expected.enable_smart_cache);
    CHECK(observed_options.preferred_adapter == expected.preferred_adapter);
    CHECK(observed_options.separator == expected.separator);
    CHECK(observed_options.external_refresh == expected.external_refresh);
    CHECK(observed_options.fast_refresh == expected.fast_refresh);
    CHECK(observed_options.max_refresh == expected.max_refresh);
    CHECK(plugin.IsCommandChecked(0) == (expected.show_internal ? 1 : 0));
    CHECK(plugin.IsCommandChecked(1) == (expected.show_external ? 1 : 0));
}

void CheckDisk(const std::wstring& directory, unsigned mask) {
    const std::wstring ini = directory + L"\\tm_ip_plugin.ini";
    CHECK(GetFileAttributesW(ini.c_str()) != INVALID_FILE_ATTRIBUTES);
    const wchar_t* keys[] = {L"show_internal", L"show_external",
                             L"enable_claude_risk_check", L"enable_exit_detection"};
    for (unsigned i = 0; i < 4; ++i) {
        CHECK(GetPrivateProfileIntW(L"ip", keys[i], 99, ini.c_str()) == ((mask >> i) & 1u));
    }
}

void Initialize(TMIpPlugin& plugin, Host& host, const std::wstring& directory,
                const std::wstring& mode) {
    if (mode.find(L"legacy") == 0) plugin.OnExtenedInfo(ITMPlugin::EI_CONFIG_DIR, directory.c_str());
    else plugin.OnInitialize(&host);
    // Invalid or unrelated notices must not erase a known configuration path.
    plugin.OnExtenedInfo(ITMPlugin::EI_CONFIG_DIR, nullptr);
    plugin.OnExtenedInfo(ITMPlugin::EI_CONFIG_DIR, L"");
    plugin.OnExtenedInfo(ITMPlugin::EI_LABEL_TEXT_COLOR, L"ignored");
}

int RunChild(const std::wstring& action, const std::wstring& directory,
             unsigned mask, const std::wstring& mode) {
    // Relative cases deliberately use a sibling of the executable so they work
    // even when the system temporary directory is on another drive.
    const std::wstring supplied_directory = mode.find(L"relative") != std::wstring::npos
        ? std::filesystem::path(directory).filename().wstring() : directory;
    Host host(supplied_directory);
    TMIpPlugin plugin;
    Initialize(plugin, host, supplied_directory, mode);
    if (action == L"--write") {
        desired_options = OptionsForMask(mask);
        apply_dialog_options = true;
        CHECK(plugin.ShowOptionsDialog(nullptr) == ITMPlugin::OR_OPTION_CHANGED);
        CHECK(message_count == 0);
        CheckDisk(directory, mask);
    } else if (action == L"--read") {
        CheckOptions(plugin, OptionsForMask(mask));
        CheckDisk(directory, mask);
    } else if (action == L"--commands") {
        if (plugin.IsCommandChecked(0) != ((mask & 1u) ? 1 : 0))
            plugin.OnPluginCommand(0, nullptr, nullptr);
        if (plugin.IsCommandChecked(1) != ((mask & 2u) ? 1 : 0))
            plugin.OnPluginCommand(1, nullptr, nullptr);
        CheckOptions(plugin, OptionsForMask(mask));
        CheckDisk(directory, mask);
        CHECK(message_count == 0);
    } else if (action == L"--callbacks") {
        CheckOptions(plugin, OptionsForMask(mask));
        Host empty_host(L"");
        plugin.OnInitialize(&empty_host);
        plugin.OnInitialize(nullptr);
        CheckOptions(plugin, OptionsForMask(mask));
        plugin.OnInitialize(&host);
        plugin.OnExtenedInfo(ITMPlugin::EI_CONFIG_DIR, directory.c_str());
        CheckOptions(plugin, OptionsForMask(mask));
        plugin.OnPluginCommand(0, nullptr, nullptr);
        CheckDisk(directory, mask ^ 1u);
        plugin.OnPluginCommand(1, nullptr, nullptr);
        CheckDisk(directory, mask ^ 3u);
        CHECK(message_count == 0);
    } else if (action == L"--readonly") {
        const std::wstring ini = directory + L"\\tm_ip_plugin.ini";
        CHECK(SetFileAttributesW(ini.c_str(), FILE_ATTRIBUTE_READONLY));
        desired_options = OptionsForMask(mask ^ 15u);
        apply_dialog_options = true;
        plugin.ShowOptionsDialog(nullptr);
        CHECK(message_count > 0);
        CHECK(last_message.find(directory) != std::wstring::npos);
        const int previous_messages = message_count;
        plugin.OnPluginCommand(0, nullptr, nullptr);
        CHECK(message_count > previous_messages);
        CHECK(SetFileAttributesW(ini.c_str(), FILE_ATTRIBUTE_NORMAL));
        WritePrivateProfileStringW(nullptr, nullptr, nullptr, ini.c_str());
        CheckDisk(directory, mask);
    } else {
        CHECK(false);
    }
    return failures == 0 ? 0 : 1;
}

std::wstring QuoteArgument(const std::wstring& argument) {
    std::wstring result = L"\"";
    std::size_t slashes = 0;
    for (wchar_t ch : argument) {
        if (ch == L'\\') { ++slashes; continue; }
        if (ch == L'\"') result.append(slashes * 2 + 1, L'\\');
        else result.append(slashes, L'\\');
        slashes = 0;
        result += ch;
    }
    result.append(slashes * 2, L'\\');
    return result + L'\"';
}

bool Spawn(const std::wstring& executable, const std::wstring& action,
           const std::wstring& directory, unsigned mask, const std::wstring& mode,
           const std::wstring& working_directory) {
    std::wstring command = QuoteArgument(executable) + L" " + action + L" " +
        QuoteArgument(directory) + L" " + std::to_wstring(mask) + L" " + mode;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(executable.c_str(), &command[0], nullptr, nullptr, FALSE, 0,
                        nullptr, working_directory.c_str(), &startup, &process)) return false;
    CloseHandle(process.hThread);
    const DWORD wait = WaitForSingleObject(process.hProcess, 30000);
    DWORD exit_code = 1;
    if (wait == WAIT_OBJECT_0) GetExitCodeProcess(process.hProcess, &exit_code);
    else TerminateProcess(process.hProcess, 1);
    CloseHandle(process.hProcess);
    if (exit_code != 0) {
        std::wcerr << action << L" failed: mask=" << mask << L", mode=" << mode << L'\n';
    }
    return wait == WAIT_OBJECT_0 && exit_code == 0;
}

struct TemporaryDirectory {
    std::wstring path;
    TemporaryDirectory() {
        wchar_t parent[MAX_PATH]{};
        const DWORD count = GetTempPathW(MAX_PATH, parent);
        if (count == 0 || count >= MAX_PATH) return;
        wchar_t unique[MAX_PATH]{};
        if (!GetTempFileNameW(parent, L"tmi", 0, unique)) return;
        if (!DeleteFileW(unique)) return;
        if (CreateDirectoryW(unique, nullptr)) path = unique;
    }
    ~TemporaryDirectory() {
        if (path.empty()) return;
        std::error_code error;
        std::filesystem::remove_all(std::filesystem::path(path), error);
    }
};

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc == 5) return RunChild(argv[1], argv[2], std::stoul(argv[3]), argv[4]);

    TemporaryDirectory root;
    CHECK(!root.path.empty());
    if (root.path.empty()) return 1;
    const std::wstring other_cwd = root.path + L"\\other-working-directory";
    CHECK(CreateDirectoryW(other_cwd.c_str(), nullptr));
    std::wstring executable(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, &executable[0], static_cast<DWORD>(executable.size()));
    CHECK(length != 0 && length < executable.size());
    executable.resize(length);

    for (const wchar_t* mode : {L"legacy", L"modern"}) {
        for (unsigned mask = 0; mask < 16; ++mask) {
            const std::wstring directory = root.path + L"\\" + mode + L"-" + std::to_wstring(mask);
            CHECK(Spawn(executable, L"--write", directory, mask, mode, root.path));
            CHECK(Spawn(executable, L"--read", directory, mask, mode, other_cwd));
        }
        // Independently exercise the right-click command path for every display
        // combination. Seed the opposite display state through the dialog.
        for (unsigned mask = 0; mask < 4; ++mask) {
            const std::wstring directory = root.path + L"\\command-" + mode + L"-" + std::to_wstring(mask);
            CHECK(Spawn(executable, L"--write", directory, mask ^ 3u, mode, root.path));
            CHECK(Spawn(executable, L"--commands", directory, mask, mode, other_cwd));
            CHECK(Spawn(executable, L"--read", directory, mask, mode, root.path));
        }
    }
    const std::wstring extra = root.path + L"\\extra";
    CHECK(Spawn(executable, L"--write", extra, 5, L"legacy", root.path));
    CHECK(Spawn(executable, L"--callbacks", extra, 5, L"legacy", other_cwd));
    CHECK(Spawn(executable, L"--read", extra, 6, L"modern", root.path));
    CHECK(Spawn(executable, L"--readonly", extra, 6, L"modern", other_cwd));
    CHECK(Spawn(executable, L"--read", extra, 6, L"legacy", root.path));
    const auto executable_directory = std::filesystem::path(executable).parent_path();
    for (const wchar_t* mode : {L"legacy-relative", L"modern-relative"}) {
        const std::wstring unique_name = L"persistence-" + std::filesystem::path(root.path).filename().wstring() + L"-" + mode;
        const auto relative_directory = executable_directory / unique_name;
        CHECK(Spawn(executable, L"--write", relative_directory.wstring(), 10, mode, root.path));
        CHECK(Spawn(executable, L"--read", relative_directory.wstring(), 10, mode, other_cwd));
        std::error_code error;
        std::filesystem::remove_all(relative_directory, error);
        CHECK(!error);
    }
    if (failures != 0) return 1;
    std::cout << "Plugin persistence tests passed: 16 switch combinations, both host APIs, "
                 "cold processes, absolute/relative paths, changed CWD, invalid callbacks and read-only INI\n";
    return 0;
}
