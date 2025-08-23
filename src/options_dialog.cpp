#pragma execution_character_set("utf-8")

#include "options_dialog.h"
#include <string>
#include <vector>
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>

extern HINSTANCE g_hInst; // from dllmain

#include "../res/resource.h"

#pragma comment(lib, "Iphlpapi.lib")

static void SetCheck(HWND hDlg, int id, bool v) { CheckDlgButton(hDlg, id, v ? BST_CHECKED : BST_UNCHECKED); }
static bool GetCheck(HWND hDlg, int id) { return IsDlgButtonChecked(hDlg, id) == BST_CHECKED; }

// Structure to hold adapter information
struct AdapterInfo {
    std::wstring friendlyName;
    std::wstring adapterName;
    std::wstring displayName;
    bool isUp;
};

// Get list of network adapters
static std::vector<AdapterInfo> GetNetworkAdapters() {
    std::vector<AdapterInfo> adapters;
    
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG family = AF_INET; // IPv4 only
    ULONG size = 15 * 1024;
    
    std::vector<BYTE> buffer(size);
    IP_ADAPTER_ADDRESSES* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    
    ULONG ret = GetAdaptersAddresses(family, flags, nullptr, addrs, &size);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size);
        addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        ret = GetAdaptersAddresses(family, flags, nullptr, addrs, &size);
    }
    
    if (ret == NO_ERROR) {
        for (auto a = addrs; a; a = a->Next) {
            if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue; // Skip loopback
            
            AdapterInfo info;
            info.friendlyName = a->FriendlyName ? a->FriendlyName : L"";
            
            // Convert AdapterName from multibyte to wide string
            if (a->AdapterName) {
                int len = MultiByteToWideChar(CP_UTF8, 0, a->AdapterName, -1, nullptr, 0);
                if (len > 0) {
                    info.adapterName.resize(len - 1);
                    MultiByteToWideChar(CP_UTF8, 0, a->AdapterName, -1, const_cast<wchar_t*>(info.adapterName.data()), len);
                }
            }
            
            info.isUp = (a->OperStatus == IfOperStatusUp);
            
            // Create display name: "Friendly Name (Status)"
            info.displayName = info.friendlyName;
            if (!info.displayName.empty()) {
                info.displayName += info.isUp ? L" (已连接)" : L" (已断开)";
            } else if (!info.adapterName.empty()) {
                info.displayName = info.adapterName;
                info.displayName += info.isUp ? L" (已连接)" : L" (已断开)";
            }
            
            if (!info.displayName.empty()) {
                adapters.push_back(info);
            }
        }
    }
    
    return adapters;
}

static void SetEdit(HWND hDlg, int id, const std::wstring& s) { SetDlgItemTextW(hDlg, id, s.c_str()); }
static std::wstring GetEdit(HWND hDlg, int id) {
    wchar_t buf[512]{};
    GetDlgItemTextW(hDlg, id, buf, (int)std::size(buf));
    return buf;
}

// Fill combo box with adapter list and select current one
static void SetupAdapterCombo(HWND hDlg, int id, const std::wstring& currentAdapter) {
    HWND hCombo = GetDlgItem(hDlg, id);
    if (!hCombo) return;
    
    // Clear existing items
    SendMessage(hCombo, CB_RESETCONTENT, 0, 0);
    
    // Add "自动选择" as first item
    SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)L"自动选择");
    SendMessage(hCombo, CB_SETITEMDATA, 0, (LPARAM)0); // Data = 0 for auto
    
    // Get adapters and add them
    auto adapters = GetNetworkAdapters();
    int selectedIndex = 0; // Default to "自动选择"
    
    for (size_t i = 0; i < adapters.size(); ++i) {
        int index = (int)SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)adapters[i].displayName.c_str());
        if (index != CB_ERR) {
            // Store adapter info as item data (index + 1 to distinguish from auto=0)
            SendMessage(hCombo, CB_SETITEMDATA, index, (LPARAM)(i + 1));
            
            // Check if this is the currently selected adapter
            if (!currentAdapter.empty() && 
                (currentAdapter == adapters[i].friendlyName || 
                 currentAdapter == adapters[i].adapterName)) {
                selectedIndex = index;
            }
        }
    }
    
    SendMessage(hCombo, CB_SETCURSEL, selectedIndex, 0);
}

// Get selected adapter name from combo box
static std::wstring GetSelectedAdapter(HWND hDlg, int id) {
    HWND hCombo = GetDlgItem(hDlg, id);
    if (!hCombo) return L"";
    
    int selection = (int)SendMessage(hCombo, CB_GETCURSEL, 0, 0);
    if (selection == CB_ERR) return L"";
    
    LPARAM data = SendMessage(hCombo, CB_GETITEMDATA, selection, 0);
    if (data == 0) {
        // Auto selection
        return L"";
    }
    
    // Get the adapter info
    auto adapters = GetNetworkAdapters();
    size_t adapterIndex = (size_t)data - 1;
    if (adapterIndex < adapters.size()) {
        return adapters[adapterIndex].friendlyName;
    }
    
    return L"";
}

static INT_PTR CALLBACK DlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    static PluginOptions* s_opts = nullptr;
    switch (msg) {
    case WM_INITDIALOG: {
        s_opts = reinterpret_cast<PluginOptions*>(lParam);
        if (!s_opts) return FALSE;
        SetCheck(hDlg, IDC_CHECK_INTERNAL, s_opts->show_internal);
        SetCheck(hDlg, IDC_CHECK_EXTERNAL, s_opts->show_external);
        SetupAdapterCombo(hDlg, IDC_EDIT_ADAPTER, s_opts->preferred_adapter);
        SetEdit(hDlg, IDC_EDIT_REFRESH, std::to_wstring(s_opts->external_refresh.count()));
        SetEdit(hDlg, IDC_EDIT_SEPARATOR, s_opts->separator);
        return TRUE;
    }
    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case IDOK: {
            if (!s_opts) { EndDialog(hDlg, IDCANCEL); return TRUE; }
            PluginOptions new_opts = *s_opts;
            new_opts.show_internal = GetCheck(hDlg, IDC_CHECK_INTERNAL);
            new_opts.show_external = GetCheck(hDlg, IDC_CHECK_EXTERNAL);
            new_opts.preferred_adapter = GetSelectedAdapter(hDlg, IDC_EDIT_ADAPTER);
            {
                std::wstring s = GetEdit(hDlg, IDC_EDIT_REFRESH);
                int m = 5;
                try { m = std::stoi(s); } catch (...) {}
                if (m <= 0) m = 5;
                if (m > 1440) m = 1440;
                new_opts.external_refresh = std::chrono::minutes(m);
            }
            new_opts.separator = GetEdit(hDlg, IDC_EDIT_SEPARATOR);
            if (new_opts.separator.empty()) new_opts.separator = L" | ";

            bool changed = (new_opts.show_internal != s_opts->show_internal)
                || (new_opts.show_external != s_opts->show_external)
                || (new_opts.preferred_adapter != s_opts->preferred_adapter)
                || (new_opts.external_refresh != s_opts->external_refresh)
                || (new_opts.separator != s_opts->separator);
            *s_opts = new_opts;
            EndDialog(hDlg, changed ? IDOK : IDCANCEL);
            return TRUE;
        }
        case IDCANCEL:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        default:
            break;
        }
        break;
    }
    }
    return FALSE;
}

bool ShowIpOptionsDialog(HWND hParent, PluginOptions& options) {
    INT_PTR ret = DialogBoxParamW(g_hInst, MAKEINTRESOURCEW(IDD_OPTIONS), hParent, DlgProc, (LPARAM)&options);
    return (ret == IDOK);
}

