// ipv6_route_monitor_gui.cpp
// 编译 (MSVC):
//   cl /EHsc /std:c++17 /DUNICODE /D_UNICODE ipv6_route_monitor_gui.cpp ^
//      user32.lib gdi32.lib shell32.lib advapi32.lib ws2_32.lib iphlpapi.lib comctl32.lib
//
// 编译 (MinGW-w64):
//   g++ -std=c++17 -municode ipv6_route_monitor_gui.cpp -o ipv6_route_monitor_gui.exe ^
//      -luser32 -lgdi32 -lshell32 -ladvapi32 -lws2_32 -liphlpapi -lcomctl32 -static

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <ipmib.h>
#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>

#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <cstdio>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

// ============================================================
// 控件 ID 与消息定义
// ============================================================
#define IDC_STATIC_STATUS   1001
#define IDC_STATIC_DETAIL   1002
#define IDC_BTN_REFRESH     1003
#define IDC_BTN_TRAY        1004
#define IDC_CHECK_AUTOSTART 1005
#define IDC_LIST_LOG        1006
#define IDC_STATIC_TITLE    1007

#define WM_TRAYICON         (WM_USER + 1)
#define WM_UPDATE_STATUS    (WM_USER + 100)

#define ID_TRAY_ICON        1
#define IDM_TRAY_SHOW       2001
#define IDM_TRAY_REFRESH    2002
#define IDM_TRAY_AUTOSTART  2003
#define IDM_TRAY_EXIT       2004

static const wchar_t* kAppName  = L"IPv6RouteMonitor";
static const wchar_t* kWndClass = L"IPv6RouteMonitorWnd";

// ============================================================
// 全局配置与状态
// ============================================================
static const int CHECK_INTERVAL_SEC   = 10;   // 检测间隔（秒）
static const int REFRESH_THRESHOLD    = 120;  // 剩余时间低于此值触发刷新（秒）
static const int REFRESH_COOLDOWN_SEC = 60;   // 两次刷新之间最小间隔（秒）

struct RouteStatus {
    bool          found         = false;
    NET_IFINDEX   ifIndex       = 0;
    std::wstring  ifName;
    std::wstring  nextHop;
    long long     remaining     = -1;    // -1 = 无限期
    unsigned long validLifetime = 0;
    unsigned long age           = 0;
    std::wstring  message;
};

static HWND                g_hWndMain       = nullptr;
static HINSTANCE           g_hInst          = nullptr;
static NOTIFYICONDATAW     g_nid            = {};
static HFONT               g_hFontTitle     = nullptr;
static HFONT               g_hFontNormal    = nullptr;
static COLORREF            g_statusColor    = RGB(0, 128, 0);
static bool                g_exiting        = false;

static std::atomic<bool>   g_running{true};
static std::atomic<bool>   g_forceCheck{false};
static std::atomic<bool>   g_forceRefresh{false};

static std::mutex          g_statusMutex;
static RouteStatus         g_currentStatus;

static std::mutex          g_logQueueMutex;
static std::vector<std::wstring> g_logQueue;

static std::mutex          g_cvMutex;
static std::condition_variable g_cv;

// ============================================================
// 小工具：从工作线程投递日志到 UI 线程
// ============================================================
static void LogMessage(const std::wstring& msg)
{
    std::lock_guard<std::mutex> lk(g_logQueueMutex);
    g_logQueue.push_back(msg);
}

// ============================================================
// 获取当前 exe 完整路径
// ============================================================
static std::wstring GetExePath()
{
    wchar_t buf[MAX_PATH * 2] = {};
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH * 2);
    return std::wstring(buf, n);
}

// ============================================================
// 检查是否以管理员权限运行
// ============================================================
static bool IsRunningAsAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

// ============================================================
// 开机自启动：读写注册表 HKCU\...\Run
// ============================================================
static bool IsAutoStartEnabled()
{
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    wchar_t value[MAX_PATH * 3] = {};
    DWORD   size = sizeof(value);
    DWORD   type = 0;
    LSTATUS st = RegQueryValueExW(hKey, kAppName, nullptr, &type,
                                  reinterpret_cast<LPBYTE>(value), &size);
    RegCloseKey(hKey);
    if (st != ERROR_SUCCESS) return false;

    // 与当前 exe 路径比对
    std::wstring expected = L"\"" + GetExePath() + L"\" --minimized";
    return _wcsicmp(value, expected.c_str()) == 0;
}

static bool SetAutoStart(bool enable)
{
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return false;

    LSTATUS st = ERROR_SUCCESS;
    if (enable) {
        std::wstring value = L"\"" + GetExePath() + L"\" --minimized";
        st = RegSetValueExW(hKey, kAppName, 0, REG_SZ,
                reinterpret_cast<const BYTE*>(value.c_str()),
                static_cast<DWORD>((value.length() + 1) * sizeof(wchar_t)));
    } else {
        st = RegDeleteValueW(hKey, kAppName);
        if (st == ERROR_FILE_NOT_FOUND) st = ERROR_SUCCESS;
    }
    RegCloseKey(hKey);
    return st == ERROR_SUCCESS;
}

// ============================================================
// 隐藏窗口执行命令行（避免黑框闪一下）
// ============================================================
static bool RunHiddenCmd(const std::wstring& cmd)
{
    std::wstring full = L"cmd.exe /C " + cmd;
    std::vector<wchar_t> buf(full.begin(), full.end());
    buf.push_back(0);

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return false;

    WaitForSingleObject(pi.hProcess, 15000);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return exitCode == 0;
}

// ============================================================
// 路由工具函数
// ============================================================
static std::wstring GetInterfaceNameW(NET_IFINDEX ifIndex)
{
    MIB_IF_ROW2 row = {};
    row.InterfaceIndex = ifIndex;
    if (GetIfEntry2(&row) == NO_ERROR)
        return std::wstring(row.Alias);
    return L"接口 " + std::to_wstring(ifIndex);
}

static std::wstring SockAddrToStringW(const SOCKADDR_INET& addr)
{
    if (addr.si_family != AF_INET6) return L"N/A";
    wchar_t buf[INET6_ADDRSTRLEN] = {};
    if (InetNtopW(AF_INET6, &addr.Ipv6.sin6_addr, buf, INET6_ADDRSTRLEN))
        return std::wstring(buf);
    return L"N/A";
}

// ============================================================
// 核心刷新：临时禁用再启用 Router Discovery，触发 RS
// ============================================================
static bool RefreshRouterDiscovery(NET_IFINDEX ifIndex)
{
    std::wstring idx = std::to_wstring(ifIndex);
    std::wstring disable = L"netsh interface ipv6 set interface " + idx +
                           L" routerdiscovery=disabled";
    std::wstring enable  = L"netsh interface ipv6 set interface " + idx +
                           L" routerdiscovery=enabled";

    if (!RunHiddenCmd(disable)) return false;
    Sleep(500);
    if (!RunHiddenCmd(enable))  return false;
    return true;
}

// ============================================================
// 后台工作线程
// ============================================================
static void WorkerThread()
{
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    auto lastRefreshTime = std::chrono::steady_clock::now() - std::chrono::hours(1);
    NET_IFINDEX lastRefreshIf = 0;

    while (g_running) {
        RouteStatus st;

        PMIB_IPFORWARD_TABLE2 pTable = nullptr;
        DWORD ret = GetIpForwardTable2(AF_INET6, &pTable);

        if (ret != NO_ERROR) {
            st.message = L"查询 IPv6 路由表失败";
        } else {
            for (DWORD i = 0; i < pTable->NumEntries; ++i) {
                const auto& row = pTable->Table[i];
                if (row.DestinationPrefix.PrefixLength != 0) continue;
                if (row.DestinationPrefix.Prefix.si_family != AF_INET6) continue;

                st.found         = true;
                st.ifIndex       = row.InterfaceIndex;
                st.ifName        = GetInterfaceNameW(row.InterfaceIndex);
                st.nextHop       = SockAddrToStringW(row.NextHop);
                st.validLifetime = row.ValidLifetime;
                st.age           = row.Age;

                if (row.ValidLifetime == 0xFFFFFFFF) {
                    st.remaining = -1;
                    st.message   = L"路由生命周期为无限";
                } else {
                    long long rem = static_cast<long long>(row.ValidLifetime)
                                  - static_cast<long long>(row.Age);
                    if (rem < 0) rem = 0;
                    st.remaining = rem;
                    st.message = (rem <= REFRESH_THRESHOLD)
                        ? L"接近老化阈值"
                        : L"运行正常";
                }
                break;
            }
            FreeMibTable(pTable);

            if (!st.found)
                st.message = L"未找到默认路由（可能未接入 IPv6 网络）";
        }

        // ---- 决定是否需要发起刷新 ----
        bool force  = g_forceRefresh.exchange(false);
        bool needRefresh = false;

        if (st.found && st.ifIndex != 0) {
            if (force) {
                needRefresh = true;
            } else if (st.remaining >= 0 && st.remaining <= REFRESH_THRESHOLD) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                    now - lastRefreshTime).count();
                if (st.ifIndex != lastRefreshIf || elapsed >= REFRESH_COOLDOWN_SEC)
                    needRefresh = true;
            }
        }

        if (needRefresh) {
            st.message = force ? L"手动刷新中..." : L"接近老化，发起路由器请求...";
            {
                std::lock_guard<std::mutex> lk(g_statusMutex);
                g_currentStatus = st;
            }
            if (g_hWndMain) PostMessage(g_hWndMain, WM_UPDATE_STATUS, 0, 0);

            if (RefreshRouterDiscovery(st.ifIndex)) {
                lastRefreshTime = std::chrono::steady_clock::now();
                lastRefreshIf   = st.ifIndex;
                st.message = L"已发送路由器请求（RS），等待新 RA";
                LogMessage(L"接口 [" + st.ifName + L"] 已触发 IPv6 路由刷新");
            } else {
                st.message = L"刷新失败（请确认以管理员身份运行）";
                LogMessage(L"接口 [" + st.ifName + L"] 刷新失败，需管理员权限");
            }
        }

        {
            std::lock_guard<std::mutex> lk(g_statusMutex);
            g_currentStatus = st;
        }
        if (g_hWndMain) PostMessage(g_hWndMain, WM_UPDATE_STATUS, 0, 0);

        // ---- 等待下一轮或被手动唤醒 ----
        std::unique_lock<std::mutex> lk(g_cvMutex);
        g_cv.wait_for(lk, std::chrono::seconds(CHECK_INTERVAL_SEC),
            []{ return g_forceCheck.load() || !g_running.load(); });
        g_forceCheck = false;
    }

    WSACleanup();
}

// ============================================================
// 托盘相关
// ============================================================
static void InitTrayIcon(HWND hWnd)
{
    g_nid.cbSize           = sizeof(NOTIFYICONDATAW);
    g_nid.hWnd             = hWnd;
    g_nid.uID              = ID_TRAY_ICON;
    g_nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon            = LoadIcon(nullptr, IDI_APPLICATION);
    wcscpy_s(g_nid.szTip, L"IPv6 路由监控");
    Shell_NotifyIconW(NIM_ADD, &g_nid);
}

static void UpdateTrayTip(const std::wstring& tip)
{
    wcsncpy_s(g_nid.szTip, tip.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

static void RemoveTrayIcon()
{
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
}

// ============================================================
// 日志追加
// ============================================================
static void AppendLog(HWND hWnd, const std::wstring& text)
{
    HWND hLog = GetDlgItem(hWnd, IDC_LIST_LOG);
    if (!hLog) return;

    SYSTEMTIME t;
    GetLocalTime(&t);
    wchar_t buf[1024];
    _snwprintf_s(buf, _TRUNCATE, L"[%02d:%02d:%02d] %s\r\n",
                 t.wHour, t.wMinute, t.wSecond, text.c_str());

    int len = GetWindowTextLengthW(hLog);
    SendMessageW(hLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(hLog, EM_REPLACESEL, FALSE, (LPARAM)buf);
    SendMessageW(hLog, EM_SCROLLCARET, 0, 0);
}

// ============================================================
// 根据状态更新 UI
// ============================================================
static void UpdateUIFromStatus(HWND hWnd)
{
    RouteStatus st;
    {
        std::lock_guard<std::mutex> lk(g_statusMutex);
        st = g_currentStatus;
    }

    // 状态文字与颜色
    std::wstring statusText;
    if (!st.found) {
        statusText    = L"⚠  未找到 IPv6 默认路由";
        g_statusColor = RGB(192, 0, 0);
    } else if (st.remaining < 0) {
        statusText    = L"✓  正常（无限期）";
        g_statusColor = RGB(0, 128, 0);
    } else if (st.remaining <= REFRESH_THRESHOLD) {
        statusText    = L"⚠  路由即将老化";
        g_statusColor = RGB(210, 105, 0);
    } else {
        statusText    = L"✓  正常";
        g_statusColor = RGB(0, 128, 0);
    }

    HWND hStatus = GetDlgItem(hWnd, IDC_STATIC_STATUS);
    SetWindowTextW(hStatus, statusText.c_str());
    InvalidateRect(hStatus, nullptr, TRUE);

    // 详细信息
    std::wstring detail;
    wchar_t buf[256];
    if (st.found) {
        detail += L"接口:      " + st.ifName + L"\r\n";
        detail += L"下一跳:    " + st.nextHop + L"\r\n";
        if (st.remaining < 0) {
            detail += L"剩余时间:  无限\r\n";
        } else {
            _snwprintf_s(buf, _TRUNCATE, L"剩余时间:  %lld 秒  (%.1f 分钟)\r\n",
                         st.remaining, st.remaining / 60.0);
            detail += buf;
            _snwprintf_s(buf, _TRUNCATE,
                         L"有效期:    %lu 秒   已存活: %lu 秒\r\n",
                         st.validLifetime, st.age);
            detail += buf;
        }
        detail += L"当前状态:  " + st.message;
    } else {
        detail = st.message.empty() ? L"等待首次检测..." : st.message;
    }
    SetWindowTextW(GetDlgItem(hWnd, IDC_STATIC_DETAIL), detail.c_str());

    // 托盘提示
    std::wstring tip = L"IPv6 路由监控 - ";
    if (!st.found)              tip += L"无默认路由";
    else if (st.remaining < 0)  tip += L"无限期";
    else                        tip += std::to_wstring(st.remaining) + L" 秒";
    UpdateTrayTip(tip);

    // 冲刷日志队列
    std::vector<std::wstring> logs;
    {
        std::lock_guard<std::mutex> lk(g_logQueueMutex);
        logs.swap(g_logQueue);
    }
    for (auto& s : logs) AppendLog(hWnd, s);
}

// ============================================================
// 手动触发刷新
// ============================================================
static void TriggerManualRefresh(HWND hWnd)
{
    AppendLog(hWnd, L"用户手动触发刷新");
    {
        std::lock_guard<std::mutex> lk(g_cvMutex);
        g_forceCheck   = true;
        g_forceRefresh = true;
    }
    g_cv.notify_all();
}

// ============================================================
// 窗口过程
// ============================================================
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        g_hWndMain = hWnd;

        g_hFontTitle = CreateFontW(-26, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
        g_hFontNormal = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");

        auto CreateStatic = [&](const wchar_t* txt, int x, int y, int w, int h,
                                int id, DWORD extra = 0) {
            HWND hCtl = CreateWindowExW(0, L"STATIC", txt,
                WS_CHILD | WS_VISIBLE | extra,
                x, y, w, h, hWnd, (HMENU)(INT_PTR)id, g_hInst, nullptr);
            SendMessageW(hCtl, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
            return hCtl;
        };

        // 状态标题
        HWND hTitle = CreateStatic(L"当前 IPv6 默认路由状态",
            20, 15, 480, 24, IDC_STATIC_TITLE);
        SendMessageW(hTitle, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

        // 状态值
        HWND hStatus = CreateStatic(L"正在检测...",
            20, 40, 480, 40, IDC_STATIC_STATUS);
        SendMessageW(hStatus, WM_SETFONT, (WPARAM)g_hFontTitle, TRUE);

        // 详情
        CreateStatic(L"",
            20, 90, 485, 130, IDC_STATIC_DETAIL, SS_LEFT);

        // 按钮
        HWND hBtn1 = CreateWindowExW(0, L"BUTTON", L"立即刷新",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            20, 230, 110, 32, hWnd, (HMENU)IDC_BTN_REFRESH, g_hInst, nullptr);
        SendMessageW(hBtn1, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

        HWND hBtn2 = CreateWindowExW(0, L"BUTTON", L"最小化到托盘",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            140, 230, 140, 32, hWnd, (HMENU)IDC_BTN_TRAY, g_hInst, nullptr);
        SendMessageW(hBtn2, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

        HWND hChk = CreateWindowExW(0, L"BUTTON", L"开机自启动",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            300, 235, 130, 24, hWnd, (HMENU)IDC_CHECK_AUTOSTART, g_hInst, nullptr);
        SendMessageW(hChk, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
        if (IsAutoStartEnabled())
            SendMessageW(hChk, BM_SETCHECK, BST_CHECKED, 0);

        // 日志区
        CreateStatic(L"运行日志:", 20, 275, 200, 20, -1);

        HWND hLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL |
            ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            20, 300, 485, 140, hWnd, (HMENU)IDC_LIST_LOG, g_hInst, nullptr);
        SendMessageW(hLog, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);

        // 初始化托盘
        InitTrayIcon(hWnd);

        // 启动日志
        AppendLog(hWnd, L"程序启动");
        if (!IsRunningAsAdmin())
            AppendLog(hWnd, L"⚠ 未以管理员身份运行，路由刷新可能失败");
        else
            AppendLog(hWnd, L"已获得管理员权限");
        AppendLog(hWnd, L"检测间隔 " + std::to_wstring(CHECK_INTERVAL_SEC)
                       + L" 秒，刷新阈值 " + std::to_wstring(REFRESH_THRESHOLD) + L" 秒");

        return 0;
    }

    case WM_COMMAND:
    {
        WORD id   = LOWORD(wParam);
        WORD code = HIWORD(wParam);

        switch (id)
        {
        case IDC_BTN_REFRESH:
            if (code == BN_CLICKED) TriggerManualRefresh(hWnd);
            break;

        case IDC_BTN_TRAY:
            if (code == BN_CLICKED) {
                ShowWindow(hWnd, SW_HIDE);
                AppendLog(hWnd, L"已最小化到系统托盘");
            }
            break;

        case IDC_CHECK_AUTOSTART:
            if (code == BN_CLICKED) {
                bool checked = SendMessageW(
                    GetDlgItem(hWnd, IDC_CHECK_AUTOSTART),
                    BM_GETCHECK, 0, 0) == BST_CHECKED;
                if (SetAutoStart(checked)) {
                    AppendLog(hWnd, checked ? L"已启用开机自启动"
                                            : L"已禁用开机自启动");
                } else {
                    MessageBoxW(hWnd, L"设置开机自启动失败，请检查权限。",
                                L"错误", MB_ICONERROR);
                    SendMessageW(GetDlgItem(hWnd, IDC_CHECK_AUTOSTART),
                        BM_SETCHECK, checked ? BST_UNCHECKED : BST_CHECKED, 0);
                }
            }
            break;

        case IDM_TRAY_SHOW:
            ShowWindow(hWnd, SW_SHOW);
            ShowWindow(hWnd, SW_RESTORE);
            SetForegroundWindow(hWnd);
            break;

        case IDM_TRAY_REFRESH:
            TriggerManualRefresh(hWnd);
            break;

        case IDM_TRAY_AUTOSTART:
        {
            bool newState = !IsAutoStartEnabled();
            if (SetAutoStart(newState)) {
                SendMessageW(GetDlgItem(hWnd, IDC_CHECK_AUTOSTART),
                    BM_SETCHECK, newState ? BST_CHECKED : BST_UNCHECKED, 0);
                AppendLog(hWnd, newState ? L"已启用开机自启动"
                                         : L"已禁用开机自启动");
            }
            break;
        }

        case IDM_TRAY_EXIT:
            g_exiting = true;
            DestroyWindow(hWnd);
            break;
        }
        return 0;
    }

    case WM_TRAYICON:
        if (lParam == WM_RBUTTONUP || lParam == WM_CONTEXTMENU) {
            POINT pt;
            GetCursorPos(&pt);
            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, IDM_TRAY_SHOW, L"显示主窗口(&O)");
            AppendMenuW(hMenu, MF_STRING, IDM_TRAY_REFRESH, L"立即刷新(&R)");
            AppendMenuW(hMenu,
                MF_STRING | (IsAutoStartEnabled() ? MF_CHECKED : 0),
                IDM_TRAY_AUTOSTART, L"开机自启动(&A)");
            AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(hMenu, MF_STRING, IDM_TRAY_EXIT, L"退出(&X)");

            SetForegroundWindow(hWnd);
            TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hWnd, nullptr);
            PostMessage(hWnd, WM_NULL, 0, 0);
            DestroyMenu(hMenu);
        }
        else if (lParam == WM_LBUTTONDBLCLK) {
            ShowWindow(hWnd, SW_SHOW);
            ShowWindow(hWnd, SW_RESTORE);
            SetForegroundWindow(hWnd);
        }
        return 0;

    case WM_UPDATE_STATUS:
        UpdateUIFromStatus(hWnd);
        return 0;

    case WM_CTLCOLORSTATIC:
    {
        HDC hdc  = (HDC)wParam;
        HWND hCtl = (HWND)lParam;
        if (hCtl == GetDlgItem(hWnd, IDC_STATIC_STATUS)) {
            SetTextColor(hdc, g_statusColor);
            SetBkMode(hdc, TRANSPARENT);
            return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
        }
        SetBkMode(hdc, TRANSPARENT);
        return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
    }

    case WM_SYSCOMMAND:
        // 点最小化也进入托盘
        if ((wParam & 0xFFF0) == SC_MINIMIZE) {
            ShowWindow(hWnd, SW_HIDE);
            AppendLog(hWnd, L"已最小化到系统托盘");
            return 0;
        }
        break;

    case WM_CLOSE:
        // 关闭按钮 → 隐藏到托盘，而非退出
        ShowWindow(hWnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        RemoveTrayIcon();
        if (g_hFontTitle)  DeleteObject(g_hFontTitle);
        if (g_hFontNormal) DeleteObject(g_hFontNormal);

        g_running = false;
        g_cv.notify_all();
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ============================================================
// 程序入口
// ============================================================
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR lpCmdLine, int nCmdShow)
{
    g_hInst = hInstance;

    // 检查是否以最小化模式启动（开机自启用）
    bool startMinimized = (wcsstr(lpCmdLine, L"--minimized") != nullptr);

    // 初始化 Common Controls
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    // 注册窗口类
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = kWndClass;
    wc.hIcon         = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm       = LoadIcon(nullptr, IDI_APPLICATION);
    if (!RegisterClassExW(&wc))
        return 1;

    // 创建窗口（带固定大小，禁止缩放）
    HWND hWnd = CreateWindowExW(
        0, kWndClass, L"IPv6 默认路由监控",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 548, 500,
        nullptr, nullptr, hInstance, nullptr);
    if (!hWnd) return 1;

    // 启动后台工作线程
    std::thread worker(WorkerThread);

    // 显示或隐藏
    if (!startMinimized) {
        ShowWindow(hWnd, nCmdShow);
        UpdateWindow(hWnd);
    }

    // 消息循环
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // 优雅退出
    g_running = false;
    g_cv.notify_all();
    if (worker.joinable()) worker.join();

    return (int)msg.wParam;
}