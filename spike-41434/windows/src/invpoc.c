/* Spike #41434: real-time change sources for non-process inventories (services, packages, AppX, users, network).
 * Usage: invpoc.exe <seconds>
 * Prints "<utc_filetime> <source> <detail>" per notification, to compare with the driver's ground truth. */
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <iphlpapi.h>
#include <winevt.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include <netioapi.h>

static ULONGLONG now_ft(void)
{
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    return ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

/* ---- services: SCM create/delete notifications (APC, one-shot, re-armed) ---- */
static SERVICE_NOTIFYW g_notify;
static SC_HANDLE g_scm, g_spool;
static SERVICE_NOTIFYW g_snotify;
static void CALLBACK on_scm(PVOID p)
{
    SERVICE_NOTIFYW* n = p;
    const wchar_t* kind = (n->dwNotificationTriggered & SERVICE_NOTIFY_CREATED) ? L"created" : L"deleted";
    /* pszServiceNames: double-NUL list, created names prefixed with '/' */
    for (wchar_t* s = n->pszServiceNames; s && *s; s += wcslen(s) + 1)
        wprintf(L"%llu SCM %ls %ls\n", now_ft(), kind, s[0] == L'/' ? s + 1 : s);
    fflush(stdout);
    if (n->pszServiceNames) LocalFree(n->pszServiceNames);
}
static void CALLBACK on_svc(PVOID p)
{
    SERVICE_NOTIFYW* n = p;
    wprintf(L"%llu SVC Spooler state=%lu\n", now_ft(), n->ServiceStatus.dwCurrentState);
    fflush(stdout);
}
static void arm_svc(void)
{
    memset(&g_snotify, 0, sizeof(g_snotify));
    g_snotify.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
    g_snotify.pfnNotifyCallback = on_svc;
    g_snotify.pContext = &g_snotify;
    NotifyServiceStatusChangeW(g_spool, SERVICE_NOTIFY_RUNNING | SERVICE_NOTIFY_STOPPED | SERVICE_NOTIFY_START_PENDING | SERVICE_NOTIFY_STOP_PENDING, &g_snotify);
}
static void arm_scm(void)
{
    memset(&g_notify, 0, sizeof(g_notify));
    g_notify.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
    g_notify.pfnNotifyCallback = on_scm;
    g_notify.pContext = &g_notify;
    DWORD rc = NotifyServiceStatusChangeW(g_scm, SERVICE_NOTIFY_CREATED | SERVICE_NOTIFY_DELETED, &g_notify);
    if (rc != ERROR_SUCCESS) wprintf(L"%llu SCM arm_failed %lu\n", now_ft(), rc);
}

/* ---- services: System log 7036 (state), 7040 (start type), 7045 (installed) ---- */
static DWORD WINAPI on_evt(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID ctx, EVT_HANDLE ev)
{
    (void)ctx;
    if (action != EvtSubscribeActionDeliver) return 0;
    wchar_t buf[8192];
    DWORD used = 0, props = 0;
    if (!EvtRender(NULL, ev, EvtRenderEventXml, sizeof(buf), buf, &used, &props)) return 0;
    wchar_t* id = wcsstr(buf, L"<EventID");
    wchar_t* d = wcsstr(buf, L"<Data");
    int eid = id ? _wtoi(wcschr(id, L'>') + 1) : 0;
    wchar_t name[256] = L"?";
    if (d)
    {
        wchar_t* v = wcschr(d, L'>') + 1;
        wchar_t* e = wcschr(v, L'<');
        if (e && e - v < 255) { wcsncpy(name, v, e - v); name[e - v] = 0; }
    }
    wprintf(L"%llu EVT %d %ls\n", now_ft(), eid, name);
    fflush(stdout);
    return 0;
}

/* ---- packages: registry change on Uninstall keys ---- */
typedef struct { HKEY root; wchar_t path[512]; } REGW;
static DWORD WINAPI reg_thread(LPVOID arg)
{
    REGW* r = arg;
    const wchar_t* path = r->path;
    HKEY k;
    if (RegOpenKeyExW(r->root, path, 0, KEY_NOTIFY, &k) != ERROR_SUCCESS)
    {
        wprintf(L"%llu REG open_failed %ls\n", now_ft(), path);
        return 1;
    }
    HANDLE e = CreateEventW(NULL, FALSE, FALSE, NULL);
    for (;;)
    {
        if (RegNotifyChangeKeyValue(k, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC, e, TRUE) != ERROR_SUCCESS) break;
        WaitForSingleObject(e, INFINITE);
        wprintf(L"%llu REG changed %ls%ls\n", now_ft(), r->root == HKEY_USERS ? L"HKU\\" : L"HKLM\\", path);
        fflush(stdout);
    }
    return 0;
}

/* browser extensions: directory changes under a profile folder (argv[2]) */
static DWORD WINAPI dir_thread(LPVOID arg)
{
    const wchar_t* path = arg;
    HANDLE d = CreateFileW(path, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (d == INVALID_HANDLE_VALUE) { wprintf(L"%llu DIR open_failed %lu %ls\n", now_ft(), GetLastError(), path); fflush(stdout); return 1; }
    static BYTE buf[65536];
    DWORD got;
    while (ReadDirectoryChangesW(d, buf, sizeof(buf), TRUE,
                                 FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE, &got, NULL, NULL))
    {
        ULONGLONG t = now_ft();
        for (FILE_NOTIFY_INFORMATION* fi = (FILE_NOTIFY_INFORMATION*)buf; got;)
        {
            wprintf(L"%llu DIR action=%lu %.*ls\n", t, fi->Action, (int)(fi->FileNameLength / sizeof(wchar_t)), fi->FileName);
            if (!fi->NextEntryOffset) break;
            fi = (FILE_NOTIFY_INFORMATION*)((BYTE*)fi + fi->NextEntryOffset);
        }
        fflush(stdout);
    }
    return 0;
}

static void watch(HKEY root, const wchar_t* path)
{
    REGW* r = calloc(1, sizeof(*r));
    r->root = root;
    wcsncpy(r->path, path, 511);
    CreateThread(NULL, 0, reg_thread, r, 0, NULL);
}

static VOID NETIOAPI_API_ on_if(PVOID ctx, PMIB_IPINTERFACE_ROW row, MIB_NOTIFICATION_TYPE t)
{
    (void)ctx;
    wprintf(L"%llu NET interface type=%d ifindex=%lu family=%u\n", now_ft(), t, row ? row->InterfaceIndex : 0, row ? row->Family : 0);
    fflush(stdout);
}

static VOID NETIOAPI_API_ on_addr(PVOID ctx, PMIB_UNICASTIPADDRESS_ROW row, MIB_NOTIFICATION_TYPE t)
{
    (void)ctx;
    wchar_t a[64] = L"?";
    if (row && row->Address.si_family == AF_INET)
    {
        BYTE* b = (BYTE*)&row->Address.Ipv4.sin_addr;
        swprintf(a, 64, L"%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    }
    wprintf(L"%llu NET address type=%d ifindex=%lu addr=%ls\n", now_ft(), t, row ? row->InterfaceIndex : 0, a);
    fflush(stdout);
}

int wmain(int argc, wchar_t** argv)
{
    int secs = argc > 1 ? _wtoi(argv[1]) : 60;
    g_scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!g_scm) { wprintf(L"OpenSCManager failed %lu\n", GetLastError()); return 1; }
    EVT_HANDLE sub = EvtSubscribe(NULL, NULL, L"System",
                                  L"*[System[Provider[@Name='Service Control Manager'] and (EventID=7036 or EventID=7040 or EventID=7045)]]",
                                  NULL, NULL, on_evt, EvtSubscribeToFutureEvents);
    if (!sub) wprintf(L"EvtSubscribe failed %lu\n", GetLastError());
    watch(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    watch(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    /* hotfixes: CBS package store, as Syscollector reads it */
    watch(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages");
    EVT_HANDLE wu = EvtSubscribe(NULL, NULL, L"Microsoft-Windows-WindowsUpdateClient/Operational", L"*", NULL, NULL, on_evt, EvtSubscribeToFutureEvents);
    if (!wu) wprintf(L"EvtSubscribe WindowsUpdateClient failed %lu\n", GetLastError());
    if (argc > 2) CreateThread(NULL, 0, dir_thread, argv[2], 0, NULL);
    /* every loaded user hive: per-user Uninstall and AppX repository, as Syscollector reads them */
    wchar_t sid[256];
    for (DWORD i = 0, n = 256; RegEnumKeyExW(HKEY_USERS, i, sid, &n, NULL, NULL, NULL, NULL) == ERROR_SUCCESS; i++, n = 256)
    {
        if (wcsncmp(sid, L"S-1-5-21-", 9) || wcsstr(sid, L"_Classes")) continue;
        wchar_t p[512];
        swprintf(p, 512, L"%ls\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", sid);
        watch(HKEY_USERS, p);
        swprintf(p, 512, L"%ls\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages", sid);
        watch(HKEY_USERS, p);
    }
    /* users and local groups: Security log account management */
    EVT_HANDLE sec = EvtSubscribe(NULL, NULL, L"Security", L"*[System[(EventID=4720 or EventID=4726 or EventID=4732 or EventID=4733)]]",
                                  NULL, NULL, on_evt, EvtSubscribeToFutureEvents);
    if (!sec) wprintf(L"EvtSubscribe Security failed %lu\n", GetLastError());
    /* network interfaces and addresses */
    HANDLE h1 = NULL, h2 = NULL;
    DWORD r1 = NotifyIpInterfaceChange(AF_UNSPEC, on_if, NULL, FALSE, &h1);
    DWORD r2 = NotifyUnicastIpAddressChange(AF_UNSPEC, on_addr, NULL, FALSE, &h2);
    if (r1 || r2) wprintf(L"NotifyIp failed if=%lu addr=%lu\n", r1, r2);
    g_spool = OpenServiceW(g_scm, L"Spooler", SERVICE_QUERY_STATUS);
    if (g_spool) arm_svc();
    arm_scm();
    wprintf(L"%llu READY\n", now_ft());
    fflush(stdout);
    ULONGLONG end = GetTickCount64() + (ULONGLONG)secs * 1000;
    while (GetTickCount64() < end)
    {
        /* alertable wait so the SCM APC runs; re-arm after each delivery */
        if (SleepEx(200, TRUE) == WAIT_IO_COMPLETION) { arm_scm(); if (g_spool) arm_svc(); }
    }
    wprintf(L"%llu DONE\n", now_ft());
    return 0;
}
