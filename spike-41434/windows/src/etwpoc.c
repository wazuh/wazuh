/* ETW real-time consumer PoC for spike #41434.
 * Usage: etwpoc.exe <mode> <seconds> [maxprint] [buf_kb] [max_buffers] [slow_us] [decode_only] [flush_ms] [watchdog]
 *   mp    = manifest providers Microsoft-Windows-Kernel-Process + Kernel-Network (private session)
 *   sl    = private system-logger session (classic kernel Process + TcpIp/UdpIp events)
 *   afd   = Microsoft-Windows-Winsock-AFD + Microsoft-Windows-TCPIP, unfiltered
 *   ports = Microsoft-Windows-TCPIP filtered by event ID, with EVENT_ENABLE_PROPERTY_SID
 *   full  = system logger (classic process + classic network) + TCPIP filtered
 *   full2 = system logger (classic process only) + TCPIP filtered + Kernel-Network filtered
 *   full3 = full2 + Kernel-Process event 1 (full image path); the recommended set
 *   full3afd = full3 + Winsock-AFD filtered to 1030/1001 (UDP bind/close on Server 2012 R2)
 *   planb = regular private session (no system-logger slot): Kernel-Process 1/2 + Kernel-Network + TCPIP, user from the token
 *   hog   = hold <maxprint> empty system-logger sessions for <seconds>, to exhaust the slots
 *   list  = list running ETW sessions and system-logger slots in use
 * Prints every event's TDH-decoded properties and, at the end, counts, latency and loss. */
#define INITGUID
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <sddl.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>

/* missing from this MinGW tdh.h */
ULONG WINAPI TdhFormatProperty(PTRACE_EVENT_INFO, PEVENT_MAP_INFO, ULONG, USHORT, USHORT, USHORT, USHORT, PBYTE, PULONG, PWCHAR, PUSHORT);

static const GUID KP = {0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};
static const GUID KN = {0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}};
/* classic kernel MOF classes */
static const GUID PROCESS_CLASS = {0x3d6fa8d0, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
static const GUID TCPIP_CLASS = {0x9a280ac0, 0xc8e0, 0x11d1, {0x84, 0xe2, 0x00, 0xc0, 0x4f, 0xb9, 0x98, 0xa2}};
static const GUID UDPIP_CLASS = {0xbf3a50c5, 0xa9c9, 0x4988, {0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80}};

static const GUID AFD = {0xe53c6823, 0x7bb8, 0x44bb, {0x90, 0xdc, 0x3f, 0x86, 0x09, 0x0d, 0x48, 0xa6}};
static const GUID TCPIPP = {0x2f07e2ee, 0x15db, 0x40f1, {0x90, 0xef, 0x9d, 0x7b, 0xa2, 0x82, 0x18, 0x8a}};
static int g_mode_afd, g_mode_ports, g_mode_full, g_mode_full2, g_mode_full3, g_mode_afdf, g_mode_planb, g_watchdog;
static ULONG g_flush_ms;
typedef struct { BOOLEAN FilterIn; UCHAR Reserved; USHORT Count; USHORT Events[6]; } POC_KN_FILTER;
typedef struct { BOOLEAN FilterIn; UCHAR Reserved; USHORT Count; USHORT Events[7]; } POC_EVENT_ID_FILTER;
typedef struct { BOOLEAN FilterIn; UCHAR Reserved; USHORT Count; USHORT Events[1]; } POC_ONE_FILTER;
typedef struct { BOOLEAN FilterIn; UCHAR Reserved; USHORT Count; USHORT Events[2]; } POC_TWO_FILTER;
#define SESSION_NAME L"WazuhEtwPoc41434"

static LARGE_INTEGER g_freq;
static FILE* g_out;
static DWORD g_slow_us;
static volatile LONG g_pump_done;
static ULONG g_pump_rc;
static long g_events, g_proc, g_net, g_maxprint = 200, g_printed;
static double g_lat_sum, g_lat_max;
static long g_tok_ok, g_tok_fail, g_tok_err[256];
static int g_mode_sl;

static const char* prov_name(const GUID* g)
{
    if (IsEqualGUID(g, &KP)) return "Kernel-Process";
    if (IsEqualGUID(g, &KN)) return "Kernel-Network";
    if (IsEqualGUID(g, &PROCESS_CLASS)) return "Classic-Process";
    if (IsEqualGUID(g, &TCPIP_CLASS)) return "Classic-TcpIp";
    if (IsEqualGUID(g, &UDPIP_CLASS)) return "Classic-UdpIp";
    if (IsEqualGUID(g, &AFD)) return "Winsock-AFD";
    if (IsEqualGUID(g, &TCPIPP)) return "TCPIP";
    return NULL;
}

static void token_user(DWORD pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid), t = NULL;
    char buf[256];
    DWORD len = 0;
    LPWSTR s = NULL;
    if (h && OpenProcessToken(h, TOKEN_QUERY, &t) && GetTokenInformation(t, TokenUser, buf, sizeof(buf), &len) &&
        ConvertSidToStringSidW(((TOKEN_USER*)buf)->User.Sid, &s))
    {
        g_tok_ok++;
        if (g_printed < g_maxprint) wprintf(L"    token_user(pid=%lu)=%ls\n", pid, s);
        LocalFree(s);
    }
    else
    {
        g_tok_fail++;
        g_tok_err[GetLastError() & 0xff]++;
        if (g_printed < g_maxprint) wprintf(L"    token_user(pid=%lu)=FAIL err=%lu\n", pid, GetLastError());
    }
    if (t) CloseHandle(t);
    if (h) CloseHandle(h);
}

static void print_props(PEVENT_RECORD ev)
{
    ULONG sz = 0;
    if (TdhGetEventInformation(ev, 0, NULL, NULL, &sz) != ERROR_INSUFFICIENT_BUFFER) return;
    PTRACE_EVENT_INFO info = malloc(sz);
    if (TdhGetEventInformation(ev, 0, NULL, info, &sz) != ERROR_SUCCESS) { free(info); return; }
    if (info->TaskNameOffset) fwprintf(g_out, L" task=%ls", (wchar_t*)((BYTE*)info + info->TaskNameOffset));
    if (info->OpcodeNameOffset) fwprintf(g_out, L" opcode=%ls", (wchar_t*)((BYTE*)info + info->OpcodeNameOffset));
    fwprintf(g_out, L"\n");
    BYTE* data = ev->UserData;
    BYTE* end = data + ev->UserDataLength;
    ULONG ptrsz = (ev->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
    for (ULONG i = 0; i < info->TopLevelPropertyCount && data < end; i++)
    {
        EVENT_PROPERTY_INFO* p = &info->EventPropertyInfoArray[i];
        wchar_t* name = (wchar_t*)((BYTE*)info + p->NameOffset);
        if (p->Flags & PropertyStruct) { fwprintf(g_out, L"    %ls=<struct>\n", name); break; }
        PROPERTY_DATA_DESCRIPTOR d = {(ULONGLONG)(ULONG_PTR)name, ULONG_MAX, 0};
        ULONG plen = 0;
        TdhGetPropertySize(ev, 0, NULL, 1, &d, &plen);
        static wchar_t out[16384];
        ULONG outsz = sizeof(out);
        USHORT used = 0;
        ULONG rc = TdhFormatProperty(info, NULL, ptrsz, p->nonStructType.InType, p->nonStructType.OutType,
                                     (USHORT)plen, (USHORT)(end - data), data, &outsz, out, &used);
        if (rc == ERROR_BUFFER_OVERFLOW && p->nonStructType.InType == 1 /* TDH_INTYPE_UNICODESTRING */)
        {
            size_t n = wcsnlen((wchar_t*)data, (end - data) / sizeof(wchar_t));
            fwprintf(g_out, L"    %ls=%.*ls (raw)\n", name, (int)n, (wchar_t*)data);
            data += (n + 1) * sizeof(wchar_t);
            continue;
        }
        if (rc != ERROR_SUCCESS) { fwprintf(g_out, L"    %ls=<fmt err %lu>\n", name, rc); break; }
        fwprintf(g_out, L"    %ls=%ls\n", name, out);
        data += used;
    }
    free(info);
}

static void WINAPI on_event(PEVENT_RECORD ev)
{
    const char* pn = prov_name(&ev->EventHeader.ProviderId);
    if (!pn) return;
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER now = {.LowPart = ft.dwLowDateTime, .HighPart = ft.dwHighDateTime};
    double lat = (double)((LONGLONG)now.QuadPart - ev->EventHeader.TimeStamp.QuadPart) / 10000.0; /* 100 ns -> ms */
    g_events++;
    g_lat_sum += lat;
    if (lat > g_lat_max) g_lat_max = lat;
    int is_proc = strstr(pn, "Process") != NULL;
    if (is_proc) g_proc++; else g_net++;
    int classic = strncmp(pn, "Classic", 7) == 0;
    USHORT id = classic ? ev->EventHeader.EventDescriptor.Opcode : ev->EventHeader.EventDescriptor.Id;
    if (g_printed < g_maxprint)
    {
        wprintf(L"[%s] %ls=%u ver=%u hdr_pid=%lu lat_ms=%.2f", pn, classic ? L"opcode" : L"id", id,
                ev->EventHeader.EventDescriptor.Version, ev->EventHeader.ProcessId, lat);
        for (USHORT x = 0; x < ev->ExtendedDataCount; x++)
            if (ev->ExtendedData[x].ExtType == EVENT_HEADER_EXT_TYPE_SID)
            {
                LPWSTR sid = NULL;
                if (ConvertSidToStringSidW((PSID)(ULONG_PTR)ev->ExtendedData[x].DataPtr, &sid)) { wprintf(L" ext_sid=%ls", sid); LocalFree(sid); }
            }
        print_props(ev);
    }
    /* process start: try to resolve the user from the token, as a consumer without the SID would have to */
    int start = is_proc && id == 1;
    if (start && ev->UserDataLength >= 4)
    {
        DWORD pid = 0;
        if (classic)
        {
            PROPERTY_DATA_DESCRIPTOR d = {(ULONGLONG)(ULONG_PTR)L"ProcessId", ULONG_MAX, 0};
            TdhGetProperty(ev, 0, NULL, 1, &d, sizeof(pid), (PBYTE)&pid);
        }
        else
        {
            PROPERTY_DATA_DESCRIPTOR d = {(ULONGLONG)(ULONG_PTR)L"ProcessID", ULONG_MAX, 0};
            TdhGetProperty(ev, 0, NULL, 1, &d, sizeof(pid), (PBYTE)&pid);
        }
        if (pid && !g_mode_full) token_user(pid);
    }
    if (g_printed >= g_maxprint && g_out != stdout) print_props(ev); /* decode-only cost run */
    if (g_slow_us >= 1000) Sleep(g_slow_us / 1000); /* slow consumer that does not steal CPU from the producers */
    else if (g_slow_us) { LARGE_INTEGER a, b; QueryPerformanceCounter(&a); do QueryPerformanceCounter(&b); while ((b.QuadPart - a.QuadPart) * 1000000 / g_freq.QuadPart < g_slow_us); }
    if (g_printed < g_maxprint) g_printed++;
    fflush(stdout);
}

static DWORD WINAPI pump(LPVOID arg)
{
    TRACEHANDLE h = *(TRACEHANDLE*)arg;
    g_pump_rc = ProcessTrace(&h, 1, NULL, NULL);
    InterlockedExchange(&g_pump_done, 1);
    for (int e = 0; e < 256; e++)
        if (g_tok_err[e]) wprintf(L"TOKEN_FAIL err=%d count=%ld\n", e, g_tok_err[e]);
    return 0;
}

static ULONG start_session(TRACEHANDLE* session, EVENT_TRACE_PROPERTIES* props, ULONG bufsz, ULONG bufkb, ULONG maxbuf)
{
    memset(props, 0, bufsz);
    props->Wnode.BufferSize = bufsz;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->Wnode.BufferSize = bufsz;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1; /* QPC timestamps, to measure latency */
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | (g_mode_sl ? EVENT_TRACE_SYSTEM_LOGGER_MODE : 0);
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->BufferSize = bufkb; /* KB */
    props->MinimumBuffers = maxbuf < 16 ? maxbuf : 16;
    props->MaximumBuffers = maxbuf;
    props->FlushTimer = g_flush_ms ? g_flush_ms : 1;
    if (g_flush_ms) props->LogFileMode |= 0x10; /* EVENT_TRACE_USE_MS_FLUSH_TIMER */
    if (g_mode_sl) props->EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_NETWORK_TCPIP;

    ControlTraceW(0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP); /* leftover from a previous run */
    memset(props, 0, bufsz);
    props->Wnode.BufferSize = bufsz;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | (g_mode_sl ? EVENT_TRACE_SYSTEM_LOGGER_MODE : 0);
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->BufferSize = bufkb;
    props->MinimumBuffers = maxbuf < 16 ? maxbuf : 16;
    props->MaximumBuffers = maxbuf;
    props->FlushTimer = g_flush_ms ? g_flush_ms : 1;
    if (g_flush_ms) props->LogFileMode |= 0x10; /* EVENT_TRACE_USE_MS_FLUSH_TIMER */
    if (g_mode_sl) props->EnableFlags = EVENT_TRACE_FLAG_PROCESS | (g_mode_full2 ? 0 : EVENT_TRACE_FLAG_NETWORK_TCPIP);

    ULONG rc = StartTraceW(session, SESSION_NAME, props);
    if (rc != ERROR_SUCCESS) return rc;
    if (g_mode_ports || g_mode_full)
    {
        POC_EVENT_ID_FILTER f = {TRUE, 0, 7, {1008, 1009, 1123, 1124, 1391, 1396, 1397}};
        EVENT_FILTER_DESCRIPTOR fd = {(ULONGLONG)(ULONG_PTR)&f, sizeof(f), 0x80000200 /* EVENT_FILTER_TYPE_EVENT_ID */};
        ENABLE_TRACE_PARAMETERS ep = {0};
        ep.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        ep.EnableProperty = EVENT_ENABLE_PROPERTY_SID;
        ep.EnableFilterDesc = &fd;
        ep.FilterDescCount = 1;
        rc = EnableTraceEx2(*session, &TCPIPP, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, &ep);
        if (rc) fwprintf(stderr, L"enable TCPIP (filtered, SID) failed %lu\n", rc);
        if (g_mode_full2)
        {
            POC_KN_FILTER kf = {TRUE, 0, 6, {12, 13, 15, 28, 29, 31}}; /* TCP connect/disconnect/accept v4+v6 */
            EVENT_FILTER_DESCRIPTOR kfd = {(ULONGLONG)(ULONG_PTR)&kf, sizeof(kf), 0x80000200};
            ENABLE_TRACE_PARAMETERS kp = {0};
            kp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
            kp.EnableFilterDesc = &kfd;
            kp.FilterDescCount = 1;
            rc = EnableTraceEx2(*session, &KN, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0x30, 0, 0, &kp);
            if (rc) fwprintf(stderr, L"enable Kernel-Network (filtered) failed %lu\n", rc);
        }
        if (g_mode_full3)
        {
            POC_ONE_FILTER pf = {TRUE, 0, 1, {1}}; /* Kernel-Process ProcessStart only: full image path */
            EVENT_FILTER_DESCRIPTOR pfd = {(ULONGLONG)(ULONG_PTR)&pf, sizeof(pf), 0x80000200};
            ENABLE_TRACE_PARAMETERS pp = {0};
            pp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
            pp.EnableFilterDesc = &pfd;
            pp.FilterDescCount = 1;
            rc = EnableTraceEx2(*session, &KP, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0x10, 0, 0, &pp);
            if (rc) fwprintf(stderr, L"enable Kernel-Process (filtered) failed %lu\n", rc);
        }
        if (g_mode_afdf)
        {
            POC_TWO_FILTER af = {TRUE, 0, 2, {1030, 1001}}; /* AfdBindWithAddress, AfdClose: UDP bind on 2012 R2 */
            EVENT_FILTER_DESCRIPTOR afd = {(ULONGLONG)(ULONG_PTR)&af, sizeof(af), 0x80000200};
            ENABLE_TRACE_PARAMETERS ap = {0};
            ap.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
            ap.EnableFilterDesc = &afd;
            ap.FilterDescCount = 1;
            rc = EnableTraceEx2(*session, &AFD, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, &ap);
            if (rc) fwprintf(stderr, L"enable Winsock-AFD (filtered) failed %lu\n", rc);
        }
    }
    else if (g_mode_planb)
    {
        /* no system-logger slot: regular private session, manifest providers only */
        POC_TWO_FILTER pf = {TRUE, 0, 2, {1, 2}};
        EVENT_FILTER_DESCRIPTOR pfd = {(ULONGLONG)(ULONG_PTR)&pf, sizeof(pf), 0x80000200};
        ENABLE_TRACE_PARAMETERS pp = {0};
        pp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        pp.EnableFilterDesc = &pfd;
        pp.FilterDescCount = 1;
        rc = EnableTraceEx2(*session, &KP, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0x10, 0, 0, &pp);
        if (rc) fwprintf(stderr, L"enable Kernel-Process failed %lu\n", rc);
        POC_KN_FILTER kf = {TRUE, 0, 6, {12, 13, 15, 28, 29, 31}};
        EVENT_FILTER_DESCRIPTOR kfd = {(ULONGLONG)(ULONG_PTR)&kf, sizeof(kf), 0x80000200};
        ENABLE_TRACE_PARAMETERS kp = {0};
        kp.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        kp.EnableFilterDesc = &kfd;
        kp.FilterDescCount = 1;
        rc = EnableTraceEx2(*session, &KN, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0x30, 0, 0, &kp);
        if (rc) fwprintf(stderr, L"enable Kernel-Network failed %lu\n", rc);
        POC_EVENT_ID_FILTER f = {TRUE, 0, 7, {1008, 1009, 1123, 1124, 1391, 1396, 1397}};
        EVENT_FILTER_DESCRIPTOR fd = {(ULONGLONG)(ULONG_PTR)&f, sizeof(f), 0x80000200};
        ENABLE_TRACE_PARAMETERS ep = {0};
        ep.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        ep.EnableFilterDesc = &fd;
        ep.FilterDescCount = 1;
        rc = EnableTraceEx2(*session, &TCPIPP, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, &ep);
        if (rc) fwprintf(stderr, L"enable TCPIP failed %lu\n", rc);
    }
    else if (g_mode_afd)
    {
        rc = EnableTraceEx2(*session, &AFD, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);
        if (rc) fwprintf(stderr, L"enable Winsock-AFD failed %lu\n", rc);
        rc = EnableTraceEx2(*session, &TCPIPP, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);
        if (rc) fwprintf(stderr, L"enable TCPIP failed %lu\n", rc);
    }
    else if (!g_mode_sl)
    {
        rc = EnableTraceEx2(*session, &KP, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0x10, 0, 0, NULL);
        if (rc) fwprintf(stderr, L"enable Kernel-Process failed %lu\n", rc);
        rc = EnableTraceEx2(*session, &KN, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0x30, 0, 0, NULL);
        if (rc) fwprintf(stderr, L"enable Kernel-Network failed %lu\n", rc);
    }

    return ERROR_SUCCESS;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2) { fwprintf(stderr, L"usage: etwpoc <mp|sl> <seconds> [maxprint]\n"); return 2; }
    g_mode_sl = wcscmp(argv[1], L"sl") == 0;
    g_mode_afd = wcscmp(argv[1], L"afd") == 0;
    g_mode_ports = wcscmp(argv[1], L"ports") == 0;
    g_mode_full2 = wcscmp(argv[1], L"full2") == 0;
    g_mode_afdf = wcscmp(argv[1], L"full3afd") == 0;
    g_mode_planb = wcscmp(argv[1], L"planb") == 0;
    g_mode_full3 = wcscmp(argv[1], L"full3") == 0 || g_mode_afdf;
    g_mode_full2 = wcscmp(argv[1], L"full2") == 0 || g_mode_full3;
    g_mode_full = wcscmp(argv[1], L"full") == 0 || g_mode_full2;
    if (argc > 8) g_flush_ms = (ULONG)_wtoi(argv[8]);
    if (argc > 9) g_watchdog = _wtoi(argv[9]);
    if (g_mode_full) g_mode_sl = 1;
    g_out = stdout;
    if (argc > 6) g_slow_us = (DWORD)_wtoi(argv[6]);
    if (argc > 7 && _wtoi(argv[7]) == 1) { g_out = _wfopen(L"NUL", L"w"); }
    ULONG bufkb = argc > 4 ? (ULONG)_wtoi(argv[4]) : 64, maxbuf = argc > 5 ? (ULONG)_wtoi(argv[5]) : 64;
    int secs = argc > 2 ? _wtoi(argv[2]) : 0;
    if (argc > 3) g_maxprint = _wtoi(argv[3]);
    QueryPerformanceFrequency(&g_freq);
    if (wcscmp(argv[1], L"hog") == 0)
    {
        /* etwpoc hog <seconds> <count>: hold <count> empty system-logger sessions to exhaust the slots */
        int n = argc > 3 ? _wtoi(argv[3]) : 8, held = 0;
        ULONG sz = sizeof(EVENT_TRACE_PROPERTIES) + 512;
        for (int i = 0; i < n; i++)
        {
            wchar_t name[64];
            swprintf(name, 64, L"WazuhHog41434_%d", i);
            EVENT_TRACE_PROPERTIES* hp = calloc(1, sz);
            hp->Wnode.BufferSize = sz;
            hp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            ControlTraceW(0, name, hp, EVENT_TRACE_CONTROL_STOP);
            memset(hp, 0, sz);
            hp->Wnode.BufferSize = sz;
            hp->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            hp->Wnode.ClientContext = 1;
            hp->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
            hp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            TRACEHANDLE h = 0;
            ULONG r = StartTraceW(&h, name, hp);
            wprintf(L"HOG %ls rc=%lu\n", name, r);
            if (r == ERROR_SUCCESS) held++;
        }
        wprintf(L"HOG held=%d\n", held);
        fflush(stdout);
        Sleep((DWORD)secs * 1000);
        for (int i = 0; i < n; i++)
        {
            wchar_t name[64];
            swprintf(name, 64, L"WazuhHog41434_%d", i);
            EVENT_TRACE_PROPERTIES* hp = calloc(1, sz);
            hp->Wnode.BufferSize = sz;
            hp->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            ControlTraceW(0, name, hp, EVENT_TRACE_CONTROL_STOP);
        }
        wprintf(L"HOG released\n");
        return 0;
    }
    if (wcscmp(argv[1], L"list") == 0)
    {
        EVENT_TRACE_PROPERTIES* arr[64];
        for (int i = 0; i < 64; i++)
        {
            arr[i] = calloc(1, sizeof(EVENT_TRACE_PROPERTIES) + 2048);
            arr[i]->Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 2048;
            arr[i]->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            arr[i]->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
        }
        ULONG n = 0, r = QueryAllTracesW(arr, 64, &n), sl = 0;
        for (ULONG i = 0; i < n; i++)
        {
            int is_sl = (arr[i]->LogFileMode & EVENT_TRACE_SYSTEM_LOGGER_MODE) != 0;
            sl += is_sl;
            wprintf(L"SESSION %ls mode=0x%08lx system_logger=%d\n", (wchar_t*)((BYTE*)arr[i] + arr[i]->LoggerNameOffset), arr[i]->LogFileMode, is_sl);
        }
        wprintf(L"LIST rc=%lu sessions=%lu system_logger=%lu\n", r, n, sl);
        return 0;
    }

    ULONG bufsz = sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024;
    EVENT_TRACE_PROPERTIES* props = calloc(1, bufsz);
    TRACEHANDLE session = 0;
    ULONG rc = start_session(&session, props, bufsz, bufkb, maxbuf);
    if (rc != ERROR_SUCCESS) { fwprintf(stderr, L"StartTrace failed %lu\n", rc); return 1; }

    EVENT_TRACE_LOGFILEW lf = {0};
    lf.LoggerName = SESSION_NAME;
    lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = on_event;
    TRACEHANDLE th = OpenTraceW(&lf);
    if (th == INVALID_PROCESSTRACE_HANDLE) { fwprintf(stderr, L"OpenTrace failed %lu\n", GetLastError()); return 1; }
    HANDLE thr = CreateThread(NULL, 0, pump, &th, 0, NULL);
    wprintf(L"READY mode=%ls\n", g_mode_full2 ? L"full2(process+tcpip+kn-filtered)" : g_mode_full ? L"full(system-logger+tcpip)" : g_mode_ports ? L"ports(filtered+sid)" : g_mode_afd ? L"afd+tcpip" : g_mode_sl ? L"system-logger" : L"manifest");
    fflush(stdout);
    int gone_at = -1;
    for (int t = 0; t < secs * 10 && !g_pump_done; t++)
    {
        Sleep(100);
        if (t % 10 == 9 && gone_at < 0)
        {
            ULONG q = ControlTraceW(session, NULL, props, EVENT_TRACE_CONTROL_QUERY);
            if (q != ERROR_SUCCESS)
            {
                gone_at = (t + 1) / 10;
                wprintf(L"SESSION_GONE_DETECTED_BY_QUERY after_s=%d rc=%lu pump_done=%ld\n", gone_at, q, g_pump_done);
                if (g_watchdog)
                {
                    LARGE_INTEGER a, b;
                    QueryPerformanceCounter(&a);
                    CloseTrace(th);
                    WaitForSingleObject(thr, 5000);
                    ULONG r1 = start_session(&session, props, bufsz, bufkb, maxbuf);
                    th = OpenTraceW(&lf);
                    g_pump_done = 0;
                    thr = CreateThread(NULL, 0, pump, &th, 0, NULL);
                    QueryPerformanceCounter(&b);
                    wprintf(L"SESSION_REOPENED start_rc=%lu reopen_ms=%.1f\n", r1, (double)(b.QuadPart - a.QuadPart) * 1000.0 / g_freq.QuadPart);
                    gone_at = -1;
                }
                fflush(stdout);
            }
        }
    }
    if (g_pump_done) wprintf(L"SESSION_STOPPED_EXTERNALLY processtrace_rc=%lu\n", g_pump_rc);
    else if (gone_at >= 0) wprintf(L"PROCESSTRACE_STILL_BLOCKED after session was stopped (detected only by QUERY)\n");

    rc = ControlTraceW(session, NULL, props, EVENT_TRACE_CONTROL_QUERY);
    ULONG lost = props->EventsLost, rtlost = props->RealTimeBuffersLost;
    ControlTraceW(session, NULL, props, EVENT_TRACE_CONTROL_STOP);
    WaitForSingleObject(thr, 5000);
    CloseTrace(th);
    FILETIME c, e, k, u;
    GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u);
    PROCESS_MEMORY_COUNTERS pmc = {sizeof(pmc)};
    GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
    double cpu_ms = (((ULONGLONG)k.dwHighDateTime << 32 | k.dwLowDateTime) + ((ULONGLONG)u.dwHighDateTime << 32 | u.dwLowDateTime)) / 10000.0;
    wprintf(L"RESOURCES cpu_ms=%.0f peak_ws_kb=%lu ws_kb=%lu buf_kb=%lu max_buffers=%lu\n", cpu_ms,
            (ULONG)(pmc.PeakWorkingSetSize / 1024), (ULONG)(pmc.WorkingSetSize / 1024), bufkb, maxbuf);
    wprintf(L"SUMMARY events=%ld proc=%ld net=%ld lat_avg_ms=%.2f lat_max_ms=%.2f events_lost=%lu rt_buffers_lost=%lu "
            L"token_ok=%ld token_fail=%ld\n",
            g_events, g_proc, g_net, g_events ? g_lat_sum / g_events : 0.0, g_lat_max, lost, rtlost, g_tok_ok, g_tok_fail);
    for (int e = 0; e < 256; e++)
        if (g_tok_err[e]) wprintf(L"TOKEN_FAIL err=%d count=%ld\n", e, g_tok_err[e]);
    return 0;
}
