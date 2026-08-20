/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * December 22, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
#pragma once

#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#endif

/* Hotfixes APIs */
#include <set>
#include <wbemidl.h>
#include <wbemcli.h>
#include <stdio.h>
#include <comdef.h>
#include <codecvt>
#include "wuapi.h"

// Forward declarations for Windows Update API GUIDs (defined in wuguid library)
extern "C" const GUID CLSID_UpdateSearcher;
extern "C" const GUID IID_IUpdateSearcher;

class EXPORTED IComHelper
{
    public:
        virtual ~IComHelper() = default;

        // Abstracted methods for WMI functions
        virtual HRESULT CreateWmiLocator(IWbemLocator*& pLoc) = 0;
        virtual HRESULT ConnectToWmiServer(IWbemLocator* pLoc, IWbemServices*& pSvc, long maxWaitMs) = 0;
        virtual HRESULT SetProxyBlanket(IWbemServices* pSvc) = 0;
        virtual HRESULT ExecuteWmiQuery(IWbemServices* pSvc, IEnumWbemClassObject*& pEnumerator) = 0;

        // Abstracted methods for Windows Update API functions
        virtual HRESULT CreateUpdateSearcher(IUpdateSearcher*& pUpdateSearcher) = 0;
        virtual HRESULT GetTotalHistoryCount(IUpdateSearcher* pUpdateSearcher, LONG& count) = 0;
        virtual HRESULT QueryHistory(IUpdateSearcher* pUpdateSearcher, IUpdateHistoryEntryCollection*& pHistory, LONG& count) = 0;
        virtual HRESULT GetCount(IUpdateHistoryEntryCollection* pHistory, LONG& count) = 0;
        virtual HRESULT GetItem(IUpdateHistoryEntryCollection* pHistory, LONG index, IUpdateHistoryEntry** pEntry) = 0;
        virtual HRESULT GetTitle(IUpdateHistoryEntry* pEntry, BSTR& title) = 0;
};

class EXPORTED ComHelper : public IComHelper
{
    public:
        // Implement WMI functions
        HRESULT CreateWmiLocator(IWbemLocator*& pLoc) override;
        HRESULT ConnectToWmiServer(IWbemLocator* pLoc, IWbemServices*& pSvc, long maxWaitMs) override;
        HRESULT SetProxyBlanket(IWbemServices* pSvc) override;
        HRESULT ExecuteWmiQuery(IWbemServices* pSvc, IEnumWbemClassObject*& pEnumerator) override;

        // Implement Windows Update API functions
        HRESULT CreateUpdateSearcher(IUpdateSearcher*& pUpdateSearcher) override;
        HRESULT GetTotalHistoryCount(IUpdateSearcher* pUpdateSearcher, LONG& count) override;
        HRESULT QueryHistory(IUpdateSearcher* pUpdateSearcher, IUpdateHistoryEntryCollection*& pHistory, LONG& count) override;
        HRESULT GetCount(IUpdateHistoryEntryCollection* pHistory, LONG& count) override;
        HRESULT GetItem(IUpdateHistoryEntryCollection* pHistory, LONG index, IUpdateHistoryEntry** pEntry) override;
        HRESULT GetTitle(IUpdateHistoryEntry* pEntry, BSTR& title) override;
};

// Bounds ComHelper::ConnectToWmiServer's IWbemLocator::ConnectServer() call, which has
// no timeout parameter of its own and can block indefinitely if Winmgmt is unresponsive
// -- the same failure mode as the enumeration loop below, just one step earlier in the
// same call chain (issue #38370). Enforced via WMI's own WBEM_FLAG_CONNECT_USE_MAX_WAIT
// + an IWbemContext __MAX_WAIT property, not a detached watchdog thread.
// This value has only been exercised against a healthy-and-fast WMI connect, not a
// legitimately slow-but-not-hung one (e.g. shortly after a Winmgmt/CIM repository
// rebuild); treat it as a provisional estimate until it's validated against that case.
constexpr long WMI_CONNECT_MAX_WAIT_MS = 3000;

// Per-call timeout passed to IEnumWbemClassObject::Next() (milliseconds) -- replaces
// the previous WBEM_INFINITE, which let a slow/unresponsive Winmgmt block the
// syscollector worker thread forever (issue #38370).
constexpr long WMI_HOTFIX_NEXT_TIMEOUT_MS = 5000;

// Cumulative ceiling (milliseconds) across the whole enumeration loop, enforced as an
// absolute deadline: each IEnumWbemClassObject::Next() call is clamped to whatever time
// remains, so total blocking time can never exceed this value regardless of whether
// individual calls time out or keep succeeding without finishing. Combined with
// WMI_CONNECT_MAX_WAIT_MS, this bounds only 2 of the 5 blocking WMI/COM calls in this
// chain to at most 12000 ms total. CreateWmiLocator, SetProxyBlanket, and
// ExecuteWmiQuery remain fully unbounded (tracked as follow-up work) and can, on their
// own, still consume all of stop_wmodules()'s 20 s join budget (src/win32/win_utils.c,
// MODULE_JOIN_BUDGET_MS) -- this narrows issue #38370's reproduction window rather than
// closing it.
// This ceiling has only been exercised against a healthy-and-fast enumeration (a
// handful of hotfixes, no load); a host with a large hotfix count or under load could
// legitimately take longer to enumerate than this even with a fully responsive
// Winmgmt. Treat it as a provisional estimate until it's validated against that case.
constexpr long WMI_HOTFIX_ENUM_OVERALL_TIMEOUT_MS = 9000;

// Queries Windows Management Instrumentation (WMI) to retrieve installed hotfixes
// and stores them in the provided set. Bounded: gives up and throws std::runtime_error
// if Winmgmt does not respond within overallTimeoutMs, instead of blocking forever.
// Not EXPORTED -- not part of sysinfo.dll's public ABI -- so the timeout parameters
// stay a whitebox test seam (the unit test target compiles this translation unit
// directly, see tests/sysInfoWin/CMakeLists.txt) rather than a permanent public knob.
// Production code should call QueryWMIHotFixes() below instead.
void QueryWMIHotFixesBounded(std::set<std::string>& hotfixSet, IComHelper& comHelper,
                             long perCallTimeoutMs, long overallTimeoutMs, long connectMaxWaitMs);

// Production entry point: same as QueryWMIHotFixesBounded() above, fixed to the
// production timeout constants.
EXPORTED void QueryWMIHotFixes(std::set<std::string>& hotfixSet, IComHelper& comHelper);


// Queries Windows Update Agent (WUA) for installed update history,
// extracts hotfixes, and adds them to the provided set.
EXPORTED void QueryWUHotFixes(std::set<std::string>& hotfixSet, IComHelper& comHelper);

// Result of parsing a wide-string command line into UTF-8 components.
struct ProcessCmdLine
{
    std::string cmd;    // Full command line in UTF-8
    std::string argvs;  // Arguments only (after the executable), space-separated, UTF-8
};

// Converts a UTF-16 command line into UTF-8 cmd and argvs fields.
// Uses WideCharToMultiByte for encoding and CommandLineToArgvW for argument tokenization.
// Returns empty fields if the input is empty or conversion fails.
ProcessCmdLine parseProcessCommandLine(const std::wstring& fullCmdLineW);
