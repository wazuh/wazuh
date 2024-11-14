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

/* Hotfixes APIs */
#include <set>
#include <wbemidl.h>
#include <wbemcli.h>
#include <comdef.h>
#include <codecvt>
#include "wuapi.h"


// Define GUID manually for CLSID_UpdateSearcher
DEFINE_GUID(CLSID_UpdateSearcher, 0x5A2A5E6E, 0xD633, 0x4C3A, 0x8A, 0x7E, 0x69, 0x4D, 0xBF, 0x9E, 0xCE, 0xD4);

class IComHelper
{
    public:
        virtual ~IComHelper() = default;

        // Abstracted methods for WMI functions
        virtual HRESULT CreateWmiLocator(IWbemLocator*& pLoc) = 0;
        virtual HRESULT ConnectToWmiServer(IWbemLocator* pLoc, IWbemServices*& pSvc) = 0;
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


class ComHelper : public IComHelper
{
    public:
        // Implement WMI functions
        HRESULT CreateWmiLocator(IWbemLocator*& pLoc) override
        {
            return CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        }

        HRESULT ConnectToWmiServer(IWbemLocator* pLoc, IWbemServices*& pSvc) override
        {
            return pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, 0, 0, 0, &pSvc);
        }

        HRESULT SetProxyBlanket(IWbemServices* pSvc) override
        {
            return CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL,
                                     RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
        }

        HRESULT ExecuteWmiQuery(IWbemServices* pSvc, IEnumWbemClassObject*& pEnumerator) override
        {
            return pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_QuickFixEngineering"),
                                   WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        }

        // Implement Windows Update API functions
        HRESULT CreateUpdateSearcher(IUpdateSearcher*& pUpdateSearcher) override
        {
            return CoCreateInstance(CLSID_UpdateSearcher, NULL, CLSCTX_INPROC_SERVER, IID_IUpdateSearcher, (LPVOID*)&pUpdateSearcher);
        }

        HRESULT GetTotalHistoryCount(IUpdateSearcher* pUpdateSearcher, LONG& count) override
        {
            return pUpdateSearcher->GetTotalHistoryCount(&count);
        }

        HRESULT QueryHistory(IUpdateSearcher* pUpdateSearcher, IUpdateHistoryEntryCollection*& pHistory, LONG& count) override
        {
            return pUpdateSearcher->QueryHistory(0, count, &pHistory);
        }

        HRESULT GetCount(IUpdateHistoryEntryCollection* pHistory, LONG& count) override
        {
            return pHistory->get_Count(&count);
        }

        HRESULT GetItem(IUpdateHistoryEntryCollection* pHistory, LONG index, IUpdateHistoryEntry** pEntry) override
        {
            return pHistory->get_Item(index, pEntry);
        }

        HRESULT GetTitle(IUpdateHistoryEntry* pEntry, BSTR& title) override
        {
            return pEntry->get_Title(&title);
        }
};

// Queries Windows Management Instrumentation (WMI) to retrieve installed hotfixes
//  and stores them in the provided set.
void QueryWMIHotFixes(std::set<std::string>& hotfixSet, IComHelper& comHelper);


// Queries Windows Update Agent (WUA) for installed update history,
// extracts hotfixes, and adds them to the provided set.
void QueryWUHotFixes(std::set<std::string>& hotfixSet, IComHelper& comHelper);
