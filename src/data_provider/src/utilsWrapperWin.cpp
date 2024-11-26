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

#include <regex>
#include <sstream>        // For std::ostringstream
#include <iomanip>        // For std::hex
#include <stdexcept>      // For std::runtime_error
#include <string>         // For std::string and std::wstring
#include <locale>         // For localization utilities (if needed for string conversion)

#include "utilsWrapperWin.hpp"


// Implement WMI functions
HRESULT ComHelper::CreateWmiLocator(IWbemLocator*& pLoc)
{
    return CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
}

HRESULT ComHelper::ConnectToWmiServer(IWbemLocator* pLoc, IWbemServices*& pSvc)
{
    return pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, 0, 0, 0, &pSvc);
}

HRESULT ComHelper::SetProxyBlanket(IWbemServices* pSvc)
{
    return CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL,
                             RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
}

HRESULT ComHelper::ExecuteWmiQuery(IWbemServices* pSvc, IEnumWbemClassObject*& pEnumerator)
{
    return pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_QuickFixEngineering"),
                           WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
}

// Implement Windows Update API functions
HRESULT ComHelper::CreateUpdateSearcher(IUpdateSearcher*& pUpdateSearcher)
{
    return CoCreateInstance(CLSID_UpdateSearcher, NULL, CLSCTX_INPROC_SERVER, IID_IUpdateSearcher, (LPVOID*)&pUpdateSearcher);
}

HRESULT ComHelper::GetTotalHistoryCount(IUpdateSearcher* pUpdateSearcher, LONG& count)
{
    return pUpdateSearcher->GetTotalHistoryCount(&count);
}

HRESULT ComHelper::QueryHistory(IUpdateSearcher* pUpdateSearcher, IUpdateHistoryEntryCollection*& pHistory, LONG& count)
{
    return pUpdateSearcher->QueryHistory(0, count, &pHistory);
}

HRESULT ComHelper::GetCount(IUpdateHistoryEntryCollection* pHistory, LONG& count)
{
    return pHistory->get_Count(&count);
}

HRESULT ComHelper::GetItem(IUpdateHistoryEntryCollection* pHistory, LONG index, IUpdateHistoryEntry** pEntry)
{
    return pHistory->get_Item(index, pEntry);
}

HRESULT ComHelper::GetTitle(IUpdateHistoryEntry* pEntry, BSTR& title)
{
    return pEntry->get_Title(&title);
}

// This function provides a minimal implementation for converting C strings to BSTRs,
// avoiding the need to include a full COM library. This can be useful when you only need this specific functionality
// and want to minimize dependencies.
namespace _com_util
{
    BSTR ConvertStringToBSTR(const char* str)
    {
        int len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
        BSTR bstr = SysAllocStringLen(0, len);
        MultiByteToWideChar(CP_ACP, 0, str, -1, bstr, len);
        return bstr;
    }
}

// The BstrToString function takes a Windows-specific string (BSTR) and converts it into
// a standard C++ string (std::string) that can be more easily used in the application.
std::string BstrToString(BSTR bstr)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    std::wstring wstr(bstr, SysStringLen(bstr));
    return converter.to_bytes(wstr);
}

void QueryWMIHotFixes(std::set<std::string>& hotfixSet, IComHelper& comHelper)
{
    HRESULT hres;
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    std::ostringstream oss;

    hres = comHelper.CreateWmiLocator(pLoc);

    if (FAILED(hres))
    {
        oss << "WMI: Error creating IWbemLocator. Code: " << std::hex << hres;
        throw std::runtime_error(oss.str());
    }

    hres = comHelper.ConnectToWmiServer(pLoc, pSvc);

    if (FAILED(hres))
    {
        if (pLoc) pLoc->Release();

        oss << "WMI: connection failed. Code: " << std::hex << hres;
        throw std::runtime_error(oss.str());
    }

    hres = comHelper.SetProxyBlanket(pSvc);

    if (FAILED(hres))
    {
        if (pSvc) pSvc->Release();

        if (pLoc) pLoc->Release();

        oss << "WMI: security error. Code: " << std::hex << hres;
        throw std::runtime_error(oss.str());
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = comHelper.ExecuteWmiQuery(pSvc, pEnumerator);

    if (FAILED(hres))
    {
        if (pLoc) pLoc->Release();

        if (pLoc) pSvc->Release();

        oss << "WMI: query error. Code: " << std::hex << hres;
        throw std::runtime_error(oss.str());
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn)
        {
            break;
        }

        VARIANT vtProp;
        hr = pclsObj->Get(L"HotFixID", 0, &vtProp, 0, 0);

        if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR)
        {
            std::string hotfix = BstrToString(vtProp.bstrVal);

            if (hotfixSet.find(hotfix) == hotfixSet.end())
            {
                // New HotFix found
                hotfixSet.insert(hotfix);
            }
        }

        VariantClear(&vtProp);
        pclsObj->Release();
    }

    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
}

void QueryWUHotFixes(std::set<std::string>& hotfixSet, IComHelper& comHelper)
{
    HRESULT hres;
    IUpdateSearcher* pUpdateSearcher = NULL;
    IUpdateHistoryEntryCollection* pHistory = NULL;
    std::regex hotfixRegex("KB[0-9]+");
    std::ostringstream oss;

    hres = comHelper.CreateUpdateSearcher(pUpdateSearcher);

    if (FAILED(hres))
    {
        oss << "WUA: UpdateSearcher error. Code: " << std::hex << hres;
        throw std::runtime_error(oss.str());
    }

    LONG count;
    hres = comHelper.GetTotalHistoryCount(pUpdateSearcher, count);

    if (FAILED(hres))
    {
        if (pUpdateSearcher) pUpdateSearcher->Release();

        oss << "WUA: Error getting total update history count. Code: 0x" << std::hex << hres;
        throw std::runtime_error(oss.str());
    }

    hres = comHelper.QueryHistory(pUpdateSearcher, pHistory, count);

    if (FAILED(hres))
    {
        if (pUpdateSearcher) pUpdateSearcher->Release();

        oss << "WUA: Error querying update history. Code: 0x" << std::hex << hres;
        throw std::runtime_error(oss.str());
    }

    LONG historyCount;
    hres = comHelper.GetCount(pHistory, historyCount);

    for (LONG i = 0; i < historyCount; ++i)
    {
        IUpdateHistoryEntry* pEntry = NULL;
        comHelper.GetItem(pHistory, i, &pEntry);
        BSTR title;
        comHelper.GetTitle(pEntry, title);
        std::string titleStr = BstrToString(title);

        std::smatch match;

        if (std::regex_search(titleStr, match, hotfixRegex))
        {
            std::string hotfix = match[0];

            if (hotfixSet.find(hotfix) == hotfixSet.end())
            {
                // New HotFix found
                hotfixSet.insert(hotfix);
            }
        }

        if (pEntry) pEntry->Release();

        SysFreeString(title);
    }

    if (pHistory) pHistory->Release();

    if (pUpdateSearcher) pUpdateSearcher->Release();
}

