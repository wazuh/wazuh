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

#include <map>
#include <regex>
#include <sstream>        // For std::ostringstream
#include <iomanip>        // For std::hex
#include <stdexcept>      // For std::runtime_error
#include <string>         // For std::string and std::wstring
#include <locale>         // For localization utilities (if needed for string conversion)

#include "utilsWrapperWin.hpp"

#include <shellapi.h>


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

HRESULT ComHelper::GetOperation(IUpdateHistoryEntry* pEntry, UpdateOperation& operation)
{
    return pEntry->get_Operation(&operation);
}

HRESULT ComHelper::GetResultCode(IUpdateHistoryEntry* pEntry, OperationResultCode& resultCode)
{
    return pEntry->get_ResultCode(&resultCode);
}

HRESULT ComHelper::GetDate(IUpdateHistoryEntry* pEntry, DATE& date)
{
    return pEntry->get_Date(&date);
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

ProcessCmdLine parseProcessCommandLine(const std::wstring& fullCmdLineW)
{
    ProcessCmdLine result;

    if (fullCmdLineW.empty())
    {
        return result;
    }

    // Convert full command line from UTF-16 to UTF-8
    const int utf8Size = WideCharToMultiByte(
                             CP_UTF8, 0, fullCmdLineW.c_str(), static_cast<int>(fullCmdLineW.size()),
                             nullptr, 0, nullptr, nullptr);

    if (utf8Size > 0)
    {
        result.cmd.assign(static_cast<std::size_t>(utf8Size), '\0');
        const int written = WideCharToMultiByte(
                                CP_UTF8, 0, fullCmdLineW.c_str(), static_cast<int>(fullCmdLineW.size()),
                                result.cmd.data(), utf8Size, nullptr, nullptr);

        if (written > 0)
        {
            if (written < utf8Size)
            {
                result.cmd.resize(static_cast<std::size_t>(written));
            }
        }
        else
        {
            result.cmd.clear();
        }
    }

    // Parse arguments using CommandLineToArgvW for proper Windows command-line tokenization
    int argc = 0;
    const auto argv = CommandLineToArgvW(fullCmdLineW.c_str(), &argc);

    if (argv && argc > 1)
    {
        for (int i = 1; i < argc; ++i)
        {
            const int argSize = WideCharToMultiByte(
                                    CP_UTF8, 0, argv[i], -1, nullptr, 0, nullptr, nullptr);

            if (argSize > 0)
            {
                std::string arg(argSize, '\0');
                const int convertedSize = WideCharToMultiByte(
                                              CP_UTF8, 0, argv[i], -1, arg.data(), argSize, nullptr, nullptr);

                if (convertedSize > 0)
                {
                    arg.resize(static_cast<std::size_t>(convertedSize - 1));

                    if (!result.argvs.empty())
                    {
                        result.argvs += " ";
                    }

                    result.argvs += arg;
                }
            }
        }
    }

    if (argv)
    {
        LocalFree(argv);
    }

    return result;
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

    LONG historyCount = 0;
    hres = comHelper.GetCount(pHistory, historyCount);

    if (FAILED(hres))
    {
        if (pHistory) pHistory->Release();

        if (pUpdateSearcher) pUpdateSearcher->Release();

        oss << "WUA: Error getting update history entries count. Code: 0x" << std::hex << hres;
        throw std::runtime_error(oss.str());
    }

    // Latest successful operation per KB. The history keeps failed attempts and uninstalls too,
    // and its order is not documented, so the entry date decides which one is the latest.
    std::map<std::string, std::pair<DATE, UpdateOperation>> latestOperations;

    for (LONG i = 0; i < historyCount; ++i)
    {
        IUpdateHistoryEntry* pEntry = NULL;

        if (FAILED(comHelper.GetItem(pHistory, i, &pEntry)))
        {
            continue;
        }

        BSTR title = NULL;
        UpdateOperation operation = static_cast<UpdateOperation>(0);
        OperationResultCode resultCode = orcNotStarted;
        DATE date = 0;

        if (SUCCEEDED(comHelper.GetTitle(pEntry, title)) &&
                SUCCEEDED(comHelper.GetResultCode(pEntry, resultCode)) &&
                (resultCode == orcSucceeded || resultCode == orcSucceededWithErrors) &&
                SUCCEEDED(comHelper.GetOperation(pEntry, operation)) &&
                SUCCEEDED(comHelper.GetDate(pEntry, date)))
        {
            const std::string titleStr = BstrToString(title);
            std::smatch match;

            if (std::regex_search(titleStr, match, hotfixRegex))
            {
                const std::string hotfix = match[0];
                const auto it = latestOperations.find(hotfix);

                if (it == latestOperations.end() || date > it->second.first)
                {
                    latestOperations[hotfix] = {date, operation};
                }
            }
        }

        if (pEntry) pEntry->Release();

        SysFreeString(title);
    }

    for (const auto& [hotfix, latest] : latestOperations)
    {
        if (latest.second == uoInstallation)
        {
            hotfixSet.insert(hotfix);
        }
    }

    if (pHistory) pHistory->Release();

    if (pUpdateSearcher) pUpdateSearcher->Release();
}

