/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * February 25, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYSINFO_WIN_TEST_H
#define _SYSINFO_WIN_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilsWrapperWin.hpp"

class SysInfoWinTest : public ::testing::Test
{
    protected:

        SysInfoWinTest() = default;
        virtual ~SysInfoWinTest() = default;

        void SetUp() override;
        void TearDown() override;
};


class MockComHelper : public IComHelper
{
    public:
        MOCK_METHOD(HRESULT, CreateWmiLocator, (IWbemLocator*& pLoc), (override));
        MOCK_METHOD(HRESULT, ConnectToWmiServer, (IWbemLocator* pLoc, IWbemServices*& pSvc, long maxWaitMs), (override));
        MOCK_METHOD(HRESULT, SetProxyBlanket, (IWbemServices* pSvc), (override));
        MOCK_METHOD(HRESULT, ExecuteWmiQuery, (IWbemServices* pSvc, IEnumWbemClassObject*& pEnumerator), (override));
        MOCK_METHOD(HRESULT, CreateUpdateSearcher, (IUpdateSearcher*& pUpdateSearcher), (override));
        MOCK_METHOD(HRESULT, GetTotalHistoryCount, (IUpdateSearcher* pUpdateSearcher, LONG& count), (override));
        MOCK_METHOD(HRESULT, QueryHistory, (IUpdateSearcher* pUpdateSearcher, IUpdateHistoryEntryCollection*& pHistory,  LONG& count), (override));
        MOCK_METHOD(HRESULT, GetCount, (IUpdateHistoryEntryCollection* pHistory, LONG& count), (override));
        MOCK_METHOD(HRESULT, GetItem, (IUpdateHistoryEntryCollection* pHistory, LONG index, IUpdateHistoryEntry** pEntry), (override));
        MOCK_METHOD(HRESULT, GetTitle, (IUpdateHistoryEntry* pEntry, BSTR& title), (override));
};

// IComHelper::ExecuteWmiQuery hands back a raw IEnumWbemClassObject*, so exercising
// QueryWMIHotFixes' enumeration loop (in particular the #38370 bounded-timeout path)
// needs a fake of that COM interface itself, not just of IComHelper.
class MockEnumWbemClassObject : public IEnumWbemClassObject
{
    public:
        // IUnknown -- trivial stubs; refcounting/QI behavior is irrelevant to these tests,
        // and this instance's lifetime is owned by the test, not COM.
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void** ppvObject) override
        {
            if (ppvObject)
            {
                *ppvObject = nullptr;
            }

            return E_NOTIMPL;
        }
        ULONG STDMETHODCALLTYPE AddRef() override
        {
            return 1;
        }
        ULONG STDMETHODCALLTYPE Release() override
        {
            return 1;
        }

        // IEnumWbemClassObject -- only Next() is exercised by QueryWMIHotFixes.
        // Calltype(STDMETHODCALLTYPE) is required: IEnumWbemClassObject::Next is declared
        // STDMETHODCALLTYPE (__stdcall), and without a matching call type here the mock's
        // override has a conflicting calling convention -- a hard compile error under mingw.
        MOCK_METHOD(HRESULT, Next, (long lTimeout, ULONG uCount, IWbemClassObject** apObjects, ULONG* puReturned),
                    (Calltype(STDMETHODCALLTYPE), override));
        HRESULT STDMETHODCALLTYPE NextAsync(ULONG, IWbemObjectSink*) override
        {
            return E_NOTIMPL;
        }
        HRESULT STDMETHODCALLTYPE Clone(IEnumWbemClassObject**) override
        {
            return E_NOTIMPL;
        }
        HRESULT STDMETHODCALLTYPE Skip(long, ULONG) override
        {
            return E_NOTIMPL;
        }
        HRESULT STDMETHODCALLTYPE Reset() override
        {
            return E_NOTIMPL;
        }
};


#endif //_SYSINFO_WIN_TEST_H
