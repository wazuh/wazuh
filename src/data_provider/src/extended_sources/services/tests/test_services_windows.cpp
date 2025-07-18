/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "services_windows.hpp"
#include "encodingWindowsHelper.h"

using ::testing::_;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::DoAll;
using ::testing::Invoke;
using ::testing::Eq;
using ::testing::Truly;
using ::testing::NotNull;
using ::testing::StrEq;

class MockServicesHelper : public IServicesHelper
{
    public:
        MOCK_METHOD(std::optional<std::wstring>, readServiceDllFromParameters, (const std::wstring& serviceName), (override));
        MOCK_METHOD(std::optional<std::wstring>, expandEnvStringW, (const std::wstring& str), (override));
};

class MockWinSvcWrapper : public IWinSvcWrapper
{
    public:
        MOCK_METHOD(SC_HANDLE, OpenSCManagerWrapper, (LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess), (override));
        MOCK_METHOD(SC_HANDLE, OpenServiceWWrapper, (SC_HANDLE hSCManager, LPCWSTR lpServiceName, DWORD dwDesiredAccess), (override));
        MOCK_METHOD(BOOL, CloseServiceHandleWrapper, (SC_HANDLE hSCObject), (override));
        MOCK_METHOD(BOOL, QueryServiceConfigWWrapper, (SC_HANDLE hService, LPQUERY_SERVICE_CONFIGW lpServiceConfig, DWORD cbBufSize, LPDWORD pcbBytesNeeded), (override));
        MOCK_METHOD(BOOL, QueryServiceConfig2WWrapper, (SC_HANDLE hService, DWORD dwInfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded), (override));
        MOCK_METHOD(BOOL, EnumServicesStatusExWWrapper, (SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded,
                                                         LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCWSTR pszGroupName), (override));
};

class MockWindowsApiWrapper : public IWindowsApiWrapper
{
    public:
        MOCK_METHOD(DWORD, NetUserEnumWrapper,
                    (LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD), (override));
        MOCK_METHOD(DWORD, NetLocalGroupEnumWrapper,
                    (LPCWSTR, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD, LPDWORD), (override));
        MOCK_METHOD(DWORD, NetUserGetInfoWrapper,
                    (LPCWSTR, LPCWSTR, DWORD, LPBYTE*), (override));
        MOCK_METHOD(DWORD, RegOpenKeyExWWrapper,
                    (HKEY, LPCWSTR, DWORD, REGSAM, PHKEY), (override));
        MOCK_METHOD(DWORD, RegQueryValueExWWrapper,
                    (HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD), (override));
        MOCK_METHOD(LSTATUS, RegQueryInfoKeyWWrapper,
                    (HKEY, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD,
                     LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME), (override));
        MOCK_METHOD(bool, IsValidSidWrapper, (PSID), (override));
        MOCK_METHOD(BOOL, ConvertSidToStringSidAWrapper, (PSID, LPSTR*), (override));
        MOCK_METHOD(bool, ConvertSidToStringSidWWrapper, (PSID, LPWSTR*), (override));
        MOCK_METHOD(BOOL, ConvertStringSidToSidAWrapper, (LPCSTR, PSID*), (override));
        MOCK_METHOD(BOOL, LookupAccountSidWWrapper,
                    (LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE), (override));
        MOCK_METHOD(bool, LookupAccountNameWWrapper,
                    (LPCWSTR, LPCWSTR, PSID, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE), (override));
        MOCK_METHOD(void, FreeSidWrapper, (LPVOID), (override));
        MOCK_METHOD(DWORD, NetUserGetLocalGroupsWrapper,
                    (LPCWSTR, LPCWSTR, DWORD, DWORD, LPBYTE*, DWORD, LPDWORD, LPDWORD), (override));
        MOCK_METHOD(PUCHAR, GetSidSubAuthorityCountWrapper, (PSID), (override));
        MOCK_METHOD(PDWORD, GetSidSubAuthorityWrapper, (PSID, DWORD), (override));
        MOCK_METHOD(LSTATUS, RegEnumKeyWWrapper, (HKEY, DWORD, LPWSTR, DWORD), (override));
        MOCK_METHOD(DWORD, GetLastErrorWrapper, (), (override));
        MOCK_METHOD(LSTATUS, RegCloseKeyWrapper, (HKEY hKey), (override));
};

class ServicesProviderTest : public ::testing::Test
{
    protected:
        std::shared_ptr<MockServicesHelper> mockServicesHelper;
        std::shared_ptr<MockWinSvcWrapper> mockWinSvcWrapper;
        std::shared_ptr<MockWindowsApiWrapper> mockWinApiWrapper;
        std::unique_ptr<ServicesProvider> servicesProvider;

        void SetUp() override
        {
            mockServicesHelper = std::make_shared<MockServicesHelper>();
            mockWinSvcWrapper = std::make_shared<MockWinSvcWrapper>();
            mockWinApiWrapper = std::make_shared<MockWindowsApiWrapper>();
            servicesProvider = std::make_unique<ServicesProvider>(mockServicesHelper, mockWinSvcWrapper, mockWinApiWrapper);
        }

        // Helper to simulate LPQUERY_SERVICE_CONFIGW buffer
        void SetQueryServiceConfigWBuffer(LPQUERY_SERVICE_CONFIGW config, const std::string& binaryPath, const std::string& startName, DWORD startType, DWORD serviceType)
        {
            static WCHAR binaryPathBuffer[MAX_PATH];
            static WCHAR startNameBuffer[MAX_PATH];

            std::wcsncpy(binaryPathBuffer, Utils::EncodingWindowsHelper::stringUTF8ToWstring(binaryPath).c_str(), MAX_PATH - 1);
            binaryPathBuffer[MAX_PATH - 1] = L'\0';
            std::wcsncpy(startNameBuffer, Utils::EncodingWindowsHelper::stringUTF8ToWstring(startName).c_str(), MAX_PATH - 1);
            startNameBuffer[MAX_PATH - 1] = L'\0';

            config->dwServiceType = serviceType;
            config->dwStartType = startType;
            config->lpBinaryPathName = binaryPathBuffer;
            config->lpServiceStartName = startNameBuffer;
        }

        void SetServiceDescriptionWBuffer(LPSERVICE_DESCRIPTIONW desc, const std::string& descriptionText)
        {
            static WCHAR descriptionBuffer[1024];

            if (!descriptionText.empty())
            {
                std::wcsncpy(descriptionBuffer, Utils::EncodingWindowsHelper::stringUTF8ToWstring(descriptionText).c_str(), 1023);
                descriptionBuffer[1023] = L'\0';
                desc->lpDescription = descriptionBuffer;
            }
            else
            {
                desc->lpDescription = nullptr;
            }
        }
};

TEST_F(ServicesProviderTest, Collect_Success)
{
    SC_HANDLE fakeScmHandle = reinterpret_cast<SC_HANDLE>(100);

    // Mock OpenSCManagerWrapper
    EXPECT_CALL(*mockWinSvcWrapper, OpenSCManagerWrapper(nullptr, nullptr, GENERIC_READ))
    .WillOnce(Return(fakeScmHandle));

    DWORD initialBytesNeeded = 2 * sizeof(ENUM_SERVICE_STATUS_PROCESSW); // Two services
    DWORD initialServiceCount = 0;
    EXPECT_CALL(*mockWinSvcWrapper, EnumServicesStatusExWWrapper(fakeScmHandle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL, nullptr, 0, _, _, nullptr, nullptr))
    .WillOnce(DoAll(SetArgPointee<6>(initialBytesNeeded), SetArgPointee<7>(initialServiceCount), Return(FALSE)));
    EXPECT_CALL(*mockWinApiWrapper, GetLastErrorWrapper())
    .WillOnce(Return(ERROR_MORE_DATA))
    .WillOnce(Return(ERROR_INSUFFICIENT_BUFFER))
    .WillOnce(Return(ERROR_INSUFFICIENT_BUFFER))
    .WillOnce(Return(ERROR_INSUFFICIENT_BUFFER))
    .WillOnce(Return(ERROR_INVALID_PARAMETER));

    // Simulate EnumServicesStatusExWWrapper for actual data
    DWORD finalServiceCount = 2;
    EXPECT_CALL(*mockWinSvcWrapper, EnumServicesStatusExWWrapper(fakeScmHandle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL, _, initialBytesNeeded, _, _, nullptr, nullptr))
    .WillOnce(DoAll(Invoke([&](SC_HANDLE, SC_ENUM_TYPE, DWORD, DWORD, LPBYTE lpServices, DWORD, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD, LPCWSTR)
    {
        ENUM_SERVICE_STATUS_PROCESSW* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(lpServices);

        // Service 1
        static WCHAR svc1Name[] = L"ServiceA";
        static WCHAR svc1DisplayName[] = L"Display Service A";
        services[0].lpServiceName = svc1Name;
        services[0].lpDisplayName = svc1DisplayName;
        services[0].ServiceStatusProcess.dwCurrentState = SERVICE_RUNNING;
        services[0].ServiceStatusProcess.dwProcessId = 111;
        services[0].ServiceStatusProcess.dwWin32ExitCode = 0;
        services[0].ServiceStatusProcess.dwServiceSpecificExitCode = 0;

        // Service 2
        static WCHAR svc2Name[] = L"ServiceB";
        static WCHAR svc2DisplayName[] = L"Display Service B";
        services[1].lpServiceName = svc2Name;
        services[1].lpDisplayName = svc2DisplayName;
        services[1].ServiceStatusProcess.dwCurrentState = SERVICE_STOPPED;
        services[1].ServiceStatusProcess.dwProcessId = 222;
        services[1].ServiceStatusProcess.dwWin32ExitCode = 0;
        services[1].ServiceStatusProcess.dwServiceSpecificExitCode = 0;

        *pcbBytesNeeded = initialBytesNeeded;
        *lpServicesReturned = finalServiceCount;
        return TRUE;
    }), Return(TRUE)));

    // Mock for ServiceA
    SC_HANDLE fakeSvcHandleA = reinterpret_cast<SC_HANDLE>(201);
    EXPECT_CALL(*mockWinSvcWrapper, OpenServiceWWrapper(fakeScmHandle, StrEq(L"ServiceA"), SERVICE_QUERY_CONFIG))
    .WillOnce(Return(fakeSvcHandleA));

    DWORD requiredSize = sizeof(QUERY_SERVICE_CONFIGW) + 100;

    EXPECT_CALL(*mockWinSvcWrapper, QueryServiceConfigWWrapper(fakeSvcHandleA, nullptr, 0, _))
    .WillOnce(DoAll(SetArgPointee<3>(requiredSize), Return(FALSE)));

    EXPECT_CALL(*mockWinSvcWrapper, QueryServiceConfigWWrapper(fakeSvcHandleA, NotNull(), requiredSize, _))
    .WillOnce(DoAll(Invoke([&](SC_HANDLE, LPQUERY_SERVICE_CONFIGW config, DWORD, LPDWORD pcbBytesNeeded)
    {
        SetQueryServiceConfigWBuffer(config, "C:\\Path\\A.exe", "LocalSystemA", SERVICE_AUTO_START, SERVICE_WIN32_OWN_PROCESS);
        *pcbBytesNeeded = requiredSize;
        return TRUE;
    }), Return(TRUE)));

    requiredSize = sizeof(SERVICE_DESCRIPTIONW) + 50;

    EXPECT_CALL(*mockWinSvcWrapper, QueryServiceConfig2WWrapper(fakeSvcHandleA, SERVICE_CONFIG_DESCRIPTION, nullptr, 0, _))
    .WillOnce(DoAll(SetArgPointee<4>(requiredSize), Return(FALSE)));
    EXPECT_CALL(*mockWinSvcWrapper, QueryServiceConfig2WWrapper(fakeSvcHandleA, SERVICE_CONFIG_DESCRIPTION, NotNull(), requiredSize, _))
    .WillOnce(DoAll(Invoke([&](SC_HANDLE, DWORD, LPBYTE lpBuffer, DWORD, LPDWORD pcbBytesNeeded)
    {
        LPSERVICE_DESCRIPTIONW desc = reinterpret_cast<LPSERVICE_DESCRIPTIONW>(lpBuffer);
        SetServiceDescriptionWBuffer(desc, "Desc A.");
        *pcbBytesNeeded = requiredSize;
        return TRUE;
    }), Return(TRUE)));
    EXPECT_CALL(*mockServicesHelper, readServiceDllFromParameters(Eq(L"ServiceA")))
    .WillOnce(Return(std::make_optional(L"C:\\Path\\ModuleA.dll")));
    EXPECT_CALL(*mockServicesHelper, expandEnvStringW(Eq(L"C:\\Path\\ModuleA.dll")))
    .WillOnce(Return(std::make_optional(L"C:\\Path\\ModuleA.dll")));
    EXPECT_CALL(*mockWinSvcWrapper, CloseServiceHandleWrapper(fakeSvcHandleA))
    .WillOnce(Return(TRUE));

    // Mock for ServiceB
    SC_HANDLE fakeSvcHandleB = reinterpret_cast<SC_HANDLE>(202);

    EXPECT_CALL(*mockWinSvcWrapper, OpenServiceWWrapper(fakeScmHandle, StrEq(L"ServiceB"), SERVICE_QUERY_CONFIG))
    .WillOnce(Return(fakeSvcHandleB));

    requiredSize = sizeof(QUERY_SERVICE_CONFIGW) + 100;

    EXPECT_CALL(*mockWinSvcWrapper, QueryServiceConfigWWrapper(fakeSvcHandleB, nullptr, 0, _))
    .WillOnce(DoAll(SetArgPointee<3>(requiredSize), Return(FALSE)));
    EXPECT_CALL(*mockWinSvcWrapper, QueryServiceConfigWWrapper(fakeSvcHandleB, NotNull(), requiredSize, _))
    .WillOnce(DoAll(Invoke([&](SC_HANDLE, LPQUERY_SERVICE_CONFIGW config, DWORD, LPDWORD pcbBytesNeeded)
    {
        SetQueryServiceConfigWBuffer(config, "C:\\Path\\B.exe", "NetworkServiceB", SERVICE_DEMAND_START, SERVICE_FILE_SYSTEM_DRIVER);
        *pcbBytesNeeded = requiredSize;
        return TRUE;
    }), Return(TRUE)));
    EXPECT_CALL(*mockWinSvcWrapper, QueryServiceConfig2WWrapper(fakeSvcHandleB, SERVICE_CONFIG_DESCRIPTION, nullptr, 0, _))
    .WillOnce(DoAll(SetArgPointee<4>(0), Return(FALSE))); // No description for B
    EXPECT_CALL(*mockServicesHelper, readServiceDllFromParameters(Eq(L"ServiceB")))
    .WillOnce(Return(std::nullopt)); // No module path for B
    EXPECT_CALL(*mockWinSvcWrapper, CloseServiceHandleWrapper(fakeSvcHandleB))
    .WillOnce(Return(TRUE));

    // Mock CloseSCManagerWrapper
    EXPECT_CALL(*mockWinSvcWrapper, CloseServiceHandleWrapper(fakeScmHandle))
    .WillOnce(Return(TRUE));

    nlohmann::json results = servicesProvider->collect();

    ASSERT_EQ(results.size(), 2u);

    // Verify Service A
    const auto& svc1 = results[0];
    EXPECT_EQ(svc1["name"], "ServiceA");
    EXPECT_EQ(svc1["display_name"], "Display Service A");
    EXPECT_EQ(svc1["status"], "RUNNING");
    EXPECT_EQ(svc1["pid"], 111);
    EXPECT_EQ(svc1["path"], "C:\\Path\\A.exe");
    EXPECT_EQ(svc1["description"], "Desc A.");
    EXPECT_EQ(svc1["module_path"], "C:\\Path\\ModuleA.dll");

    // Verify Service B
    const auto& svc2 = results[1];
    EXPECT_EQ(svc2["name"], "ServiceB");
    EXPECT_EQ(svc2["display_name"], "Display Service B");
    EXPECT_EQ(svc2["status"], "STOPPED");
    EXPECT_EQ(svc2["pid"], 222);
    EXPECT_EQ(svc2["path"], "C:\\Path\\B.exe");
    EXPECT_EQ(svc2["description"], ""); // No description for B
    EXPECT_EQ(svc2["module_path"], ""); // No module path for B
}

TEST_F(ServicesProviderTest, Collect_OpenSCManagerFails)
{
    // Mock OpenSCManagerWrapper to fail
    EXPECT_CALL(*mockWinSvcWrapper, OpenSCManagerWrapper(nullptr, nullptr, GENERIC_READ))
    .WillOnce(Return(nullptr));
    EXPECT_CALL(*mockWinApiWrapper, GetLastErrorWrapper())
    .WillOnce(Return(ERROR_DATABASE_DOES_NOT_EXIST));

    nlohmann::json results = servicesProvider->collect();

    ASSERT_TRUE(results.empty());
}

TEST_F(ServicesProviderTest, Collect_EnumServicesStatusExWFailsToGetBufferSize)
{
    SC_HANDLE fakeScmHandle = reinterpret_cast<SC_HANDLE>(100);

    EXPECT_CALL(*mockWinSvcWrapper, OpenSCManagerWrapper(nullptr, nullptr, GENERIC_READ))
    .WillOnce(Return(fakeScmHandle));

    EXPECT_CALL(*mockWinSvcWrapper, EnumServicesStatusExWWrapper(fakeScmHandle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL, nullptr, 0, _, _, nullptr, nullptr))
    .WillOnce(DoAll(SetArgPointee<6>(0), SetArgPointee<7>(0), Return(FALSE)));
    EXPECT_CALL(*mockWinApiWrapper, GetLastErrorWrapper())
    .WillRepeatedly(Return(ERROR_INVALID_PARAMETER));

    EXPECT_CALL(*mockWinSvcWrapper, CloseServiceHandleWrapper(fakeScmHandle))
    .WillOnce(Return(TRUE));

    nlohmann::json results = servicesProvider->collect();

    ASSERT_TRUE(results.empty());
}

TEST_F(ServicesProviderTest, Collect_EnumServicesStatusExWFailsToGetData)
{
    SC_HANDLE fakeScmHandle = reinterpret_cast<SC_HANDLE>(100);

    EXPECT_CALL(*mockWinSvcWrapper, OpenSCManagerWrapper(nullptr, nullptr, GENERIC_READ))
    .WillOnce(Return(fakeScmHandle));

    // Simulate EnumServicesStatusExWWrapper for buffer size (success)
    DWORD initialBytesNeeded = 2 * sizeof(ENUM_SERVICE_STATUS_PROCESSW);
    DWORD initialServiceCount = 0;
    EXPECT_CALL(*mockWinSvcWrapper, EnumServicesStatusExWWrapper(fakeScmHandle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL, nullptr, 0, _, _, nullptr, nullptr))
    .WillOnce(DoAll(SetArgPointee<6>(initialBytesNeeded), SetArgPointee<7>(initialServiceCount), Return(FALSE)));
    EXPECT_CALL(*mockWinApiWrapper, GetLastErrorWrapper())
    .WillOnce(Return(ERROR_MORE_DATA))
    .WillOnce(Return(ERROR_NOT_ENOUGH_MEMORY));

    // Mock EnumServicesStatusExWWrapper to fail getting actual data
    EXPECT_CALL(*mockWinSvcWrapper, EnumServicesStatusExWWrapper(fakeScmHandle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL, _, initialBytesNeeded, _, _, nullptr, nullptr))
    .WillOnce(Return(FALSE));

    EXPECT_CALL(*mockWinSvcWrapper, CloseServiceHandleWrapper(fakeScmHandle))
    .WillOnce(Return(TRUE));

    nlohmann::json results = servicesProvider->collect();

    ASSERT_TRUE(results.empty());
}
