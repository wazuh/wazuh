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


#include <set>
#include <stdio.h>
#include "packages/packagesWindowsParserHelper.h"
#include "sysInfoWin_test.h"
#include <sddl.h>
#include <iostream>


void SysInfoWinTest::SetUp() {};
void SysInfoWinTest::TearDown() {};

TEST_F(SysInfoWinTest, test_extract_HFValue_7618)
{
    // Invalid cases
    EXPECT_EQ("", PackageWindowsHelper::extractHFValue("KB"));
    EXPECT_EQ("", PackageWindowsHelper::extractHFValue("KBAAAAAA"));
    EXPECT_EQ("", PackageWindowsHelper::extractHFValue("AABBEEKB25A34111"));
    // Valid cases
    EXPECT_EQ("KB976902", PackageWindowsHelper::extractHFValue("KB976902\\KB976932\\SUPPORT\\SSU\\SAND\\5A42A8EB"));
    EXPECT_EQ("KB976932", PackageWindowsHelper::extractHFValue("KB976932\\SAND\\87C8A3D4"));
    EXPECT_EQ("KB2534111", PackageWindowsHelper::extractHFValue("KB2534111.MSU\\8847D77D"));
    EXPECT_EQ("KB2534111", PackageWindowsHelper::extractHFValue("KBKBKBKBKB2534111"));
    EXPECT_EQ("KB2534111", PackageWindowsHelper::extractHFValue("KB2534111"));
}

TEST_F(SysInfoWinTest, testHF_Valids_Format)
{
    std::set<std::string> ret;
    constexpr auto KB_FORMAT_REGEX_OK { "(KB+[0-9]{6,})"};
    constexpr auto KB_ONLY_FORMAT_REGEX { "(KB)"};
    constexpr auto KB_NO_NUMBERS_FORMAT_REGEX { "(KB+[a-z])"};
    constexpr auto KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX { "(KB+[0-9]{6,}+[aA-zZ])"};
    PackageWindowsHelper::getHotFixFromReg(HKEY_LOCAL_MACHINE, PackageWindowsHelper::WIN_REG_HOTFIX, ret);

    for (const auto& hf : ret)
    {
        EXPECT_TRUE(std::regex_match(hf, std::regex(KB_FORMAT_REGEX_OK)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_ONLY_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_NO_NUMBERS_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX)));
    }
}

TEST_F(SysInfoWinTest, testHF_NT_Valids_Format)
{
    std::set<std::string> ret;
    constexpr auto KB_FORMAT_REGEX_OK { "(KB+[0-9]{6,})"};
    constexpr auto KB_ONLY_FORMAT_REGEX { "(KB)"};
    constexpr auto KB_NO_NUMBERS_FORMAT_REGEX { "(KB+[a-z])"};
    constexpr auto KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX { "(KB+[0-9]{6,}+[aA-zZ])"};
    PackageWindowsHelper::getHotFixFromRegNT(HKEY_LOCAL_MACHINE, PackageWindowsHelper::VISTA_REG_HOTFIX, ret);

    for (const auto& hf : ret)
    {
        EXPECT_TRUE(std::regex_match(hf, std::regex(KB_FORMAT_REGEX_OK)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_ONLY_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_NO_NUMBERS_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX)));
    }
}

TEST_F(SysInfoWinTest, testHF_WOW_Valids_Format)
{
    std::set<std::string> ret;
    constexpr auto KB_FORMAT_REGEX_OK { "(KB+[0-9]{6,})"};
    constexpr auto KB_ONLY_FORMAT_REGEX { "(KB)"};
    constexpr auto KB_NO_NUMBERS_FORMAT_REGEX { "(KB+[a-z])"};
    constexpr auto KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX { "(KB+[0-9]{6,}+[aA-zZ])"};
    PackageWindowsHelper::getHotFixFromRegWOW(HKEY_LOCAL_MACHINE, PackageWindowsHelper::WIN_REG_WOW_HOTFIX, ret);

    for (const auto& hf : ret)
    {
        EXPECT_TRUE(std::regex_match(hf, std::regex(KB_FORMAT_REGEX_OK)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_ONLY_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_NO_NUMBERS_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX)));
    }
}

TEST_F(SysInfoWinTest, testHF_PRODUCT_Valids_Format)
{
    std::set<std::string> ret;
    constexpr auto KB_FORMAT_REGEX_OK { "(KB+[0-9]{6,})"};
    constexpr auto KB_ONLY_FORMAT_REGEX { "(KB)"};
    constexpr auto KB_NO_NUMBERS_FORMAT_REGEX { "(KB+[a-z])"};
    constexpr auto KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX { "(KB+[0-9]{6,}+[aA-zZ])"};
    PackageWindowsHelper::getHotFixFromRegProduct(HKEY_LOCAL_MACHINE, PackageWindowsHelper::WIN_REG_PRODUCT_HOTFIX, ret);

    for (const auto& hf : ret)
    {
        EXPECT_TRUE(std::regex_match(hf, std::regex(KB_FORMAT_REGEX_OK)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_ONLY_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_NO_NUMBERS_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX)));
    }
}

//  Test: Windows Management Instrumentation (WMI) to retrieve installed hotfixes
TEST_F(SysInfoWinTest, WmiLocatorCreationFailure)
{
    MockComHelper mockHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockHelper, CreateWmiLocator(::testing::_))
    .WillOnce(testing::Return(E_FAIL));

    EXPECT_THROW(QueryWMIHotFixes(hotfixSet, mockHelper), std::runtime_error);
}

TEST_F(SysInfoWinTest, WmiConnectToWmiServerFailure)
{
    MockComHelper mockComHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockComHelper, CreateWmiLocator(testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, ConnectToWmiServer(testing::_, testing::_))
    .WillOnce(testing::Return(E_FAIL));

    EXPECT_THROW(QueryWMIHotFixes(hotfixSet, mockComHelper), std::runtime_error);
}

TEST_F(SysInfoWinTest, WmiSetProxyBlanket)
{
    MockComHelper mockComHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockComHelper, CreateWmiLocator(testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, ConnectToWmiServer(testing::_, testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, SetProxyBlanket(testing::_))
    .WillOnce(testing::Return(E_FAIL));

    EXPECT_THROW(QueryWMIHotFixes(hotfixSet, mockComHelper), std::runtime_error);
}

TEST_F(SysInfoWinTest, WmiExecuteQuery)
{
    MockComHelper mockComHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockComHelper, CreateWmiLocator(testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, ConnectToWmiServer(testing::_, testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, SetProxyBlanket(testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, ExecuteWmiQuery(testing::_, testing::_))
    .WillOnce(testing::Return(E_FAIL));

    EXPECT_THROW(QueryWMIHotFixes(hotfixSet, mockComHelper), std::runtime_error);
}

TEST_F(SysInfoWinTest, WmiPopulatesWMIHotfixSetCorrectly)
{
    std::set<std::string> hotfixSet;
    ComHelper comHelper;

    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    EXPECT_TRUE(SUCCEEDED(hres)) << "COM Initialization failed with HRESULT: " << std::hex << hres;

    QueryWMIHotFixes(hotfixSet, comHelper);

    constexpr auto KB_NO_NUMBERS_FORMAT_REGEX { "(KB+[a-z])"};
    constexpr auto KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX { "(KB+[0-9]{6,}+[aA-zZ])"};

    for (const auto& hf : hotfixSet)
    {
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_NO_NUMBERS_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX)));
    }

    CoUninitialize();
}

// Test: Windows Update Agent (WUA) for installed update history,
TEST_F(SysInfoWinTest, WuaLocatorCreationFailure)
{
    MockComHelper mockHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockHelper, CreateUpdateSearcher(::testing::_))
    .WillOnce(testing::Return(E_FAIL));

    EXPECT_THROW(QueryWUHotFixes(hotfixSet, mockHelper), std::runtime_error);
}

TEST_F(SysInfoWinTest, WuaGetTotalHistoryCount)
{
    MockComHelper mockHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockHelper, CreateUpdateSearcher(::testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockHelper, GetTotalHistoryCount(::testing::_, ::testing::_))
    .WillOnce(testing::Return(E_FAIL));

    EXPECT_THROW(QueryWUHotFixes(hotfixSet, mockHelper), std::runtime_error);
}

TEST_F(SysInfoWinTest, WuaQueryHistory)
{
    MockComHelper mockHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockHelper, CreateUpdateSearcher(::testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockHelper, GetTotalHistoryCount(::testing::_, ::testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockHelper, QueryHistory(::testing::_, ::testing::_, ::testing::_))
    .WillOnce(testing::Return(E_FAIL));

    EXPECT_THROW(QueryWUHotFixes(hotfixSet, mockHelper), std::runtime_error);
}

TEST_F(SysInfoWinTest, GetHistoryTest)
{
    MockComHelper mockHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockHelper, CreateUpdateSearcher(::testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockHelper, GetTotalHistoryCount(::testing::_, ::testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockHelper, QueryHistory(::testing::_, ::testing::_, ::testing::_))
    .WillOnce(testing::Return(S_OK));

    long count = 4;
    EXPECT_CALL(mockHelper, GetCount(testing::_, testing::_))
    .WillOnce(testing::DoAll(testing::SetArgReferee<1>(count), testing::Return(S_OK)));

    for (int i = 0 ; i < count; i++)
    {

        EXPECT_CALL(mockHelper, GetItem(testing::_, i, testing::_))
        .WillOnce(testing::Return(S_OK));

        // Simulate getting the title
        EXPECT_CALL(mockHelper, GetTitle(testing::_, testing::_))
        .WillRepeatedly(testing::Invoke([](IUpdateHistoryEntry*, BSTR & title) -> HRESULT
        {
            title = SysAllocString(L"Security Update KB123456");
            return S_OK;
        }));
    }

    EXPECT_CALL(mockHelper, GetResultCode(testing::_, testing::_))
    .WillRepeatedly(testing::DoAll(testing::SetArgReferee<1>(orcSucceeded), testing::Return(S_OK)));
    EXPECT_CALL(mockHelper, GetOperation(testing::_, testing::_))
    .WillRepeatedly(testing::DoAll(testing::SetArgReferee<1>(uoInstallation), testing::Return(S_OK)));
    EXPECT_CALL(mockHelper, GetDate(testing::_, testing::_))
    .WillRepeatedly(testing::DoAll(testing::SetArgReferee<1>(DATE{1}), testing::Return(S_OK)));

    QueryWUHotFixes(hotfixSet, mockHelper);

    EXPECT_EQ(hotfixSet.size(), static_cast<unsigned int>(1));
    EXPECT_EQ(*hotfixSet.begin(), "KB123456");
}

namespace
{
    struct FakeHistoryEntry
    {
        const wchar_t* title;
        UpdateOperation operation;
        OperationResultCode resultCode;
        DATE date;
        HRESULT getterResult {S_OK};
    };

    // Serves the entries through the mock. The entry pointers stay null, so the getters
    // read the entry of the last GetItem call.
    std::set<std::string> queryFakeHistory(const std::vector<FakeHistoryEntry>& entries)
    {
        MockComHelper mockHelper;
        std::set<std::string> hotfixSet;
        LONG current {0};

        EXPECT_CALL(mockHelper, CreateUpdateSearcher(testing::_)).WillOnce(testing::Return(S_OK));
        EXPECT_CALL(mockHelper, GetTotalHistoryCount(testing::_, testing::_)).WillOnce(testing::Return(S_OK));
        EXPECT_CALL(mockHelper, QueryHistory(testing::_, testing::_, testing::_)).WillOnce(testing::Return(S_OK));
        EXPECT_CALL(mockHelper, GetCount(testing::_, testing::_))
        .WillOnce(testing::DoAll(testing::SetArgReferee<1>(static_cast<LONG>(entries.size())), testing::Return(S_OK)));
        EXPECT_CALL(mockHelper, GetItem(testing::_, testing::_, testing::_))
        .WillRepeatedly(testing::Invoke([&current](IUpdateHistoryEntryCollection*, LONG index, IUpdateHistoryEntry**)
        {
            current = index;
            return S_OK;
        }));
        EXPECT_CALL(mockHelper, GetTitle(testing::_, testing::_))
        .WillRepeatedly(testing::Invoke([&](IUpdateHistoryEntry*, BSTR & title)
        {
            title = SysAllocString(entries[current].title);
            return S_OK;
        }));
        EXPECT_CALL(mockHelper, GetResultCode(testing::_, testing::_))
        .WillRepeatedly(testing::Invoke([&](IUpdateHistoryEntry*, OperationResultCode & resultCode)
        {
            resultCode = entries[current].resultCode;
            return entries[current].getterResult;
        }));
        EXPECT_CALL(mockHelper, GetOperation(testing::_, testing::_))
        .WillRepeatedly(testing::Invoke([&](IUpdateHistoryEntry*, UpdateOperation & operation)
        {
            operation = entries[current].operation;
            return S_OK;
        }));
        EXPECT_CALL(mockHelper, GetDate(testing::_, testing::_))
        .WillRepeatedly(testing::Invoke([&](IUpdateHistoryEntry*, DATE & date)
        {
            date = entries[current].date;
            return S_OK;
        }));

        QueryWUHotFixes(hotfixSet, mockHelper);
        return hotfixSet;
    }
}

TEST_F(SysInfoWinTest, WuaHistoryFailedAndAbortedInstallsAreNotHotfixes)
{
    const auto hotfixes = queryFakeHistory(
    {
        {L"Security Intelligence Update - KB2267602", uoInstallation, orcFailed, 3},
        {L"Cumulative Update KB5000001", uoInstallation, orcAborted, 2},
        {L"Cumulative Update KB5000002", uoInstallation, orcInProgress, 1},
        {L"Cumulative Update KB5000003", uoInstallation, orcNotStarted, 1},
    });

    EXPECT_TRUE(hotfixes.empty());
}

TEST_F(SysInfoWinTest, WuaHistorySuccessfulInstallsAreHotfixes)
{
    const auto hotfixes = queryFakeHistory(
    {
        {L"Cumulative Update KB5000001", uoInstallation, orcSucceeded, 1},
        {L"Cumulative Update KB5000002", uoInstallation, orcSucceededWithErrors, 1},
    });

    EXPECT_EQ(hotfixes, (std::set<std::string> {"KB5000001", "KB5000002"}));
}

TEST_F(SysInfoWinTest, WuaHistoryFailedRetryKeepsTheEarlierSuccessfulInstall)
{
    const auto hotfixes = queryFakeHistory(
    {
        {L"Cumulative Update KB5000001", uoInstallation, orcFailed, 2},
        {L"Cumulative Update KB5000001", uoInstallation, orcSucceeded, 1},
    });

    EXPECT_EQ(hotfixes, (std::set<std::string> {"KB5000001"}));
}

TEST_F(SysInfoWinTest, WuaHistoryLatestUninstallRemovesTheHotfix)
{
    // Listed oldest first, so the result does not depend on the history order.
    const auto hotfixes = queryFakeHistory(
    {
        {L"Cumulative Update KB5000001", uoInstallation, orcSucceeded, 1},
        {L"Cumulative Update KB5000001", uoUninstallation, orcSucceeded, 2},
    });

    EXPECT_TRUE(hotfixes.empty());
}

TEST_F(SysInfoWinTest, WuaHistoryFailedUninstallKeepsTheHotfix)
{
    const auto hotfixes = queryFakeHistory(
    {
        {L"Cumulative Update KB5000001", uoUninstallation, orcFailed, 2},
        {L"Cumulative Update KB5000001", uoInstallation, orcSucceeded, 1},
    });

    EXPECT_EQ(hotfixes, (std::set<std::string> {"KB5000001"}));
}

TEST_F(SysInfoWinTest, WuaHistoryReinstallAfterUninstallIsAHotfix)
{
    const auto hotfixes = queryFakeHistory(
    {
        {L"Cumulative Update KB5000001", uoInstallation, orcSucceeded, 3},
        {L"Cumulative Update KB5000001", uoUninstallation, orcSucceeded, 2},
        {L"Cumulative Update KB5000001", uoInstallation, orcSucceeded, 1},
    });

    EXPECT_EQ(hotfixes, (std::set<std::string> {"KB5000001"}));
}

TEST_F(SysInfoWinTest, WuaHistoryEntryWithUnreadableResultIsSkipped)
{
    const auto hotfixes = queryFakeHistory(
    {
        {L"Cumulative Update KB5000001", uoInstallation, orcSucceeded, 1, E_FAIL},
        {L"Cumulative Update KB5000002", uoInstallation, orcSucceeded, 1},
    });

    EXPECT_EQ(hotfixes, (std::set<std::string> {"KB5000002"}));
}

TEST_F(SysInfoWinTest, WuaHistoryItemFailureIsSkipped)
{
    MockComHelper mockHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockHelper, CreateUpdateSearcher(testing::_)).WillOnce(testing::Return(S_OK));
    EXPECT_CALL(mockHelper, GetTotalHistoryCount(testing::_, testing::_)).WillOnce(testing::Return(S_OK));
    EXPECT_CALL(mockHelper, QueryHistory(testing::_, testing::_, testing::_)).WillOnce(testing::Return(S_OK));
    EXPECT_CALL(mockHelper, GetCount(testing::_, testing::_))
    .WillOnce(testing::DoAll(testing::SetArgReferee<1>(LONG{2}), testing::Return(S_OK)));
    EXPECT_CALL(mockHelper, GetItem(testing::_, testing::_, testing::_)).WillRepeatedly(testing::Return(E_FAIL));
    EXPECT_CALL(mockHelper, GetTitle(testing::_, testing::_)).Times(0);

    QueryWUHotFixes(hotfixSet, mockHelper);

    EXPECT_TRUE(hotfixSet.empty());
}

TEST_F(SysInfoWinTest, CbsOnlyInstalledPackageStatesAreHotfixes)
{
    EXPECT_TRUE(PackageWindowsHelper::isCbsPackageInstalled(0x50));  // Superseded
    EXPECT_TRUE(PackageWindowsHelper::isCbsPackageInstalled(0x70));  // Installed
    EXPECT_TRUE(PackageWindowsHelper::isCbsPackageInstalled(0x80));  // Permanent

    EXPECT_FALSE(PackageWindowsHelper::isCbsPackageInstalled(0x00)); // Absent
    EXPECT_FALSE(PackageWindowsHelper::isCbsPackageInstalled(0x05)); // Uninstall pending
    EXPECT_FALSE(PackageWindowsHelper::isCbsPackageInstalled(0x20)); // Resolved
    EXPECT_FALSE(PackageWindowsHelper::isCbsPackageInstalled(0x40)); // Staged
    EXPECT_FALSE(PackageWindowsHelper::isCbsPackageInstalled(0x60)); // Install pending
    EXPECT_FALSE(PackageWindowsHelper::isCbsPackageInstalled(0x65)); // Partially installed
    EXPECT_FALSE(PackageWindowsHelper::isCbsPackageInstalled(0xFFFFFFE0)); // Install failed
}

namespace
{
    struct FakeCbsPackage
    {
        bool hasState;
        DWORD state;
        bool hasLocation;
        std::string location;
        std::set<std::string> listed {};
        int stateReads {0};
        int locationReads {0};

        std::string hotfix(const std::string& package)
        {
            return PackageWindowsHelper::getInstalledCbsHotfix(package,
                                                               listed,
                                                               [this](DWORD & value)
            {
                ++stateReads;
                value = state;
                return hasState;
            },
            [this](std::string & value)
            {
                ++locationReads;
                value = location;
                return hasLocation;
            });
        }
    };

    constexpr auto CBS_KB_PACKAGE {"Package_10_for_KB5127694~31bf3856ad364e35~amd64~~10.0.10008.1"};
    constexpr auto CBS_ROLLUP_PACKAGE {"Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.1742.1.10"};
    constexpr auto CBS_ROLLUP_LOCATION {"\\\\?\\D:\\wd\\ctemp\\metadata\\Windows11.0-KB5043080-x64\\"};
}

TEST_F(SysInfoWinTest, CbsInstalledKbPackageIsAHotfix)
{
    FakeCbsPackage package {true, 0x70, false, ""};

    EXPECT_EQ("KB5127694", package.hotfix(CBS_KB_PACKAGE));
    EXPECT_EQ(0, package.locationReads);
}

TEST_F(SysInfoWinTest, CbsSupersededKbPackageIsAHotfix)
{
    FakeCbsPackage package {true, 0x50, false, ""};

    EXPECT_EQ("KB5127694", package.hotfix(CBS_KB_PACKAGE));
}

TEST_F(SysInfoWinTest, CbsStagedKbPackageIsNotAHotfix)
{
    FakeCbsPackage package {true, 0x40, false, ""};

    EXPECT_EQ("", package.hotfix(CBS_KB_PACKAGE));
}

TEST_F(SysInfoWinTest, CbsPackageWithoutCurrentStateIsNotAHotfix)
{
    FakeCbsPackage package {false, 0x70, false, ""};

    EXPECT_EQ("", package.hotfix(CBS_KB_PACKAGE));
}

TEST_F(SysInfoWinTest, CbsInstalledRollupTakesTheKbFromItsInstallLocation)
{
    FakeCbsPackage package {true, 0x70, true, CBS_ROLLUP_LOCATION};

    EXPECT_EQ("KB5043080", package.hotfix(CBS_ROLLUP_PACKAGE));
    EXPECT_EQ(1, package.locationReads);
}

TEST_F(SysInfoWinTest, CbsStagedRollupIsNotAHotfix)
{
    FakeCbsPackage package {true, 0x40, true, CBS_ROLLUP_LOCATION};

    EXPECT_EQ("", package.hotfix(CBS_ROLLUP_PACKAGE));
    EXPECT_EQ(0, package.locationReads);
}

TEST_F(SysInfoWinTest, CbsInstalledRollupWithoutInstallLocationIsNotAHotfix)
{
    FakeCbsPackage package {true, 0x70, false, ""};

    EXPECT_EQ("", package.hotfix(CBS_ROLLUP_PACKAGE));
}

TEST_F(SysInfoWinTest, CbsPackagesWithoutKbOrRollupAreNotRead)
{
    FakeCbsPackage package {true, 0x70, true, CBS_ROLLUP_LOCATION};

    EXPECT_EQ("", package.hotfix("Package_for_ServicingStack~31bf3856ad364e35~amd64~~26100.1.1"));
    EXPECT_EQ("", package.hotfix("Microsoft-Windows-Foundation-Package~31bf3856ad364e35~amd64~~KB5127694"));
    EXPECT_EQ(0, package.stateReads);
    EXPECT_EQ(0, package.locationReads);
}

TEST_F(SysInfoWinTest, CbsPackageOfAListedKbIsNotRead)
{
    FakeCbsPackage package {true, 0x40, false, "", {"KB5127694"}};

    EXPECT_EQ("", package.hotfix(CBS_KB_PACKAGE));
    EXPECT_EQ(0, package.stateReads);
}

TEST_F(SysInfoWinTest, WuaGetCountFailureThrows)
{
    MockComHelper mockHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockHelper, CreateUpdateSearcher(testing::_)).WillOnce(testing::Return(S_OK));
    EXPECT_CALL(mockHelper, GetTotalHistoryCount(testing::_, testing::_)).WillOnce(testing::Return(S_OK));
    EXPECT_CALL(mockHelper, QueryHistory(testing::_, testing::_, testing::_)).WillOnce(testing::Return(S_OK));
    EXPECT_CALL(mockHelper, GetCount(testing::_, testing::_)).WillOnce(testing::Return(E_FAIL));
    EXPECT_CALL(mockHelper, GetItem(testing::_, testing::_, testing::_)).Times(0);

    EXPECT_THROW(QueryWUHotFixes(hotfixSet, mockHelper), std::runtime_error);
    EXPECT_TRUE(hotfixSet.empty());
}

namespace
{
    // Fake CBS "Packages" key under HKCU, removed when the test ends.
    class FakeCbsRegistry
    {
        public:
            static constexpr auto ROOT {"Software\\WazuhSysInfoTest\\CbsPackages"};

            FakeCbsRegistry()
            {
                RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\WazuhSysInfoTest");
            }

            ~FakeCbsRegistry()
            {
                for (const auto& package : m_denied)
                {
                    HKEY key {};

                    if (RegOpenKeyExA(HKEY_CURRENT_USER, (std::string {ROOT} + "\\" + package).c_str(), 0, WRITE_DAC, &key) == ERROR_SUCCESS)
                    {
                        setDacl(key, "D:(A;;KA;;;WD)");
                        RegCloseKey(key);
                    }
                }

                RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\WazuhSysInfoTest");
            }

            void add(const std::string& package, const DWORD* state, const std::string& location = "")
            {
                HKEY key {};
                ASSERT_EQ(ERROR_SUCCESS, RegCreateKeyExA(HKEY_CURRENT_USER, (std::string {ROOT} + "\\" + package).c_str(),
                                                         0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &key, nullptr));

                if (state)
                {
                    RegSetValueExA(key, "CurrentState", 0, REG_DWORD, reinterpret_cast<const BYTE*>(state), sizeof(DWORD));
                }

                if (!location.empty())
                {
                    RegSetValueExA(key, "InstallLocation", 0, REG_SZ, reinterpret_cast<const BYTE*>(location.c_str()),
                                   static_cast<DWORD>(location.size() + 1));
                }

                RegCloseKey(key);
            }

            // Denies reading the package key. Returns false where the DACL is not enforced (Wine).
            bool deny(const std::string& package)
            {
                const auto path {std::string {ROOT} + "\\" + package};
                HKEY key {};

                if (RegOpenKeyExA(HKEY_CURRENT_USER, path.c_str(), 0, WRITE_DAC, &key) != ERROR_SUCCESS)
                {
                    return false;
                }

                m_denied.push_back(package);
                setDacl(key, "D:P(D;;KA;;;WD)");
                RegCloseKey(key);

                if (RegOpenKeyExA(HKEY_CURRENT_USER, path.c_str(), 0, KEY_READ, &key) == ERROR_SUCCESS)
                {
                    RegCloseKey(key);
                    return false;
                }

                return true;
            }

            std::set<std::string> hotfixes(std::set<std::string> listed = {}) const
            {
                PackageWindowsHelper::getHotFixFromReg(HKEY_CURRENT_USER, ROOT, listed);
                return listed;
            }

        private:
            static void setDacl(HKEY key, const char* sddl)
            {
                PSECURITY_DESCRIPTOR descriptor {nullptr};

                if (ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1, &descriptor, nullptr))
                {
                    RegSetKeySecurity(key, DACL_SECURITY_INFORMATION, descriptor);
                    LocalFree(descriptor);
                }
            }

            std::vector<std::string> m_denied;
    };

    constexpr DWORD CBS_STAGED {0x40};
    constexpr DWORD CBS_INSTALLED {0x70};
}

TEST_F(SysInfoWinTest, CbsRegistryReportsOnlyInstalledPackages)
{
    FakeCbsRegistry registry;
    registry.add("Package_1_for_KB5000001~31bf3856ad364e35~amd64~~10.0.1.1", &CBS_INSTALLED);
    registry.add("Package_1_for_KB5000002~31bf3856ad364e35~amd64~~10.0.1.1", &CBS_STAGED);
    registry.add("Package_1_for_KB5000003~31bf3856ad364e35~amd64~~10.0.1.1", nullptr);
    registry.add("Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.1.1.1", &CBS_INSTALLED,
                 "\\\\?\\C:\\Windows\\ctemp\\metadata\\Windows11.0-KB5000004-x64\\");
    registry.add("Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.2.1.1", &CBS_STAGED,
                 "\\\\?\\C:\\Windows\\ctemp\\metadata\\Windows11.0-KB5000005-x64\\");
    registry.add("Package_for_ServicingStack~31bf3856ad364e35~amd64~~26100.1.1", &CBS_INSTALLED);

    EXPECT_EQ(registry.hotfixes(), (std::set<std::string> {"KB5000001", "KB5000004"}));
}

TEST_F(SysInfoWinTest, CbsRegistryUnreadablePackageDoesNotStopTheOthers)
{
    FakeCbsRegistry registry;
    registry.add("Package_1_for_KB5000001~31bf3856ad364e35~amd64~~10.0.1.1", &CBS_INSTALLED);
    registry.add("Package_1_for_KB5000002~31bf3856ad364e35~amd64~~10.0.1.1", &CBS_INSTALLED);
    registry.add("Package_1_for_KB5000003~31bf3856ad364e35~amd64~~10.0.1.1", &CBS_INSTALLED);

    if (!registry.deny("Package_1_for_KB5000002~31bf3856ad364e35~amd64~~10.0.1.1"))
    {
        GTEST_SKIP() << "Registry key permissions are not enforced here";
    }

    EXPECT_EQ(registry.hotfixes(), (std::set<std::string> {"KB5000001", "KB5000003"}));
}

// Tests for parseProcessCommandLine() — the UTF-16 to UTF-8 conversion and
// argument parsing logic used by the Windows process inventory.

// Empty input returns empty fields.
TEST_F(SysInfoWinTest, ParseCmdLineEmptyInput)
{
    const auto result = parseProcessCommandLine(L"");
    EXPECT_TRUE(result.cmd.empty());
    EXPECT_TRUE(result.argvs.empty());
}

// Simple executable path with no arguments.
TEST_F(SysInfoWinTest, ParseCmdLineNoArguments)
{
    const auto result = parseProcessCommandLine(L"C:\\Windows\\notepad.exe");
    EXPECT_EQ(result.cmd, "C:\\Windows\\notepad.exe");
    EXPECT_TRUE(result.argvs.empty());
}

// Executable with a single argument.
TEST_F(SysInfoWinTest, ParseCmdLineSingleArgument)
{
    const auto result = parseProcessCommandLine(L"app.exe --help");
    EXPECT_EQ(result.cmd, "app.exe --help");
    EXPECT_EQ(result.argvs, "--help");
}

// Executable with multiple arguments (svchost-style).
TEST_F(SysInfoWinTest, ParseCmdLineMultipleArguments)
{
    const auto result = parseProcessCommandLine(
                            L"C:\\Windows\\system32\\svchost.exe -k netsvcs -p");
    EXPECT_EQ(result.cmd, "C:\\Windows\\system32\\svchost.exe -k netsvcs -p");
    EXPECT_EQ(result.argvs, "-k netsvcs -p");
}

// Quoted executable path with spaces in the path.
TEST_F(SysInfoWinTest, ParseCmdLineQuotedPathWithSpaces)
{
    const auto result = parseProcessCommandLine(
                            L"\"C:\\Program Files\\My App\\app.exe\" --flag value");
    EXPECT_EQ(result.cmd, "\"C:\\Program Files\\My App\\app.exe\" --flag value");
    EXPECT_EQ(result.argvs, "--flag value");
}

// Quoted argument values are unquoted by CommandLineToArgvW.
TEST_F(SysInfoWinTest, ParseCmdLineQuotedArguments)
{
    const auto result = parseProcessCommandLine(
                            L"app.exe --name \"hello world\" --verbose");
    EXPECT_EQ(result.cmd, "app.exe --name \"hello world\" --verbose");
    EXPECT_EQ(result.argvs, "--name hello world --verbose");
}

// Unicode characters in the command line are properly converted to UTF-8.
TEST_F(SysInfoWinTest, ParseCmdLineUnicodeCharacters)
{
    // L"app.exe café" — é is U+00E9
    const auto result = parseProcessCommandLine(L"app.exe caf\u00E9");
    EXPECT_EQ(result.cmd, "app.exe caf\xC3\xA9");
    EXPECT_EQ(result.argvs, "caf\xC3\xA9");
}

// Command with many arguments preserves order and spacing.
TEST_F(SysInfoWinTest, ParseCmdLineManyArguments)
{
    const auto result = parseProcessCommandLine(L"cmd.exe /c dir /s /b /a-d");
    EXPECT_EQ(result.cmd, "cmd.exe /c dir /s /b /a-d");
    EXPECT_EQ(result.argvs, "/c dir /s /b /a-d");
}

// Calling the function twice with the same input produces the same result.
TEST_F(SysInfoWinTest, ParseCmdLineDeterministic)
{
    const std::wstring input = L"svchost.exe -k DcomLaunch -p";
    const auto result1 = parseProcessCommandLine(input);
    const auto result2 = parseProcessCommandLine(input);
    EXPECT_EQ(result1.cmd, result2.cmd);
    EXPECT_EQ(result1.argvs, result2.argvs);
}
