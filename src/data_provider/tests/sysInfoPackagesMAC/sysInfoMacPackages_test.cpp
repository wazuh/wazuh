/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * December 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sysInfoMacPackages_test.h"
#include <climits>
#include <unistd.h>
#include "packages/packageMac.h"
#include "packages/macportsWrapper.h"
#include "mocks/sqliteWrapperTempMock.h"
#include "sqliteWrapperTemp.h"
#include <filesystem>
#include <fstream>
#include <unistd.h>

void SysInfoMacPackagesTest::SetUp() {};

void SysInfoMacPackagesTest::TearDown() {};

using ::testing::_;
using ::testing::Return;
using ::testing::An;
using ::testing::ByMove;

class SysInfoMacPackagesWrapperMock: public IPackageWrapper
{
    public:
        SysInfoMacPackagesWrapperMock() = default;
        virtual ~SysInfoMacPackagesWrapperMock() = default;
        MOCK_METHOD(std::string, name, (), (const override));
        MOCK_METHOD(std::string, version, (), (const override));
        MOCK_METHOD(std::string, groups, (), (const override));
        MOCK_METHOD(std::string, description, (), (const override));
        MOCK_METHOD(std::string, architecture, (), (const override));
        MOCK_METHOD(std::string, format, (), (const override));
        MOCK_METHOD(std::string, osPatch, (), (const override));
        MOCK_METHOD(std::string, source, (), (const override));
        MOCK_METHOD(std::string, location, (), (const override));
        MOCK_METHOD(std::string, priority, (), (const override));
        MOCK_METHOD(int64_t, size, (), (const override));
        MOCK_METHOD(std::string, vendor, (), (const override));
        MOCK_METHOD(std::string, install_time, (), (const override));
        MOCK_METHOD(std::string, multiarch, (), (const override));
};

TEST_F(SysInfoMacPackagesTest, Test_SPEC_Data)
{
    auto mock { std::make_shared<SysInfoMacPackagesWrapperMock>() };
    nlohmann::json packages {};
    EXPECT_CALL(*mock, name()).Times(1).WillOnce(Return("1"));
    EXPECT_CALL(*mock, version()).Times(1).WillOnce(Return("2"));
    EXPECT_CALL(*mock, groups()).Times(1).WillOnce(Return("3"));
    EXPECT_CALL(*mock, description()).Times(1).WillOnce(Return("4"));
    EXPECT_CALL(*mock, architecture()).Times(1).WillOnce(Return("5"));
    EXPECT_CALL(*mock, format()).Times(1).WillOnce(Return("6"));
    EXPECT_CALL(*mock, source()).Times(1).WillOnce(Return("7"));
    EXPECT_CALL(*mock, location()).Times(1).WillOnce(Return("8"));
    EXPECT_CALL(*mock, priority()).Times(1).WillOnce(Return("9"));
    EXPECT_CALL(*mock, size()).Times(1).WillOnce(Return(10));
    EXPECT_CALL(*mock, vendor()).Times(1).WillOnce(Return("11"));
    EXPECT_CALL(*mock, install_time()).Times(1).WillOnce(Return("2022/01/13 14:48:58"));
    EXPECT_CALL(*mock, multiarch()).Times(1).WillOnce(Return("13"));

    EXPECT_NO_THROW(std::make_unique<BSDPackageImpl>(mock)->buildPackageData(packages));
    EXPECT_EQ("1", packages.at("name").get_ref<const std::string&>());
    EXPECT_EQ("2", packages.at("version_").get_ref<const std::string&>());
    EXPECT_EQ("3", packages.at("category").get_ref<const std::string&>());
    EXPECT_EQ("4", packages.at("description").get_ref<const std::string&>());
    EXPECT_EQ("5", packages.at("architecture").get_ref<const std::string&>());
    EXPECT_EQ("6", packages.at("type").get_ref<const std::string&>());
    EXPECT_EQ("7", packages.at("source").get_ref<const std::string&>());
    EXPECT_EQ("8", packages.at("path").get_ref<const std::string&>());
    EXPECT_EQ("9", packages.at("priority").get_ref<const std::string&>());
    EXPECT_EQ(10, packages.at("size").get<const int>());
    EXPECT_EQ("11", packages.at("vendor").get_ref<const std::string&>());
    EXPECT_EQ("2022-01-13T14:48:58.000Z", packages.at("installed").get_ref<const std::string&>());
    EXPECT_EQ("13", packages.at("multiarch").get_ref<const std::string&>());
}

// The registry stores no size and `location` points at a compressed archive, so the size is
// summed from the port's own file list. Fixtures: bin/tool (100 bytes) + lib/data.bin (250).
TEST_F(SysInfoMacPackagesTest, macPortsSizeSumsTheRegistryFileList)
{
    char cwd[PATH_MAX] {};
    ASSERT_NE(::getcwd(cwd, sizeof(cwd)), nullptr);
    const std::string base {std::string(cwd) + "/input_files/Cellar/testpkg/1.0.0"};

    // char(1) is what the query uses to join the paths, because a path may contain a newline.
    const std::string paths
    {
        base + "/bin/tool" + '\x01' + base + "/lib/data.bin" + '\x01' +
        base + "/does/not/exist"
    };

    auto mockStatement { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement, columnsCount()).WillOnce(Return(6));

    auto mockColumn_1 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_1, value(An<const std::string&>())).WillOnce(Return("testpkg"));
    auto mockColumn_2 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_2, value(An<const std::string&>())).WillOnce(Return("1.0.0"));
    auto mockColumn_3 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_3, value(An<const int64_t&>())).WillOnce(Return(1690831043));
    auto mockColumn_4 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_4, value(An<const std::string&>()))
    .WillOnce(Return("/opt/local/var/macports/software/testpkg/testpkg-1.0.0.darwin_25.arm64.tbz2"));
    auto mockColumn_5 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_5, value(An<const std::string&>())).WillOnce(Return("arm64"));
    auto mockColumn_6 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_6, value(An<const std::string&>())).WillOnce(Return(paths));

    EXPECT_CALL(*mockColumn_1, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_2, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_3, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_4, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_5, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_6, hasValue()).WillOnce(Return(true));

    EXPECT_CALL(*mockStatement, column(0)).WillOnce(Return(ByMove(std::move(mockColumn_1))));
    EXPECT_CALL(*mockStatement, column(1)).WillOnce(Return(ByMove(std::move(mockColumn_2))));
    EXPECT_CALL(*mockStatement, column(2)).WillOnce(Return(ByMove(std::move(mockColumn_3))));
    EXPECT_CALL(*mockStatement, column(3)).WillOnce(Return(ByMove(std::move(mockColumn_4))));
    EXPECT_CALL(*mockStatement, column(4)).WillOnce(Return(ByMove(std::move(mockColumn_5))));
    EXPECT_CALL(*mockStatement, column(5)).WillOnce(Return(ByMove(std::move(mockColumn_6))));

    MacportsWrapper macportsMock(*mockStatement);

    // A path recorded in the registry but since removed contributes nothing rather than throwing,
    // and the archive in `location` is never measured.
    EXPECT_EQ(macportsMock.size(), 350);
}

TEST_F(SysInfoMacPackagesTest, macPortsSizeIsZeroWhenTheFileListIsAbsent)
{
    auto mockStatement { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement, columnsCount()).WillOnce(Return(6));

    auto mockColumn_1 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_1, value(An<const std::string&>())).WillOnce(Return("testpkg"));
    auto mockColumn_2 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_2, value(An<const std::string&>())).WillOnce(Return("1.0.0"));
    auto mockColumn_3 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_3, value(An<const int64_t&>())).WillOnce(Return(1690831043));
    auto mockColumn_4 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_4, value(An<const std::string&>())).WillOnce(Return("/opt/local/x.tbz2"));
    auto mockColumn_5 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_5, value(An<const std::string&>())).WillOnce(Return("arm64"));
    auto mockColumn_6 { std::make_unique<MockColumn>() };

    EXPECT_CALL(*mockColumn_1, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_2, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_3, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_4, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_5, hasValue()).WillOnce(Return(true));
    // A port with no active files, which group_concat returns as NULL.
    EXPECT_CALL(*mockColumn_6, hasValue()).WillOnce(Return(false));

    EXPECT_CALL(*mockStatement, column(0)).WillOnce(Return(ByMove(std::move(mockColumn_1))));
    EXPECT_CALL(*mockStatement, column(1)).WillOnce(Return(ByMove(std::move(mockColumn_2))));
    EXPECT_CALL(*mockStatement, column(2)).WillOnce(Return(ByMove(std::move(mockColumn_3))));
    EXPECT_CALL(*mockStatement, column(3)).WillOnce(Return(ByMove(std::move(mockColumn_4))));
    EXPECT_CALL(*mockStatement, column(4)).WillOnce(Return(ByMove(std::move(mockColumn_5))));
    EXPECT_CALL(*mockStatement, column(5)).WillOnce(Return(ByMove(std::move(mockColumn_6))));

    MacportsWrapper macportsMock(*mockStatement);

    EXPECT_EQ(macportsMock.size(), 0);
}

TEST_F(SysInfoMacPackagesTest, macPortsValidData)
{
    auto mockStatement { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement, columnsCount()).WillOnce(Return(6));

    auto mockColumn_1 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_1, value(An<const std::string&>()))
    .WillOnce(Return("neovim"));
    auto mockColumn_2 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_2, value(An<const std::string&>()))
    .WillOnce(Return("0.8.1"));
    auto mockColumn_3 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_3, value(An<const int64_t&>()))
    .WillOnce(Return(1690831043));
    auto mockColumn_4 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_4, value(An<const std::string&>()))
    .WillOnce(Return("/opt/local/var/macports/software/neovim/neovim-0.8.1.tgz"));
    auto mockColumn_6 {std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_6, hasValue()).WillOnce(Return(false));
    auto mockColumn_5 {std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_5, value(An<const std::string&>()))
    .WillOnce(Return("x86_64"));

    EXPECT_CALL(*mockColumn_1, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_2, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_3, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_4, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_5, hasValue()).WillOnce(Return(true));

    EXPECT_CALL(*mockStatement, column(0)).WillOnce(Return(ByMove(std::move(mockColumn_1))));
    EXPECT_CALL(*mockStatement, column(1)).WillOnce(Return(ByMove(std::move(mockColumn_2))));
    EXPECT_CALL(*mockStatement, column(2)).WillOnce(Return(ByMove(std::move(mockColumn_3))));
    EXPECT_CALL(*mockStatement, column(3)).WillOnce(Return(ByMove(std::move(mockColumn_4))));
    EXPECT_CALL(*mockStatement, column(4)).WillOnce(Return(ByMove(std::move(mockColumn_5))));
    EXPECT_CALL(*mockStatement, column(5)).WillOnce(Return(ByMove(std::move(mockColumn_6))));

    MacportsWrapper macportsMock(*mockStatement);

    EXPECT_EQ(macportsMock.name(), "neovim");
    EXPECT_EQ(macportsMock.version(), "0.8.1");
    EXPECT_FALSE(macportsMock.install_time().empty());
    EXPECT_EQ(macportsMock.location(), "/opt/local/var/macports/software/neovim/neovim-0.8.1.tgz");
    EXPECT_EQ(macportsMock.architecture(), "x86_64");
}

TEST_F(SysInfoMacPackagesTest, macPortsValidDataEmptyFields)
{
    auto mockStatement { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement, columnsCount()).WillOnce(Return(6));

    auto mockColumn_1 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_1, value(An<const std::string&>()))
    .WillOnce(Return("neovim"));
    auto mockColumn_2 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_2, value(An<const std::string&>()))
    .WillOnce(Return(""));
    auto mockColumn_3 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_3, value(An<const int64_t&>()))
    .WillOnce(Return(0));
    auto mockColumn_4 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_4, value(An<const std::string&>()))
    .WillOnce(Return(""));
    auto mockColumn_6 {std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_6, hasValue()).WillOnce(Return(false));
    auto mockColumn_5 {std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_5, value(An<const std::string&>()))
    .WillOnce(Return(""));

    EXPECT_CALL(*mockColumn_1, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_2, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_3, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_4, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_5, hasValue()).WillOnce(Return(true));

    EXPECT_CALL(*mockStatement, column(0)).WillOnce(Return(ByMove(std::move(mockColumn_1))));
    EXPECT_CALL(*mockStatement, column(1)).WillOnce(Return(ByMove(std::move(mockColumn_2))));
    EXPECT_CALL(*mockStatement, column(2)).WillOnce(Return(ByMove(std::move(mockColumn_3))));
    EXPECT_CALL(*mockStatement, column(3)).WillOnce(Return(ByMove(std::move(mockColumn_4))));
    EXPECT_CALL(*mockStatement, column(4)).WillOnce(Return(ByMove(std::move(mockColumn_5))));
    EXPECT_CALL(*mockStatement, column(5)).WillOnce(Return(ByMove(std::move(mockColumn_6))));

    MacportsWrapper macportsMock(*mockStatement);

    EXPECT_EQ(macportsMock.name(), "neovim");
    // Empty string fields are replaced with space.
    EXPECT_EQ(macportsMock.version(), " ");
    EXPECT_FALSE(macportsMock.install_time().empty());
    EXPECT_EQ(macportsMock.location(), " ");
    EXPECT_EQ(macportsMock.architecture(), " ");
}

TEST_F(SysInfoMacPackagesTest, macPortsValidDataEmptyName)
{
    auto mockStatement { std::make_unique<MockStatement>() };
    EXPECT_CALL(*mockStatement, columnsCount()).WillOnce(Return(6));

    auto mockColumn_1 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_1, value(An<const std::string&>()))
    .WillOnce(Return(""));
    auto mockColumn_2 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_2, value(An<const std::string&>()))
    .WillOnce(Return("0.8.1"));
    auto mockColumn_3 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_3, value(An<const int64_t&>()))
    .WillOnce(Return(1690831043));
    auto mockColumn_4 { std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_4, value(An<const std::string&>()))
    .WillOnce(Return("/opt/local/var/macports/software/neovim/neovim-0.8.1.tgz"));
    auto mockColumn_6 {std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_6, hasValue()).WillOnce(Return(false));
    auto mockColumn_5 {std::make_unique<MockColumn>() };
    EXPECT_CALL(*mockColumn_5, value(An<const std::string&>()))
    .WillOnce(Return("x86_64"));

    EXPECT_CALL(*mockColumn_1, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_2, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_3, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_4, hasValue()).WillOnce(Return(true));
    EXPECT_CALL(*mockColumn_5, hasValue()).WillOnce(Return(true));

    EXPECT_CALL(*mockStatement, column(0)).WillOnce(Return(ByMove(std::move(mockColumn_1))));
    EXPECT_CALL(*mockStatement, column(1)).WillOnce(Return(ByMove(std::move(mockColumn_2))));
    EXPECT_CALL(*mockStatement, column(2)).WillOnce(Return(ByMove(std::move(mockColumn_3))));
    EXPECT_CALL(*mockStatement, column(3)).WillOnce(Return(ByMove(std::move(mockColumn_4))));
    EXPECT_CALL(*mockStatement, column(4)).WillOnce(Return(ByMove(std::move(mockColumn_5))));
    EXPECT_CALL(*mockStatement, column(5)).WillOnce(Return(ByMove(std::move(mockColumn_6))));

    MacportsWrapper macportsMock(*mockStatement);

    // Packages with empty string names are discarded.
    EXPECT_EQ(macportsMock.name(), "");
}

namespace
{
    void writeAppInfoPlist(const std::string& infoPlistPath, const std::string& bundleName)
    {
        std::filesystem::create_directories(std::filesystem::path(infoPlistPath).parent_path());
        std::ofstream out { infoPlistPath, std::ios::trunc };
        out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            << "<plist version=\"1.0\">\n"
            << "<dict>\n"
            << "  <key>CFBundleName</key>\n"
            << "  <string>" << bundleName << "</string>\n"
            << "</dict>\n"
            << "</plist>\n";
    }
}

class GetPackagesFromPathTest : public ::testing::Test
{
    protected:
        std::string m_tempDir;

        void SetUp() override
        {
            char tmpl[] = "/tmp/getpkgpath_test_XXXXXX";

            if (const char* dir = ::mkdtemp(tmpl))
            {
                m_tempDir = dir;
            }
        }

        void TearDown() override
        {
            if (!m_tempDir.empty())
            {
                std::filesystem::remove_all(m_tempDir);
            }
        }
};

TEST_F(GetPackagesFromPathTest, FindsAnAppOneLevelDeepInAVendorSubfolder)
{
    writeAppInfoPlist(m_tempDir + "/Vendor/App.app/Contents/Info.plist", "VendorApp");

    std::vector<nlohmann::json> found;
    getPackagesFromPath(m_tempDir, PKG, [&found](nlohmann::json & package)
    {
        found.push_back(package);
    }, true);

    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].at("name").get<std::string>(), "VendorApp");
    EXPECT_EQ(found[0].at("path").get<std::string>(), m_tempDir + "/Vendor/App.app/Contents/Info.plist");
}

TEST_F(GetPackagesFromPathTest, SkipsASubfolderStartingWithADot)
{
    writeAppInfoPlist(m_tempDir + "/.HiddenVendor/App.app/Contents/Info.plist", "HiddenApp");

    std::vector<nlohmann::json> found;
    getPackagesFromPath(m_tempDir, PKG, [&found](nlohmann::json & package)
    {
        found.push_back(package);
    }, true);

    EXPECT_TRUE(found.empty());
}

TEST_F(GetPackagesFromPathTest, RejectsASymlinkedAppEntryWhenRejectingSymlinks)
{
    writeAppInfoPlist(m_tempDir + "/Real.app/Contents/Info.plist", "RealApp");
    ASSERT_EQ(0, ::symlink((m_tempDir + "/Real.app").c_str(), (m_tempDir + "/Linked.app").c_str()));

    std::vector<nlohmann::json> found;
    getPackagesFromPath(m_tempDir, PKG, [&found](nlohmann::json & package)
    {
        found.push_back(package);
    }, true);

    // Only the real bundle is reported; the symlinked alias to the same bundle is not,
    // so the same install is not double-counted under a second path.
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].at("path").get<std::string>(), m_tempDir + "/Real.app/Contents/Info.plist");
}

TEST_F(GetPackagesFromPathTest, RejectsASymlinkedVendorSubfolderWhenRejectingSymlinks)
{
    writeAppInfoPlist(m_tempDir + "/RealVendor/App.app/Contents/Info.plist", "RealVendorApp");
    ASSERT_EQ(0, ::symlink((m_tempDir + "/RealVendor").c_str(), (m_tempDir + "/VendorLink").c_str()));

    std::vector<nlohmann::json> found;
    getPackagesFromPath(m_tempDir, PKG, [&found](nlohmann::json & package)
    {
        found.push_back(package);
    }, true);

    // The app is found once, through the real vendor folder; the symlinked alias to that
    // same folder is not descended into, so it is not reported a second time.
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].at("path").get<std::string>(), m_tempDir + "/RealVendor/App.app/Contents/Info.plist");
}

// Regression test for the Safari cryptex case: a fixed, root-owned root (rejectSymlinks=false)
// must still follow a symlinked app entry, exactly like /Applications/Safari.app pointing into
// /System/Cryptexes/App since macOS 13. Confirmed against real hardware: without this,
// Safari silently disappeared from the inventory.
TEST_F(GetPackagesFromPathTest, FollowsASymlinkedAppEntryWhenNotRejectingSymlinks)
{
    writeAppInfoPlist(m_tempDir + "/Real.app/Contents/Info.plist", "RealApp");
    ASSERT_EQ(0, ::symlink((m_tempDir + "/Real.app").c_str(), (m_tempDir + "/Linked.app").c_str()));

    std::vector<nlohmann::json> found;
    getPackagesFromPath(m_tempDir, PKG, [&found](nlohmann::json & package)
    {
        found.push_back(package);
    }, false);

    ASSERT_EQ(found.size(), 2u);
}
