#include "package_scanner.hpp"

#include <unistd.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

using wazuh::container_baseline::DetectPackageDbs;
using wazuh::container_baseline::PackageBaselineRow;
using wazuh::container_baseline::PackageDbFormat;
using wazuh::container_baseline::ParseApkBlock;

TEST(ParseApkBlock, ParsesTypicalAlpineEntry)
{
    const std::vector<std::string> block = {
        "C:Q1qKcZ+j23xssAXmgQhkOO8dHnbWw=",
        "P:musl",
        "V:1.2.4-r2",
        "A:x86_64",
        "S:383152",
        "I:622592",
        "T:the musl c library (libc) implementation",
        "U:https://musl.libc.org/",
        "L:MIT",
        "o:musl",
        "m:Timo Teräs <timo.teras@iki.fi>",
        "t:1689211875",
    };

    PackageBaselineRow row;
    ASSERT_TRUE(ParseApkBlock(block, row));
    EXPECT_EQ(row.name, "musl");
    EXPECT_EQ(row.version, "1.2.4-r2");
    EXPECT_EQ(row.architecture, "x86_64");
    EXPECT_EQ(row.description, "the musl c library (libc) implementation");
    EXPECT_EQ(row.size, 622592);
    EXPECT_EQ(row.vendor, "Timo Teräs <timo.teras@iki.fi>");
    EXPECT_EQ(row.source, "musl");
    EXPECT_EQ(row.format, "apk");
}

TEST(ParseApkBlock, RejectsBlockWithoutName)
{
    const std::vector<std::string> block = {"V:1.0.0", "A:x86_64"};
    PackageBaselineRow row;
    EXPECT_FALSE(ParseApkBlock(block, row));
}

TEST(ParseApkBlock, IgnoresMalformedLines)
{
    const std::vector<std::string> block = {"P:busybox", "V", "", "X"};
    PackageBaselineRow row;
    ASSERT_TRUE(ParseApkBlock(block, row));
    EXPECT_EQ(row.name, "busybox");
    EXPECT_TRUE(row.version.empty());
}

TEST(ParseApkBlock, NonNumericSizeYieldsZero)
{
    const std::vector<std::string> block = {"P:busybox", "I:notanumber"};
    PackageBaselineRow row;
    ASSERT_TRUE(ParseApkBlock(block, row));
    EXPECT_EQ(row.size, 0);
}

class DetectPackageDbsTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        char tmpl[] = "/tmp/cbaseline_pkg_test_XXXXXX";
        root_ = ::mkdtemp(tmpl);
        ASSERT_FALSE(root_.empty());
    }

    void TearDown() override
    {
        std::filesystem::remove_all(root_);
    }

    void Touch(const std::string& rel_path)
    {
        const auto full = std::filesystem::path{root_} / rel_path.substr(1);
        std::filesystem::create_directories(full.parent_path());
        std::ofstream{full} << "";
    }

    std::string root_;
};

TEST_F(DetectPackageDbsTest, EmptyRootfsHasNoDatabases)
{
    EXPECT_TRUE(DetectPackageDbs(root_).empty());
}

TEST_F(DetectPackageDbsTest, DetectsDpkg)
{
    Touch("/var/lib/dpkg/status");
    const auto found = DetectPackageDbs(root_);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0], PackageDbFormat::Dpkg);
}

TEST_F(DetectPackageDbsTest, DetectsDistrolessStatusD)
{
    Touch("/var/lib/dpkg/status.d/base-files");
    const auto found = DetectPackageDbs(root_);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0], PackageDbFormat::DpkgStatusD);
}

TEST_F(DetectPackageDbsTest, ClassicStatusWinsOverStatusD)
{
    Touch("/var/lib/dpkg/status");
    Touch("/var/lib/dpkg/status.d/base-files");
    const auto found = DetectPackageDbs(root_);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0], PackageDbFormat::Dpkg);
}

TEST_F(DetectPackageDbsTest, DetectsApk)
{
    Touch("/lib/apk/db/installed");
    const auto found = DetectPackageDbs(root_);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0], PackageDbFormat::Apk);
}

TEST_F(DetectPackageDbsTest, DetectsRpmSqlite)
{
    Touch("/var/lib/rpm/rpmdb.sqlite");
    const auto found = DetectPackageDbs(root_);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0], PackageDbFormat::RpmSqlite);
}

TEST_F(DetectPackageDbsTest, DetectsRpmBdb)
{
    Touch("/var/lib/rpm/Packages");
    const auto found = DetectPackageDbs(root_);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0], PackageDbFormat::RpmBdb);
}

TEST_F(DetectPackageDbsTest, SqliteWinsOverStaleBdb)
{
    Touch("/var/lib/rpm/rpmdb.sqlite");
    Touch("/var/lib/rpm/Packages");
    const auto found = DetectPackageDbs(root_);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0], PackageDbFormat::RpmSqlite);
}

TEST_F(DetectPackageDbsTest, DetectsSysimageRpmLocation)
{
    Touch("/usr/lib/sysimage/rpm/rpmdb.sqlite");
    const auto found = DetectPackageDbs(root_);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0], PackageDbFormat::RpmSqlite);
}

TEST(ScanContainerPackages, MissingRootfsYieldsEmpty)
{
    EXPECT_TRUE(wazuh::container_baseline::ScanContainerPackages(-1).empty());
}
