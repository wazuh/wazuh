/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * July 20, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "pkgWrapper_test.h"
#include "packages/packageMac.h"
#include "packages/pkgWrapper.h"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <limits.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <iostream>

namespace
{
    std::string currentWorkingDirectory()
    {
        char path[PATH_MAX];

        if (::getcwd(path, sizeof(path)) == nullptr)
        {
            throw std::runtime_error("getcwd failed");
        }

        return path;
    }
}

void PKGWrapperTest::SetUp()
{
    PKGWrapper::setReceiptLivenessChecker(
        [](const std::string&, const std::string&)
    {
        return true;
    });

    // Create a unique temp directory for tests that write files.
    char tmpl[] = "/tmp/pkgtest_XXXXXX";

    if (const char* dir = ::mkdtemp(tmpl))
    {
        m_tempDir = dir;
    }
};

void PKGWrapperTest::TearDown()
{
    PKGWrapper::resetReceiptLivenessChecker();

    // Remove any leftover files and the temp directory itself.
    if (!m_tempDir.empty())
    {
        const std::string cmd { "rm -rf " + m_tempDir };
        ::system(cmd.c_str());
    }
};

using ::testing::_;
using ::testing::Return;

TEST_F(PKGWrapperTest, LongVersion)
{
    std::string inputPath;
    inputPath += currentWorkingDirectory();
    inputPath += "/input_files";
    std::string package { "PKGWrapperTest_LongVersion.app" };

    struct PackageContext ctx
    {
        inputPath, package, ""
    };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));
    EXPECT_EQ(wrapper->name(), "Opera");
    EXPECT_EQ(wrapper->version(), "100.0.4815.54");
    EXPECT_EQ(wrapper->groups(), "public.app-category.productivity");
    EXPECT_EQ(wrapper->description(), "com.operasoftware.Opera");
    EXPECT_EQ(wrapper->architecture(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->format(), "pkg");
    EXPECT_EQ(wrapper->osPatch(), "");
    EXPECT_EQ(wrapper->source(), "utilities");
    EXPECT_EQ(wrapper->location(), inputPath + "/" + package + "/" + APP_INFO_PATH);
    EXPECT_EQ(wrapper->vendor(), "Operasoftware");
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, ShortVersion)
{
    std::string inputPath;
    inputPath += currentWorkingDirectory();
    inputPath += "/input_files";
    std::string package { "PKGWrapperTest_ShortVersion.app" };

    struct PackageContext ctx
    {
        inputPath, package, ""
    };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));
    EXPECT_EQ(wrapper->name(), "Opera");
    EXPECT_EQ(wrapper->version(), "100.0");
    EXPECT_EQ(wrapper->groups(), "public.app-category.productivity");
    EXPECT_EQ(wrapper->description(), "com.operasoftware.Opera");
    EXPECT_EQ(wrapper->architecture(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->format(), "pkg");
    EXPECT_EQ(wrapper->osPatch(), "");
    EXPECT_EQ(wrapper->source(), "utilities");
    EXPECT_EQ(wrapper->location(), inputPath + "/" + package + "/" + APP_INFO_PATH);
    EXPECT_EQ(wrapper->vendor(), "Operasoftware");
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, NameDifferentExecutable)
{
    std::string inputPath;
    inputPath += currentWorkingDirectory();
    inputPath += "/input_files";
    std::string package { "PKGWrapperTest_NameDifferentExecutable.app" };

    struct PackageContext ctx
    {
        inputPath, package, ""
    };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));
    EXPECT_EQ(wrapper->name(), "OperaName");
    EXPECT_EQ(wrapper->version(), "100.0.4815.54");
    EXPECT_EQ(wrapper->groups(), "public.app-category.productivity");
    EXPECT_EQ(wrapper->description(), "com.operasoftware.Opera");
    EXPECT_EQ(wrapper->architecture(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->format(), "pkg");
    EXPECT_EQ(wrapper->osPatch(), "");
    EXPECT_EQ(wrapper->source(), "utilities");
    EXPECT_EQ(wrapper->location(), inputPath + "/" + package + "/" + APP_INFO_PATH);
    EXPECT_EQ(wrapper->vendor(), "Operasoftware");
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, NameFirst)
{
    std::string inputPath;
    inputPath += currentWorkingDirectory();
    inputPath += "/input_files";
    std::string package { "PKGWrapperTest_NameFirst.app" };

    struct PackageContext ctx
    {
        inputPath, package, ""
    };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));
    EXPECT_EQ(wrapper->name(), "OperaName");
    EXPECT_EQ(wrapper->version(), "100.0.4815.54");
    EXPECT_EQ(wrapper->groups(), "public.app-category.productivity");
    EXPECT_EQ(wrapper->description(), "com.operasoftware.Opera");
    EXPECT_EQ(wrapper->architecture(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->format(), "pkg");
    EXPECT_EQ(wrapper->osPatch(), "");
    EXPECT_EQ(wrapper->source(), "utilities");
    EXPECT_EQ(wrapper->location(), inputPath + "/" + package + "/" + APP_INFO_PATH);
    EXPECT_EQ(wrapper->vendor(), "Operasoftware");
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, NoNameButExecutable)
{
    std::string inputPath;
    inputPath += currentWorkingDirectory();
    inputPath += "/input_files";
    std::string package { "PKGWrapperTest_NoNameButExecutable.app" };

    struct PackageContext ctx
    {
        inputPath, package, ""
    };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));
    EXPECT_EQ(wrapper->name(), "Opera");
    EXPECT_EQ(wrapper->version(), "100.0.4815.54");
    EXPECT_EQ(wrapper->groups(), "public.app-category.productivity");
    EXPECT_EQ(wrapper->description(), "com.operasoftware.Opera");
    EXPECT_EQ(wrapper->architecture(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->format(), "pkg");
    EXPECT_EQ(wrapper->osPatch(), "");
    EXPECT_EQ(wrapper->source(), "utilities");
    EXPECT_EQ(wrapper->location(), inputPath + "/" + package + "/" + APP_INFO_PATH);
    EXPECT_EQ(wrapper->vendor(), "Operasoftware");
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, NoNameNoExecutable)
{
    std::string inputPath;
    inputPath += currentWorkingDirectory();
    inputPath += "/input_files";
    std::string package { "PKGWrapperTest_NoNameNoExecutable.app" };

    struct PackageContext ctx
    {
        inputPath, package, ""
    };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));
    EXPECT_EQ(wrapper->name(), "");
    EXPECT_EQ(wrapper->version(), "100.0.4815.54");
    EXPECT_EQ(wrapper->groups(), "public.app-category.productivity");
    EXPECT_EQ(wrapper->description(), "com.operasoftware.Opera");
    EXPECT_EQ(wrapper->architecture(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->format(), "pkg");
    EXPECT_EQ(wrapper->osPatch(), "");
    EXPECT_EQ(wrapper->source(), "utilities");
    EXPECT_EQ(wrapper->location(), inputPath + "/" + package + "/" + APP_INFO_PATH);
    EXPECT_EQ(wrapper->vendor(), "Operasoftware");
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, NoVersion)
{
    std::string inputPath;
    inputPath += currentWorkingDirectory();
    inputPath += "/input_files";
    std::string package { "PKGWrapperTest_NoVersion.app" };

    struct PackageContext ctx
    {
        inputPath, package, ""
    };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));
    EXPECT_EQ(wrapper->name(), "Opera");
    EXPECT_EQ(wrapper->version(), " ");
    EXPECT_EQ(wrapper->groups(), "public.app-category.productivity");
    EXPECT_EQ(wrapper->description(), "com.operasoftware.Opera");
    EXPECT_EQ(wrapper->architecture(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->format(), "pkg");
    EXPECT_EQ(wrapper->osPatch(), "");
    EXPECT_EQ(wrapper->source(), "utilities");
    EXPECT_EQ(wrapper->location(), inputPath + "/" + package + "/" + APP_INFO_PATH);
    EXPECT_EQ(wrapper->vendor(), "Operasoftware");
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, NoGroups)
{
    std::string inputPath;
    inputPath += currentWorkingDirectory();
    inputPath += "/input_files";
    std::string package { "PKGWrapperTest_NoGroups.app" };

    struct PackageContext ctx
    {
        inputPath, package, ""
    };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));
    EXPECT_EQ(wrapper->name(), "Opera");
    EXPECT_EQ(wrapper->version(), "100.0.4815.54");
    EXPECT_EQ(wrapper->groups(), " ");
    EXPECT_EQ(wrapper->description(), "com.operasoftware.Opera");
    EXPECT_EQ(wrapper->architecture(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->format(), "pkg");
    EXPECT_EQ(wrapper->osPatch(), "");
    EXPECT_EQ(wrapper->source(), "utilities");
    EXPECT_EQ(wrapper->location(), inputPath + "/" + package + "/" + APP_INFO_PATH);
    EXPECT_EQ(wrapper->vendor(), "Operasoftware");
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, NoDescription)
{
    std::string inputPath;
    inputPath += currentWorkingDirectory();
    inputPath += "/input_files";
    std::string package { "PKGWrapperTest_NoDescription.app" };

    struct PackageContext ctx
    {
        inputPath, package, ""
    };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));
    EXPECT_EQ(wrapper->name(), "Opera");
    EXPECT_EQ(wrapper->version(), "100.0.4815.54");
    EXPECT_EQ(wrapper->groups(), "public.app-category.productivity");
    EXPECT_EQ(wrapper->description(), " ");
    EXPECT_EQ(wrapper->architecture(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->format(), "pkg");
    EXPECT_EQ(wrapper->osPatch(), "");
    EXPECT_EQ(wrapper->source(), "utilities");
    EXPECT_EQ(wrapper->location(), inputPath + "/" + package + "/" + APP_INFO_PATH);
    EXPECT_EQ(wrapper->vendor(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, NoVendor)
{
    std::string inputPath;
    inputPath += currentWorkingDirectory();
    inputPath += "/input_files";
    std::string package { "PKGWrapperTest_NoVendor.app" };

    struct PackageContext ctx
    {
        inputPath, package, ""
    };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));
    EXPECT_EQ(wrapper->name(), "Opera");
    EXPECT_EQ(wrapper->version(), "100.0.4815.54");
    EXPECT_EQ(wrapper->groups(), "public.app-category.productivity");
    EXPECT_EQ(wrapper->description(), "description_text");
    EXPECT_EQ(wrapper->architecture(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->format(), "pkg");
    EXPECT_EQ(wrapper->osPatch(), "");
    EXPECT_EQ(wrapper->source(), "utilities");
    EXPECT_EQ(wrapper->location(), inputPath + "/" + package + "/" + APP_INFO_PATH);
    EXPECT_EQ(wrapper->vendor(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, pkgVersionXML)
{
    std::string inputPath;
    inputPath += currentWorkingDirectory();
    inputPath += "/input_files";
    std::string package { "com.wazuh.pkg.wazuh-agent.plist" };

    struct PackageContext ctx
    {
        inputPath, package, ""
    };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));
    EXPECT_EQ(wrapper->name(), "wazuh-agent");
    EXPECT_EQ(wrapper->version(), "4.10.1");
    EXPECT_EQ(wrapper->groups(), " ");
    EXPECT_EQ(wrapper->description(), "com.wazuh.pkg.wazuh-agent");
    EXPECT_EQ(wrapper->architecture(), " ");
    EXPECT_EQ(wrapper->format(), "pkg");
    EXPECT_EQ(wrapper->osPatch(), "");
    EXPECT_EQ(wrapper->source(), "receipts");
    EXPECT_EQ(wrapper->location(), inputPath + "/" + package);
    EXPECT_EQ(wrapper->vendor(), "Wazuh");
    EXPECT_EQ(wrapper->priority(), " ");
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), "2024-11-07T08:58:38Z");
    EXPECT_EQ(wrapper->multiarch(), " ");
}

TEST_F(PKGWrapperTest, pkgVersionBin)
{
    std::string inputPath;
    inputPath += currentWorkingDirectory();
    inputPath += "/input_files";
    std::string package { "us.zoom.pkg.videomeeting.plist" };

    struct PackageContext ctx
    {
        inputPath, package, ""
    };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));
    EXPECT_EQ(wrapper->name(), "videomeeting");
    EXPECT_EQ(wrapper->version(), "6.2.6.41824");
    EXPECT_EQ(wrapper->groups(), " ");
    EXPECT_EQ(wrapper->description(), "us.zoom.pkg.videomeeting");
    EXPECT_EQ(wrapper->architecture(), " ");
    EXPECT_EQ(wrapper->format(), "pkg");
    EXPECT_EQ(wrapper->osPatch(), "");
    EXPECT_EQ(wrapper->source(), "receipts");
    EXPECT_EQ(wrapper->location(), inputPath + "/" + package);
    EXPECT_EQ(wrapper->vendor(), "Zoom");
    EXPECT_EQ(wrapper->priority(), " ");
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), "2024-11-08T11:44:04Z");
    EXPECT_EQ(wrapper->multiarch(), " ");
}

TEST_F(PKGWrapperTest, pkgVersionLong)
{
    std::string inputPath;
    inputPath += currentWorkingDirectory();
    inputPath += "/input_files";
    std::string package { "org.R-project.x86_64.R.GUI.pkg.plist" };

    struct PackageContext ctx
    {
        inputPath, package, ""
    };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));
    EXPECT_EQ(wrapper->name(), "R.GUI");
    EXPECT_EQ(wrapper->version(), "1.81");
    EXPECT_EQ(wrapper->groups(), " ");
    EXPECT_EQ(wrapper->description(), "org.R-project.x86_64.R.GUI.pkg");
    EXPECT_EQ(wrapper->architecture(), " ");
    EXPECT_EQ(wrapper->format(), "pkg");
    EXPECT_EQ(wrapper->osPatch(), "");
    EXPECT_EQ(wrapper->source(), "receipts");
    EXPECT_EQ(wrapper->location(), inputPath + "/" + package);
    EXPECT_EQ(wrapper->vendor(), "R-project");
    EXPECT_EQ(wrapper->priority(), " ");
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), "2024-11-13T10:59:10Z");
    EXPECT_EQ(wrapper->multiarch(), " ");
}

namespace
{
    // Minimal helper to write a synthetic XML receipt next to the test
    // executable, mirroring the layout sysInfoMac.cpp passes to PKGWrapper.
    void writeReceiptPlist(const std::string& path,
                           const std::string& pkgId,
                           const std::string& version,
                           const std::string& installDate,
                           const std::string& installPrefixPath = "")
    {
        std::ofstream out { path, std::ios::trunc };
        out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
            << "<plist version=\"1.0\">\n"
            << "<dict>\n"
            << "  <key>PackageIdentifier</key><string>" << pkgId << "</string>\n"
            << "  <key>PackageVersion</key><string>" << version << "</string>\n"
            << "  <key>InstallDate</key><string>" << installDate << "</string>\n";

        if (!installPrefixPath.empty())
        {
            out << "  <key>InstallPrefixPath</key><string>" << installPrefixPath << "</string>\n";
        }

        out << "</dict>\n"
            << "</plist>\n";
    }
}

TEST_F(PKGWrapperTest, ReceiptKeptWhenLivenessCheckerReturnsTrue)
{
    // Override the SetUp default with an explicit always-live checker that
    // also records the arguments it received, so we can confirm wiring.
    std::string seenPath;
    std::string seenPrefix;
    PKGWrapper::setReceiptLivenessChecker(
        [&](const std::string & p, const std::string & prefix)
    {
        seenPath = p;
        seenPrefix = prefix;
        return true;
    });

    const std::string dir { currentWorkingDirectory() + "/input_files" };
    const std::string package { "com.wazuh.pkg.wazuh-agent.plist" };
    PackageContext ctx { dir, package, "" };

    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));
    EXPECT_EQ(wrapper->name(), "wazuh-agent");
    EXPECT_EQ(wrapper->location(), dir + "/" + package);

    // The wrapper must have asked the checker about this exact receipt.
    EXPECT_EQ(seenPath, dir + "/" + package);
    // No InstallPrefixPath in the fixture → default "/".
    EXPECT_EQ(seenPrefix, "/");
}

TEST_F(PKGWrapperTest, ReceiptDroppedWhenLivenessCheckerReturnsFalse)
{
    PKGWrapper::setReceiptLivenessChecker(
        [](const std::string&, const std::string&)
    {
        return false;
    });

    const std::string dir { currentWorkingDirectory() + "/input_files" };
    const std::string package { "com.wazuh.pkg.wazuh-agent.plist" };
    PackageContext ctx { dir, package, "" };

    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));

    // Empty name is the contract that tells sysInfoMac.cpp to skip this row.
    EXPECT_EQ(wrapper->name(), "");
    // The other fields are still parsed (we only clear the name) — the caller
    // never reads them in this case.
    EXPECT_EQ(wrapper->source(), "receipts");
}

TEST_F(PKGWrapperTest, JavaResidualReceiptIsDroppedByDefaultChecker)
{
    // Reproduces the bug exactly: synthetic com.oracle.jre receipt with
    // version 1.1, no companion BOM. The default checker must classify it
    // as dead.
    PKGWrapper::resetReceiptLivenessChecker();

    const std::string plistName { "com.oracle.jre.plist" };
    const std::string plistPath { m_tempDir + "/" + plistName };
    writeReceiptPlist(plistPath, "com.oracle.jre", "1.1", "2022-08-16T15:30:00Z");

    PackageContext ctx { m_tempDir, plistName, "" };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));

    // No BOM → default checker returns false → wrapper drops the entry.
    EXPECT_EQ(wrapper->name(), "");
}

TEST_F(PKGWrapperTest, ReceiptWithoutBomIsDroppedByDefaultChecker)
{
    PKGWrapper::resetReceiptLivenessChecker();

    const std::string plistName { "no_bom.plist" };
    const std::string plistPath { m_tempDir + "/" + plistName };
    writeReceiptPlist(plistPath, "com.example.nobom", "9.9", "2024-01-01T00:00:00Z");

    PackageContext ctx { m_tempDir, plistName, "" };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));

    EXPECT_EQ(wrapper->name(), "");
}

// ---------------------------------------------------------------------------
// Scenario: InstallPrefixPath = "." is normalised to "/"
// ---------------------------------------------------------------------------
TEST_F(PKGWrapperTest, DotPrefixIsNormalisedToRoot)
{
    std::string seenPrefix;
    PKGWrapper::setReceiptLivenessChecker(
        [&](const std::string&, const std::string & prefix)
    {
        seenPrefix = prefix;
        return true;
    });

    const std::string plistName { "dot_prefix.plist" };
    const std::string plistPath { m_tempDir + "/" + plistName };
    writeReceiptPlist(plistPath, "com.example.dotprefix", "1.0", "2024-01-01T00:00:00Z", ".");

    PackageContext ctx { m_tempDir, plistName, "" };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));

    // "." must be normalised to "/" before reaching the checker.
    EXPECT_EQ(seenPrefix, "/");
    EXPECT_EQ(wrapper->name(), "dotprefix");
}

// ---------------------------------------------------------------------------
// Scenario: InstallPrefixPath = "/" is passed through unchanged
// ---------------------------------------------------------------------------
TEST_F(PKGWrapperTest, SlashPrefixIsPassedThrough)
{
    std::string seenPrefix;
    PKGWrapper::setReceiptLivenessChecker(
        [&](const std::string&, const std::string & prefix)
    {
        seenPrefix = prefix;
        return true;
    });

    const std::string plistName { "slash_prefix.plist" };
    const std::string plistPath { m_tempDir + "/" + plistName };
    writeReceiptPlist(plistPath, "com.example.slashprefix", "2.0", "2024-01-01T00:00:00Z", "/");

    PackageContext ctx { m_tempDir, plistName, "" };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));

    EXPECT_EQ(seenPrefix, "/");
    EXPECT_EQ(wrapper->name(), "slashprefix");
}

// ---------------------------------------------------------------------------
// Scenario: custom InstallPrefixPath (e.g. /Library/Java) is preserved
// ---------------------------------------------------------------------------
TEST_F(PKGWrapperTest, CustomPrefixIsPreserved)
{
    std::string seenPrefix;
    PKGWrapper::setReceiptLivenessChecker(
        [&](const std::string&, const std::string & prefix)
    {
        seenPrefix = prefix;
        return true;
    });

    const std::string plistName { "custom_prefix.plist" };
    const std::string plistPath { m_tempDir + "/" + plistName };
    writeReceiptPlist(plistPath, "com.example.custom", "3.0", "2024-01-01T00:00:00Z", "/Library/Java");

    PackageContext ctx { m_tempDir, plistName, "" };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));

    EXPECT_EQ(seenPrefix, "/Library/Java");
    EXPECT_EQ(wrapper->name(), "custom");
}

// ---------------------------------------------------------------------------
// Scenario: missing InstallPrefixPath defaults to "/"
// ---------------------------------------------------------------------------
TEST_F(PKGWrapperTest, MissingPrefixDefaultsToRoot)
{
    std::string seenPrefix;
    PKGWrapper::setReceiptLivenessChecker(
        [&](const std::string&, const std::string & prefix)
    {
        seenPrefix = prefix;
        return true;
    });

    const std::string plistName { "no_prefix.plist" };
    const std::string plistPath { m_tempDir + "/" + plistName };
    writeReceiptPlist(plistPath, "com.example.noprefix", "4.0", "2024-01-01T00:00:00Z");

    PackageContext ctx { m_tempDir, plistName, "" };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));

    EXPECT_EQ(seenPrefix, "/");
}

// ---------------------------------------------------------------------------
// Scenario: a live receipt retains all fields
// ---------------------------------------------------------------------------
TEST_F(PKGWrapperTest, LiveReceiptRetainsAllFields)
{
    PKGWrapper::setReceiptLivenessChecker(
        [](const std::string&, const std::string&)
    {
        return true;
    });

    const std::string plistName { "live_receipt.plist" };
    const std::string plistPath { m_tempDir + "/" + plistName };
    writeReceiptPlist(plistPath, "com.vendor.product", "5.6.7", "2025-03-15T12:00:00Z", "/");

    PackageContext ctx { m_tempDir, plistName, "" };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));

    EXPECT_EQ(wrapper->name(), "product");
    EXPECT_EQ(wrapper->version(), "5.6.7");
    EXPECT_EQ(wrapper->vendor(), "Vendor");
    EXPECT_EQ(wrapper->description(), "com.vendor.product");
    EXPECT_EQ(wrapper->source(), "receipts");
    EXPECT_EQ(wrapper->install_time(), "2025-03-15T12:00:00Z");
}

// ---------------------------------------------------------------------------
// Scenario: a dead receipt clears name; other fields remain populated.
// The caller (sysInfoMac.cpp) skips entries with empty name.
// ---------------------------------------------------------------------------
TEST_F(PKGWrapperTest, DeadReceiptClearsNameOnly)
{
    PKGWrapper::setReceiptLivenessChecker(
        [](const std::string&, const std::string&)
    {
        return false;
    });

    const std::string plistName { "dead_receipt.plist" };
    const std::string plistPath { m_tempDir + "/" + plistName };
    writeReceiptPlist(plistPath, "com.vendor.deadpkg", "1.0", "2025-01-01T00:00:00Z", "/");

    PackageContext ctx { m_tempDir, plistName, "" };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));

    // Name cleared → sysInfoMac.cpp will skip this entry.
    EXPECT_EQ(wrapper->name(), "");
    // Other fields are still populated from the plist parsing phase.
    EXPECT_EQ(wrapper->source(), "receipts");
    EXPECT_EQ(wrapper->version(), "1.0");
}
