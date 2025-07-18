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
#include <unistd.h>
#include <iostream>

void PKGWrapperTest::SetUp() {};

void PKGWrapperTest::TearDown() {};

using ::testing::_;
using ::testing::Return;

TEST_F(PKGWrapperTest, LongVersion)
{
    std::string inputPath;
    inputPath += getwd(NULL);
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
    EXPECT_EQ(wrapper->vendor(), "operasoftware");
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, ShortVersion)
{
    std::string inputPath;
    inputPath += getwd(NULL);
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
    EXPECT_EQ(wrapper->vendor(), "operasoftware");
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, NameDifferentExecutable)
{
    std::string inputPath;
    inputPath += getwd(NULL);
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
    EXPECT_EQ(wrapper->vendor(), "operasoftware");
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, NameFirst)
{
    std::string inputPath;
    inputPath += getwd(NULL);
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
    EXPECT_EQ(wrapper->vendor(), "operasoftware");
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, NoNameButExecutable)
{
    std::string inputPath;
    inputPath += getwd(NULL);
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
    EXPECT_EQ(wrapper->vendor(), "operasoftware");
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, NoNameNoExecutable)
{
    std::string inputPath;
    inputPath += getwd(NULL);
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
    EXPECT_EQ(wrapper->vendor(), "operasoftware");
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, NoVersion)
{
    std::string inputPath;
    inputPath += getwd(NULL);
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
    EXPECT_EQ(wrapper->vendor(), "operasoftware");
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, NoGroups)
{
    std::string inputPath;
    inputPath += getwd(NULL);
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
    EXPECT_EQ(wrapper->vendor(), "operasoftware");
    EXPECT_EQ(wrapper->priority(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), UNKNOWN_VALUE);
    EXPECT_EQ(wrapper->multiarch(), UNKNOWN_VALUE);
}

TEST_F(PKGWrapperTest, NoDescription)
{
    std::string inputPath;
    inputPath += getwd(NULL);
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
    inputPath += getwd(NULL);
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
    inputPath += getwd(NULL);
    inputPath += "/input_files";
    std::string package { "com.Wazuh.pkg.wazuh-agent.plist" };

    struct PackageContext ctx
    {
        inputPath, package, ""
    };
    std::shared_ptr<PKGWrapper> wrapper;
    EXPECT_NO_THROW(wrapper = std::make_shared<PKGWrapper>(ctx));
    EXPECT_EQ(wrapper->name(), "wazuh-agent");
    EXPECT_EQ(wrapper->version(), "4.10.1");
    EXPECT_EQ(wrapper->groups(), " ");
    EXPECT_EQ(wrapper->description(), "com.Wazuh.pkg.wazuh-agent");
    EXPECT_EQ(wrapper->architecture(), " ");
    EXPECT_EQ(wrapper->format(), "pkg");
    EXPECT_EQ(wrapper->osPatch(), "");
    EXPECT_EQ(wrapper->source(), "receipts");
    EXPECT_EQ(wrapper->location(), inputPath + "/" + package);
    EXPECT_EQ(wrapper->vendor(), "wazuh");
    EXPECT_EQ(wrapper->priority(), " ");
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), "2024-11-07T08:58:38Z");
    EXPECT_EQ(wrapper->multiarch(), " ");
}

TEST_F(PKGWrapperTest, pkgVersionBin)
{
    std::string inputPath;
    inputPath += getwd(NULL);
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
    EXPECT_EQ(wrapper->vendor(), "zoom");
    EXPECT_EQ(wrapper->priority(), " ");
    EXPECT_EQ(wrapper->size(), 0);
    EXPECT_EQ(wrapper->install_time(), "2024-11-08T11:44:04Z");
    EXPECT_EQ(wrapper->multiarch(), " ");
}

TEST_F(PKGWrapperTest, pkgVersionLong)
{
    std::string inputPath;
    inputPath += getwd(NULL);
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
