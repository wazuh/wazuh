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

TEST_F(PKGWrapperTest, NoName)
{
    std::string inputPath;
    inputPath += getwd(NULL);
    inputPath += "/input_files";
    std::string package { "PKGWrapperTest_NoName.app" };

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
