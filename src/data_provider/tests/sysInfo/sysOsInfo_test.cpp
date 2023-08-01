/*
 * Wazuh SysOsInfo
 * Copyright (C) 2015, Wazuh Inc.
 * November 5, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "sysOsInfo_test.h"
#include "osinfo/sysOsInfoWin.h"

void SysOsInfoTest::SetUp() {};

void SysOsInfoTest::TearDown()
{
};
using ::testing::_;
using ::testing::Return;

class SysOsInfoProviderWrapper : public ISysOsInfoProvider
{
    public:
        SysOsInfoProviderWrapper() = default;
        ~SysOsInfoProviderWrapper() = default;
        MOCK_METHOD(std::string, name, (), (const override));
        MOCK_METHOD(std::string, version, (), (const override));
        MOCK_METHOD(std::string, majorVersion, (), (const override));
        MOCK_METHOD(std::string, minorVersion, (), (const override));
        MOCK_METHOD(std::string, build, (), (const override));
        MOCK_METHOD(std::string, release, (), (const override));
        MOCK_METHOD(std::string, displayVersion, (), (const override));
        MOCK_METHOD(std::string, machine, (), (const override));
        MOCK_METHOD(std::string, nodeName, (), (const override));
};


TEST_F(SysOsInfoTest, setOsInfoSchema)
{
    nlohmann::json output;
    const auto pOsInfoProvider{new SysOsInfoProviderWrapper};
    const std::shared_ptr<ISysOsInfoProvider> spOsInfoProvider
    {
        pOsInfoProvider
    };
    EXPECT_CALL(*pOsInfoProvider, name()).WillOnce(Return("Microsoft Windows 10 Home"));
    EXPECT_CALL(*pOsInfoProvider, version()).WillOnce(Return("10.0.18362"));
    EXPECT_CALL(*pOsInfoProvider, majorVersion()).WillOnce(Return("10"));
    EXPECT_CALL(*pOsInfoProvider, minorVersion()).WillOnce(Return("0"));
    EXPECT_CALL(*pOsInfoProvider, build()).WillOnce(Return("18362"));
    EXPECT_CALL(*pOsInfoProvider, release()).WillOnce(Return("1903"));
    EXPECT_CALL(*pOsInfoProvider, displayVersion()).WillOnce(Return("19H1"));
    EXPECT_CALL(*pOsInfoProvider, machine()).WillOnce(Return("x86_64"));
    EXPECT_CALL(*pOsInfoProvider, nodeName()).WillOnce(Return("DESKTOP-U7Q6UQV"));
    SysOsInfo::setOsInfo(spOsInfoProvider, output);
    EXPECT_EQ("x86_64", output.at("architecture"));
    EXPECT_EQ("DESKTOP-U7Q6UQV", output.at("hostname"));
    EXPECT_EQ("18362", output.at("os_build"));
    EXPECT_EQ("10", output.at("os_major"));
    EXPECT_EQ("0", output.at("os_minor"));
    EXPECT_EQ("Microsoft Windows 10 Home", output.at("os_name"));
    EXPECT_EQ("1903", output.at("os_release"));
    EXPECT_EQ("19H1", output.at("os_display_version"));
    EXPECT_EQ("10.0.18362", output.at("os_version"));
}