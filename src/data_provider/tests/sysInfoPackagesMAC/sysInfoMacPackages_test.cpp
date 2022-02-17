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
#include "packages/packageMac.h"

void SysInfoMacPackagesTest::SetUp() {};

void SysInfoMacPackagesTest::TearDown() {};

using ::testing::_;
using ::testing::Return;

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
        MOCK_METHOD(int, size, (), (const override));
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
    EXPECT_CALL(*mock, install_time()).Times(1).WillOnce(Return("12"));
    EXPECT_CALL(*mock, multiarch()).Times(1).WillOnce(Return("13"));

    EXPECT_NO_THROW(std::make_unique<BSDPackageImpl>(mock)->buildPackageData(packages));
    EXPECT_EQ("1", packages.at("name").get_ref<const std::string&>());
    EXPECT_EQ("2", packages.at("version").get_ref<const std::string&>());
    EXPECT_EQ("3", packages.at("groups").get_ref<const std::string&>());
    EXPECT_EQ("4", packages.at("description").get_ref<const std::string&>());
    EXPECT_EQ("5", packages.at("architecture").get_ref<const std::string&>());
    EXPECT_EQ("6", packages.at("format").get_ref<const std::string&>());
    EXPECT_EQ("7", packages.at("source").get_ref<const std::string&>());
    EXPECT_EQ("8", packages.at("location").get_ref<const std::string&>());
    EXPECT_EQ("9", packages.at("priority").get_ref<const std::string&>());
    EXPECT_EQ(10, packages.at("size").get<const int>());
    EXPECT_EQ("11", packages.at("vendor").get_ref<const std::string&>());
    EXPECT_EQ("12", packages.at("install_time").get_ref<const std::string&>());
    EXPECT_EQ("13", packages.at("multiarch").get_ref<const std::string&>());
}
