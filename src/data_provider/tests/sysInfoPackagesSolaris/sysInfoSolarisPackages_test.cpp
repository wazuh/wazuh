/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * January 12, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sysInfoSolarisPackages_test.h"
#include "packages/packageFamilyDataAFactory.h"
#include "packages/packageSolaris.h"

void SysInfoSolarisPackagesTest::SetUp() {};

void SysInfoSolarisPackagesTest::TearDown() {};

using ::testing::_;
using ::testing::Return;

class SysInfoSolarisPackagesWrapperMock: public IPackageWrapper
{
    public:
        SysInfoSolarisPackagesWrapperMock() = default;
        virtual ~SysInfoSolarisPackagesWrapperMock() = default;
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

TEST_F(SysInfoSolarisPackagesTest, Test_Success_Data)
{
    auto mock { std::make_shared<SysInfoSolarisPackagesWrapperMock>() };
    nlohmann::json packages {};

    EXPECT_CALL(*mock, name()).Times(1).WillOnce(Return("libstdc++6"));
    EXPECT_CALL(*mock, version()).Times(1).WillOnce(Return("5.5.0"));
    EXPECT_CALL(*mock, groups()).Times(1).WillOnce(Return("application"));
    EXPECT_CALL(*mock, description()).Times(1).WillOnce(Return("libstdc++6 - The GNU Compiler Collection, libstdc++.so.6"));
    EXPECT_CALL(*mock, architecture()).Times(1).WillOnce(Return("i386"));
    EXPECT_CALL(*mock, format()).Times(1).WillOnce(Return("pkg"));
    EXPECT_CALL(*mock, source()).Times(1).WillOnce(Return(""));
    EXPECT_CALL(*mock, location()).Times(1).WillOnce(Return(""));
    EXPECT_CALL(*mock, priority()).Times(1).WillOnce(Return(""));
    EXPECT_CALL(*mock, size()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, vendor()).Times(1).WillOnce(Return("Oracle corporation"));
    EXPECT_CALL(*mock, install_time()).Times(1).WillOnce(Return("2022/01/13 14:48:58"));

    EXPECT_NO_THROW(FactoryPackageFamilyCreator<OSPlatformType::SOLARIS>::create(mock)->buildPackageData(packages));

    EXPECT_EQ("libstdc++6", packages.at("name").get_ref<const std::string&>());
    EXPECT_EQ("5.5.0", packages.at("version").get_ref<const std::string&>());
    EXPECT_EQ("application", packages.at("groups").get_ref<const std::string&>());
    EXPECT_EQ("libstdc++6 - The GNU Compiler Collection, libstdc++.so.6", packages.at("description").get_ref<const std::string&>());
    EXPECT_EQ("i386", packages.at("architecture").get_ref<const std::string&>());
    EXPECT_EQ("pkg", packages.at("format").get_ref<const std::string&>());
    EXPECT_EQ("", packages.at("source").get_ref<const std::string&>());
    EXPECT_EQ("", packages.at("location").get_ref<const std::string&>());
    EXPECT_EQ("", packages.at("priority").get_ref<const std::string&>());
    EXPECT_EQ(0, packages.at("size").get<const int>());
    EXPECT_EQ("Oracle corporation", packages.at("vendor").get_ref<const std::string&>());
    EXPECT_EQ("2022/01/13 14:48:58", packages.at("install_time").get_ref<const std::string&>());
}
