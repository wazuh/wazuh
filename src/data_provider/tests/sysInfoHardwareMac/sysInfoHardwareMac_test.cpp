/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * May 18, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sysInfoHardwareMac_test.h"
#include "hardware/factoryHardwareFamilyCreator.h"
#include "hardware/hardwareWrapperInterface.h"
#include "json.hpp"

void SysInfoHardwareMacTest::SetUp() {};

void SysInfoHardwareMacTest::TearDown() {};

using ::testing::Return;

class OSHardwareWrapperMacMock: public IOSHardwareWrapper
{
    public:
        OSHardwareWrapperMacMock() = default;
        virtual ~OSHardwareWrapperMacMock() = default;
        MOCK_METHOD(std::string, boardSerial, (), (const override));
        MOCK_METHOD(std::string, cpuName, (), (const override));
        MOCK_METHOD(int, cpuCores, (), (const override));
        MOCK_METHOD(double, cpuMhz, (), (override));
        MOCK_METHOD(uint64_t, ramTotal, (), (const override));
        MOCK_METHOD(uint64_t, ramFree, (), (const override));
        MOCK_METHOD(uint64_t, ramUsage, (), (const override));
};

TEST_F(SysInfoHardwareMacTest, Test_BuildHardwareData_Succeed)
{
    auto mock { std::make_shared<OSHardwareWrapperMacMock>() };
    nlohmann::json hardware {};
    EXPECT_CALL(*mock, boardSerial()).WillOnce(Return("H2WH91N3Q6NY"));
    EXPECT_CALL(*mock, cpuName()).WillOnce(Return("Macmini9,1"));
    EXPECT_CALL(*mock, cpuCores()).WillOnce(Return(8));
    EXPECT_CALL(*mock, cpuMhz()).WillOnce(Return(3204.0));
    EXPECT_CALL(*mock, ramTotal()).WillOnce(Return(16777216));
    EXPECT_CALL(*mock, ramFree()).WillOnce(Return(8388608));
    EXPECT_CALL(*mock, ramUsage()).WillOnce(Return(50));
    EXPECT_NO_THROW(FactoryHardwareFamilyCreator<OSPlatformType::BSDBASED>::create(mock)->buildHardwareData(hardware));

    EXPECT_EQ("H2WH91N3Q6NY", hardware.at("board_serial").get_ref<nlohmann::json::string_t&>());
    EXPECT_EQ("Macmini9,1", hardware.at("cpu_name").get_ref<nlohmann::json::string_t&>());
    EXPECT_EQ((int)8, hardware.at("cpu_cores").get_ref<nlohmann::json::number_integer_t&>());
    EXPECT_EQ((double)3204.0, hardware.at("cpu_mhz").get_ref<nlohmann::json::number_float_t&>());
    EXPECT_EQ((uint64_t)16777216, hardware.at("ram_total").get_ref<nlohmann::json::number_unsigned_t&>());
    EXPECT_EQ((uint64_t)8388608, hardware.at("ram_free").get_ref<nlohmann::json::number_unsigned_t&>());
    EXPECT_EQ((uint64_t)50, hardware.at("ram_usage").get_ref<nlohmann::json::number_unsigned_t&>());
}
