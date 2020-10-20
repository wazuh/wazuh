/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 19, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "sysInfo_test.h"
#include "sysInfo.hpp"

void SysInfoTest::SetUp() {};

void SysInfoTest::TearDown()
{
};

using ::testing::_;
using ::testing::Return;

std::string SysInfo::getSerialNumber(){return "";}
std::string SysInfo::getCpuName(){return "";}
int SysInfo::getCpuMHz(){return 0;}
int SysInfo::getCpuCores(){return 0;}
void SysInfo::getMemory(nlohmann::json&){}
nlohmann::json SysInfo::getPackages(){return "";}

class SysInfoWrapper: public SysInfo
{
public:
    SysInfoWrapper() = default;
    ~SysInfoWrapper() = default;
    MOCK_METHOD(std::string, getSerialNumber, (), (override));
    MOCK_METHOD(std::string, getCpuName, (), (override));
    MOCK_METHOD(int, getCpuMHz, (), (override));
    MOCK_METHOD(int, getCpuCores, (), (override));
    MOCK_METHOD(void, getMemory, (nlohmann::json&), (override));
    MOCK_METHOD(nlohmann::json, getPackages, (), (override));
};


TEST_F(SysInfoTest, hardware)
{
    SysInfoWrapper info;
    EXPECT_CALL(info, getSerialNumber()).WillOnce(Return("serial"));
    EXPECT_CALL(info, getCpuName()).WillOnce(Return("name"));
    EXPECT_CALL(info, getCpuCores()).WillOnce(Return(1));
    EXPECT_CALL(info, getCpuMHz()).WillOnce(Return(2902));
    EXPECT_CALL(info, getMemory(_));
    const auto result {info.hardware()};
    EXPECT_FALSE(result.empty());
}

TEST_F(SysInfoTest, packages)
{
    SysInfoWrapper info;
    EXPECT_CALL(info, getPackages()).WillOnce(Return("packages"));
    const auto result {info.packages()};
    EXPECT_FALSE(result.empty());
}
