/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * November 10, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "sysInfoPort_test.h"
#include "ports/portImpl.h"

void SysInfoPortTest::SetUp() {};

void SysInfoPortTest::TearDown()
{
};

using ::testing::_;
using ::testing::Return;

class SysInfoPortWrapperMock: public IPortWrapper
{
    public:
        SysInfoPortWrapperMock() = default;
        virtual ~SysInfoPortWrapperMock() = default;
        MOCK_METHOD(std::string, protocol, (), (const override));
        MOCK_METHOD(std::string, localIp, (), (const override));
        MOCK_METHOD(int32_t, localPort, (), (const override));
        MOCK_METHOD(std::string, remoteIP, (), (const override));
        MOCK_METHOD(int32_t, remotePort, (), (const override));
        MOCK_METHOD(int32_t, txQueue, (), (const override));
        MOCK_METHOD(int32_t, rxQueue, (), (const override));
        MOCK_METHOD(int64_t, inode, (), (const override));
        MOCK_METHOD(std::string, state, (), (const override));
        MOCK_METHOD(int32_t, pid, (), (const override));
        MOCK_METHOD(std::string, processName, (), (const override));
};

TEST_F(SysInfoPortTest, Test_SPEC_Data)
{
    auto mock { std::make_shared<SysInfoPortWrapperMock>() };
    nlohmann::json port {};
    EXPECT_CALL(*mock, protocol()).Times(1).WillOnce(Return("1"));
    EXPECT_CALL(*mock, localIp()).Times(1).WillOnce(Return("2"));
    EXPECT_CALL(*mock, localPort()).Times(1).WillOnce(Return(3));
    EXPECT_CALL(*mock, remoteIP()).Times(1).WillOnce(Return("4"));
    EXPECT_CALL(*mock, remotePort()).Times(1).WillOnce(Return(5));
    EXPECT_CALL(*mock, txQueue()).Times(1).WillOnce(Return(6));
    EXPECT_CALL(*mock, rxQueue()).Times(1).WillOnce(Return(7));
    EXPECT_CALL(*mock, inode()).Times(1).WillOnce(Return(4274126910));
    EXPECT_CALL(*mock, state()).Times(1).WillOnce(Return("9"));
    EXPECT_CALL(*mock, pid()).Times(1).WillOnce(Return(10));
    EXPECT_CALL(*mock, processName()).Times(1).WillOnce(Return("11"));

    EXPECT_NO_THROW(std::make_unique<PortImpl>(mock)->buildPortData(port));
    EXPECT_EQ("1", port.at("protocol").get_ref<const std::string&>());
    EXPECT_EQ("2", port.at("local_ip").get_ref<const std::string&>());
    EXPECT_EQ(3, port.at("local_port").get<int32_t>());
    EXPECT_EQ("4", port.at("remote_ip").get_ref<const std::string&>());
    EXPECT_EQ(5, port.at("remote_port").get<int32_t>());
    EXPECT_EQ(6, port.at("tx_queue").get<int32_t>());
    EXPECT_EQ(7, port.at("rx_queue").get<int32_t>());
    EXPECT_EQ(4274126910, port.at("inode").get<int64_t>());
    EXPECT_EQ("9", port.at("state").get_ref<const std::string&>());
    EXPECT_EQ(10, port.at("pid").get<int32_t>());
    EXPECT_EQ("11", port.at("process").get_ref<const std::string&>());
}