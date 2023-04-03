/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * March 31, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <sstream>
#include <unistd.h>
#include <arpa/inet.h>

#include "sysInfoSolarisPorts_test.h"
#include "ports/portImpl.h"

void SysInfoSolarisPortsTest::SetUp() {};
void SysInfoSolarisPortsTest::TearDown() {};

using ::testing::_;
using ::testing::Return;
class sysInfoPortsSolarisWrapperMock : public IPortWrapper
{
    public:
        sysInfoPortsSolarisWrapperMock() {}
        virtual ~sysInfoPortsSolarisWrapperMock() = default;
        MOCK_METHOD(std::string, protocol, (), (const, override));
        MOCK_METHOD(std::string, localIp, (), (const, override));
        MOCK_METHOD(int32_t, localPort, (), (const, override));
        MOCK_METHOD(std::string, remoteIP, (), (const, override));
        MOCK_METHOD(int32_t, remotePort, (), (const, override));
        MOCK_METHOD(int32_t, txQueue, (), (const, override));
        MOCK_METHOD(int32_t, rxQueue, (), (const, override));
        MOCK_METHOD(int64_t, inode, (), (const, override));
        MOCK_METHOD(std::string, state, (), (const, override));
        MOCK_METHOD(int32_t, pid, (), (const, override));
        MOCK_METHOD(std::string, processName, (), (const, override));
};

/**
 * @brief Test success UDP
 *
 */
TEST_F(SysInfoSolarisPortsTest, TestSuccessUDP)
{
    nlohmann::json port{};
    const mib_item_t* item = reinterpret_cast<const mib_item_t*>(testUDPbin.data());
    const mib2_udpEntry_t* udpData = reinterpret_cast<const mib2_udpEntry_t*>(item->val);
    char buf[INET_ADDRSTRLEN];

    const auto mock{std::make_shared<sysInfoPortsSolarisWrapperMock>()};

    EXPECT_CALL(*mock, protocol()).Times(1).WillOnce(Return("udp"));
    EXPECT_CALL(*mock, localIp()).Times(1).WillOnce(Return(inet_ntop(AF_INET, &udpData->udpLocalAddress, buf, sizeof(buf))));
    EXPECT_CALL(*mock, localPort()).Times(1).WillOnce(Return(udpData->udpLocalPort));
    EXPECT_CALL(*mock, remoteIP()).Times(1).WillOnce(Return(inet_ntop(AF_INET, &udpData->udpEntryInfo.ue_RemoteAddress, buf, sizeof(buf))));
    EXPECT_CALL(*mock, remotePort()).Times(1).WillOnce(Return(udpData->udpEntryInfo.ue_RemotePort));
    EXPECT_CALL(*mock, txQueue()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, rxQueue()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, inode()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, state()).Times(1).WillOnce(Return(std::to_string(udpData->udpEntryInfo.ue_state)));
    EXPECT_CALL(*mock, pid()).Times(1).WillOnce(Return(udpData->udpCreationProcess));
    EXPECT_CALL(*mock, processName()).Times(1).WillOnce(Return(""));

    EXPECT_NO_THROW(std::make_unique<PortImpl>(mock)->buildPortData(port));

    EXPECT_EQ("udp", port.at("protocol").get_ref<const std::string&>());
    EXPECT_EQ("204.8.0.0", port.at("local_ip").get_ref<const std::string&>());
    EXPECT_EQ(0, port.at("local_port").get<const int32_t>());
    EXPECT_EQ("40.0.0.0", port.at("remote_ip").get_ref<const std::string&>());
    EXPECT_EQ(68, port.at("remote_port").get<const int32_t>());
    EXPECT_EQ(0, port.at("tx_queue").get<const int32_t>());
    EXPECT_EQ(0, port.at("rx_queue").get<const int32_t>());
    EXPECT_EQ(0, port.at("inode").get<const int32_t>());
    EXPECT_EQ("2231", port.at("state").get_ref<const std::string&>());
    EXPECT_EQ(2252, port.at("pid").get<const int32_t>());
    EXPECT_EQ("", port.at("process").get_ref<const std::string&>());
}

/**
 * @brief Test success UDP6
 *
 */
TEST_F(SysInfoSolarisPortsTest, TestSuccessUDP6)
{
    nlohmann::json port{};
    const mib_item_t* item = reinterpret_cast<const mib_item_t*>(testUDP6bin.data());
    const mib2_udp6Entry_t* udpData = reinterpret_cast<const mib2_udp6Entry_t*>(item->val);
    char buf[INET6_ADDRSTRLEN];

    const auto mock{std::make_shared<sysInfoPortsSolarisWrapperMock>()};

    EXPECT_CALL(*mock, protocol()).Times(1).WillOnce(Return("udp6"));
    EXPECT_CALL(*mock, localIp()).Times(1).WillOnce(Return(inet_ntop(AF_INET6, &udpData->udp6LocalAddress, buf, sizeof(buf))));
    EXPECT_CALL(*mock, localPort()).Times(1).WillOnce(Return(udpData->udp6LocalPort));
    EXPECT_CALL(*mock, remoteIP()).Times(1).WillOnce(Return(inet_ntop(AF_INET6, &udpData->udp6EntryInfo.ue_RemoteAddress, buf, sizeof(buf))));
    EXPECT_CALL(*mock, remotePort()).Times(1).WillOnce(Return(udpData->udp6EntryInfo.ue_RemotePort));
    EXPECT_CALL(*mock, txQueue()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, rxQueue()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, inode()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, state()).Times(1).WillOnce(Return(std::to_string(udpData->udp6EntryInfo.ue_state)));
    EXPECT_CALL(*mock, pid()).Times(1).WillOnce(Return(udpData->udp6CreationProcess));
    EXPECT_CALL(*mock, processName()).Times(1).WillOnce(Return(""));

    EXPECT_NO_THROW(std::make_unique<PortImpl>(mock)->buildPortData(port));

    EXPECT_EQ("udp6", port.at("protocol").get_ref<const std::string&>());
    EXPECT_EQ("::", port.at("local_ip").get_ref<const std::string&>());
    EXPECT_EQ(0, port.at("local_port").get<const int32_t>());
    EXPECT_EQ("::", port.at("remote_ip").get_ref<const std::string&>());
    EXPECT_EQ(0, port.at("remote_port").get<const int32_t>());
    EXPECT_EQ(0, port.at("tx_queue").get<const int32_t>());
    EXPECT_EQ(0, port.at("rx_queue").get<const int32_t>());
    EXPECT_EQ(0, port.at("inode").get<const int32_t>());
    EXPECT_EQ("1", port.at("state").get_ref<const std::string&>());
    EXPECT_EQ(84, port.at("pid").get<const int32_t>());
    EXPECT_EQ("", port.at("process").get_ref<const std::string&>());
}

/**
 * @brief Test success TCP
 *
 */
TEST_F(SysInfoSolarisPortsTest, TestSuccessTCP)
{
    nlohmann::json port{};
    const mib_item_t* item = reinterpret_cast<const mib_item_t*>(testTCPbin.data());
    const mib2_tcpConnEntry_t* tcpData = reinterpret_cast<const mib2_tcpConnEntry_t*>(item->val);
    char buf[INET_ADDRSTRLEN];

    const auto mock{std::make_shared<sysInfoPortsSolarisWrapperMock>()};

    EXPECT_CALL(*mock, protocol()).Times(1).WillOnce(Return("tcp"));
    EXPECT_CALL(*mock, localIp()).Times(1).WillOnce(Return(inet_ntop(AF_INET, &tcpData->tcpConnLocalAddress, buf, sizeof(buf))));
    EXPECT_CALL(*mock, localPort()).Times(1).WillOnce(Return(tcpData->tcpConnLocalPort));
    EXPECT_CALL(*mock, remoteIP()).Times(1).WillOnce(Return(inet_ntop(AF_INET, &tcpData->tcpConnRemAddress, buf, sizeof(buf))));
    EXPECT_CALL(*mock, remotePort()).Times(1).WillOnce(Return(tcpData->tcpConnRemPort));
    EXPECT_CALL(*mock, txQueue()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, rxQueue()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, inode()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, state()).Times(1).WillOnce(Return(std::to_string(tcpData->tcpConnState)));
    EXPECT_CALL(*mock, pid()).Times(1).WillOnce(Return(tcpData->tcpConnCreationProcess));
    EXPECT_CALL(*mock, processName()).Times(1).WillOnce(Return(""));

    EXPECT_NO_THROW(std::make_unique<PortImpl>(mock)->buildPortData(port));

    EXPECT_EQ("tcp", port.at("protocol").get_ref<const std::string&>());
    EXPECT_EQ("200.0.0.0", port.at("local_ip").get_ref<const std::string&>());
    EXPECT_EQ(60000, port.at("local_port").get<const int32_t>());
    EXPECT_EQ("255.255.255.255", port.at("remote_ip").get_ref<const std::string&>());
    EXPECT_EQ(58832, port.at("remote_port").get<const int32_t>());
    EXPECT_EQ(0, port.at("tx_queue").get<const int32_t>());
    EXPECT_EQ(0, port.at("rx_queue").get<const int32_t>());
    EXPECT_EQ(0, port.at("inode").get<const int32_t>());
    EXPECT_EQ("4", port.at("state").get_ref<const std::string&>());
    EXPECT_EQ(4338295, port.at("pid").get<const int32_t>());
    EXPECT_EQ("", port.at("process").get_ref<const std::string&>());
}

/**
 * @brief Test success TCP6
 *
 */
TEST_F(SysInfoSolarisPortsTest, TestSuccessTCP6)
{
    nlohmann::json port{};
    const mib_item_t* item = reinterpret_cast<const mib_item_t*>(testTCP6bin.data());
    const mib2_tcp6ConnEntry_t* tcpData = reinterpret_cast<const mib2_tcp6ConnEntry_t*>(item->val);
    char buf[INET6_ADDRSTRLEN];

    const auto mock{std::make_shared<sysInfoPortsSolarisWrapperMock>()};

    EXPECT_CALL(*mock, protocol()).Times(1).WillOnce(Return("tcp6"));
    EXPECT_CALL(*mock, localIp()).Times(1).WillOnce(Return(inet_ntop(AF_INET6, &tcpData->tcp6ConnLocalAddress, buf, sizeof(buf))));
    EXPECT_CALL(*mock, localPort()).Times(1).WillOnce(Return(tcpData->tcp6ConnLocalPort));
    EXPECT_CALL(*mock, remoteIP()).Times(1).WillOnce(Return(inet_ntop(AF_INET6, &tcpData->tcp6ConnRemAddress, buf, sizeof(buf))));
    EXPECT_CALL(*mock, remotePort()).Times(1).WillOnce(Return(tcpData->tcp6ConnRemPort));
    EXPECT_CALL(*mock, txQueue()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, rxQueue()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, inode()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, state()).Times(1).WillOnce(Return(std::to_string(tcpData->tcp6ConnState)));
    EXPECT_CALL(*mock, pid()).Times(1).WillOnce(Return(tcpData->tcp6ConnCreationProcess));
    EXPECT_CALL(*mock, processName()).Times(1).WillOnce(Return(""));

    EXPECT_NO_THROW(std::make_unique<PortImpl>(mock)->buildPortData(port));

    EXPECT_EQ("tcp6", port.at("protocol").get_ref<const std::string&>());
    EXPECT_EQ("::1", port.at("local_ip").get_ref<const std::string&>());
    EXPECT_EQ(5999, port.at("local_port").get<const int32_t>());
    EXPECT_EQ("::", port.at("remote_ip").get_ref<const std::string&>());
    EXPECT_EQ(0, port.at("remote_port").get<const int32_t>());
    EXPECT_EQ(0, port.at("tx_queue").get<const int32_t>());
    EXPECT_EQ(0, port.at("rx_queue").get<const int32_t>());
    EXPECT_EQ(0, port.at("inode").get<const int32_t>());
    EXPECT_EQ("2", port.at("state").get_ref<const std::string&>());
    EXPECT_EQ(84, port.at("pid").get<const int32_t>());
    EXPECT_EQ("", port.at("process").get_ref<const std::string&>());
}

/**
 * @brief Test Not success
 *
 */
TEST_F(SysInfoSolarisPortsTest, TestNotSuccess)
{
    nlohmann::json port{};

    const auto EMPTY_PORT =
        R"({"inode":0,"local_ip":"","local_port":0,"pid":0,"process":"",
            "protocol":"tcp6","remote_ip":"","remote_port":0,"rx_queue":0,
            "state":"","tx_queue":0})"_json;

    const auto mock{std::make_shared<sysInfoPortsSolarisWrapperMock>()};

    EXPECT_CALL(*mock, protocol()).Times(1).WillOnce(Return("tcp6"));
    EXPECT_CALL(*mock, localIp()).Times(1).WillOnce(Return(""));
    EXPECT_CALL(*mock, localPort()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, remoteIP()).Times(1).WillOnce(Return(""));
    EXPECT_CALL(*mock, remotePort()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, txQueue()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, rxQueue()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, inode()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, state()).Times(1).WillOnce(Return(""));
    EXPECT_CALL(*mock, pid()).Times(1).WillOnce(Return(0));
    EXPECT_CALL(*mock, processName()).Times(1).WillOnce(Return(""));

    EXPECT_NO_THROW(std::make_unique<PortImpl>(mock)->buildPortData(port));

    EXPECT_EQ(EMPTY_PORT, port);
}
