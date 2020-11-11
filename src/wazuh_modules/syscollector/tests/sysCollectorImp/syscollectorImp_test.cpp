/*
 * Wazuh SyscollectorImp
 * Copyright (C) 2015-2020, Wazuh Inc.
 * November 9, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "syscollectorImp_test.h"
#include "syscollectorImp.h"

void SyscollectorImpTest::SetUp() {};

void SyscollectorImpTest::TearDown()
{
};

using ::testing::_;
using ::testing::Return;

class SysInfoWrapper: public ISysInfo
{
public:
    SysInfoWrapper() = default;
    ~SysInfoWrapper() = default;
    MOCK_METHOD(nlohmann::json, hardware, (), (override));
    MOCK_METHOD(nlohmann::json, packages, (), (override));
    MOCK_METHOD(nlohmann::json, os, (), (override));    
    MOCK_METHOD(nlohmann::json, networks, (), (override));    
    MOCK_METHOD(nlohmann::json, processes, (), (override));
    MOCK_METHOD(nlohmann::json, ports, (), (override));
};

TEST_F(SyscollectorImpTest, defaultCtor)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return("hardware"));
    EXPECT_CALL(*spInfoWrapper, packages()).WillOnce(Return("packages"));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return("os"));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillOnce(Return("processes"));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));
    std::thread t1;
    {
        Syscollector syscollector{spInfoWrapper};
        t1 = std::thread{[&syscollector](){ syscollector.start(); }};
    }
    if (t1.joinable())
    {
        t1.join();
    }
}

TEST_F(SyscollectorImpTest, intervalSeconds)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return("hardware"));
    EXPECT_CALL(*spInfoWrapper, packages()).WillOnce(Return("packages"));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return("os"));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillOnce(Return("processes"));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    std::thread t1;
    {
        Syscollector syscollector{spInfoWrapper, "100s"};
        t1 = std::thread{[&syscollector](){ syscollector.start(); }};
    }
    if (t1.joinable())
    {
        t1.join();
    }
}

TEST_F(SyscollectorImpTest, intervalMinutes)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return("hardware"));
    EXPECT_CALL(*spInfoWrapper, packages()).WillOnce(Return("packages"));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return("os"));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillOnce(Return("processes"));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    std::thread t1;
    {
        Syscollector syscollector{spInfoWrapper, "100m"};
        t1 = std::thread{[&syscollector](){ syscollector.start(); }};
    }
    if (t1.joinable())
    {
        t1.join();
    }
}

TEST_F(SyscollectorImpTest, intervalDays)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return("hardware"));
    EXPECT_CALL(*spInfoWrapper, packages()).WillOnce(Return("packages"));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return("os"));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillOnce(Return("processes"));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    std::thread t1;
    {
        Syscollector syscollector{spInfoWrapper, "1d"};
        t1 = std::thread{[&syscollector](){ syscollector.start(); }};
    }
    if (t1.joinable())
    {
        t1.join();
    }
}

TEST_F(SyscollectorImpTest, intervalUnknownUnit)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return("hardware"));
    EXPECT_CALL(*spInfoWrapper, packages()).WillOnce(Return("packages"));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return("os"));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillOnce(Return("processes"));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    std::thread t1;
    {
        Syscollector syscollector{spInfoWrapper, "1y"};
        t1 = std::thread{[&syscollector](){ syscollector.start(); }};
    }
    if (t1.joinable())
    {
        t1.join();
    }
}

TEST_F(SyscollectorImpTest, noScanOnStart)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, packages()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);
    EXPECT_CALL(*spInfoWrapper, networks()).Times(0);
    EXPECT_CALL(*spInfoWrapper, processes()).Times(0);
    EXPECT_CALL(*spInfoWrapper, ports()).Times(0);
    std::thread t1;
    {
        Syscollector syscollector{spInfoWrapper, "1h", false};
        t1 = std::thread{[&syscollector](){ syscollector.start(); }};
    }
    if (t1.joinable())
    {
        t1.join();
    }
}

TEST_F(SyscollectorImpTest, noHardware)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, packages()).WillOnce(Return("packages"));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return("os"));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillOnce(Return("processes"));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    std::thread t1;
    {
        Syscollector syscollector{spInfoWrapper, "1h", true, false};
        t1 = std::thread{[&syscollector](){ syscollector.start(); }};
    }
    if (t1.joinable())
    {
        t1.join();
    }
}

TEST_F(SyscollectorImpTest, noOs)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return("hardware"));
    EXPECT_CALL(*spInfoWrapper, packages()).WillOnce(Return("packages"));
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillOnce(Return("processes"));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    std::thread t1;
    {
        Syscollector syscollector{spInfoWrapper, "1h", true, true, false};
        t1 = std::thread{[&syscollector](){ syscollector.start(); }};
    }
    if (t1.joinable())
    {
        t1.join();
    }
}

TEST_F(SyscollectorImpTest, noNetwork)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return("hardware"));
    EXPECT_CALL(*spInfoWrapper, packages()).WillOnce(Return("packages"));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return("os"));
    EXPECT_CALL(*spInfoWrapper, networks()).Times(0);
    EXPECT_CALL(*spInfoWrapper, processes()).WillOnce(Return("processes"));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    std::thread t1;
    {
        Syscollector syscollector{spInfoWrapper, "1h", true, true, true, false};
        t1 = std::thread{[&syscollector](){ syscollector.start(); }};
    }
    if (t1.joinable())
    {
        t1.join();
    }
}

TEST_F(SyscollectorImpTest, noPackages)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return("hardware"));
    EXPECT_CALL(*spInfoWrapper, packages()).Times(0);
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return("os"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillOnce(Return("processes"));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    std::thread t1;
    {
        Syscollector syscollector{spInfoWrapper, "1h", true, true, true, true, false};
        t1 = std::thread{[&syscollector](){ syscollector.start(); }};
    }
    if (t1.joinable())
    {
        t1.join();
    }
}

TEST_F(SyscollectorImpTest, noPorts)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return("hardware"));
    EXPECT_CALL(*spInfoWrapper, packages()).WillOnce(Return("packages"));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return("os"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillOnce(Return("processes"));
    EXPECT_CALL(*spInfoWrapper, ports()).Times(0);   
    std::thread t1;
    {
        Syscollector syscollector{spInfoWrapper, "1h", true, true, true, true, true, false};
        t1 = std::thread{[&syscollector](){ syscollector.start(); }};
    }
    if (t1.joinable())
    {
        t1.join();
    }
}

TEST_F(SyscollectorImpTest, noPortsAll)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return("hardware"));
    EXPECT_CALL(*spInfoWrapper, packages()).WillOnce(Return("packages"));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return("os"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillOnce(Return("processes"));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    std::thread t1;
    {
        Syscollector syscollector{spInfoWrapper, "1h", true, true, true, true, true, true, false};
        t1 = std::thread{[&syscollector](){ syscollector.start(); }};
    }
    if (t1.joinable())
    {
        t1.join();
    }
}

TEST_F(SyscollectorImpTest, noProcesses)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return("hardware"));
    EXPECT_CALL(*spInfoWrapper, packages()).WillOnce(Return("packages"));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return("os"));
    EXPECT_CALL(*spInfoWrapper, processes()).Times(0);
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));
    std::thread t1;
    {
        Syscollector syscollector{spInfoWrapper, "1h", true, true, true, true, true, true, true, false};
        t1 = std::thread{[&syscollector](){ syscollector.start(); }};
    }
    if (t1.joinable())
    {
        t1.join();
    }
}

TEST_F(SyscollectorImpTest, noHotfixes)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillOnce(Return("hardware"));
    EXPECT_CALL(*spInfoWrapper, packages()).WillOnce(Return("packages"));
    EXPECT_CALL(*spInfoWrapper, networks()).WillOnce(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, os()).WillOnce(Return("os"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillOnce(Return("processes"));
    EXPECT_CALL(*spInfoWrapper, ports()).WillOnce(Return("ports"));    
    std::thread t1;
    {
        Syscollector syscollector{spInfoWrapper, "1h", true, true, true, true, true, true, true, true, false};
        t1 = std::thread{[&syscollector](){ syscollector.start(); }};
    }
    if (t1.joinable())
    {
        t1.join();
    }
}

TEST_F(SyscollectorImpTest, scanOnInverval)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return("hardware"));
    EXPECT_CALL(*spInfoWrapper, packages()).WillRepeatedly(Return("packages"));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return("networks"));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return("os"));
    EXPECT_CALL(*spInfoWrapper, processes()).WillRepeatedly(Return("processes"));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return("ports"));    
    std::thread t1;
    {
        Syscollector syscollector{spInfoWrapper, "1s"};
        t1 = std::thread{[&syscollector](){ syscollector.start(); }};
        std::this_thread::sleep_for(std::chrono::seconds{3});
    }
    if (t1.joinable())
    {
        t1.join();
    }
}