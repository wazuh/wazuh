/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * October 19, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "sysInfo_test.h"
#include "sysInfo.hpp"
#include "sysInfo.h"
#include "cjsonSmartDeleter.hpp"

void SysInfoTest::SetUp() {};

void SysInfoTest::TearDown()
{
};

auto PROCESSES_EXPECTED
{
    R"([{"test":"processes"}])"_json
};

auto PACKAGES_EXPECTED
{
    R"([{"test":"packages"}])"_json
};

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;

nlohmann::json SysInfo::getHardware() const
{
    return "";
}
nlohmann::json SysInfo::getPackages() const
{
    return "";
}
nlohmann::json SysInfo::getOsInfo() const
{
    return "";
}
nlohmann::json SysInfo::getProcessesInfo() const
{
    return {};
}
nlohmann::json SysInfo::getNetworks() const
{
    return {};
}
nlohmann::json SysInfo::getPorts() const
{
    return {};
}
nlohmann::json SysInfo::getHotfixes() const
{
    return {};
}
nlohmann::json SysInfo::getGroups() const
{
    return {};
}

void SysInfo::getPackages(std::function<void(nlohmann::json&)>callback) const
{
    callback(PACKAGES_EXPECTED);
}

void SysInfo::getProcessesInfo(std::function<void(nlohmann::json&)>callback) const
{
    callback(PROCESSES_EXPECTED);
}

class CallbackMock
{
    public:
        CallbackMock() = default;
        ~CallbackMock() = default;
        MOCK_METHOD(void, callbackMock, (ReturnTypeCallback type, std::string), ());
        MOCK_METHOD(void, callbackMock, (nlohmann::json&), ());
};

static void callback(const ReturnTypeCallback type,
                     const cJSON* json,
                     void* ctx)
{
    CallbackMock* wrapper { reinterpret_cast<CallbackMock*>(ctx)};
    const std::unique_ptr<char, CJsonSmartFree> spJsonBytes{ cJSON_PrintUnformatted(json) };
    wrapper->callbackMock(type, std::string(spJsonBytes.get()));
}

class SysInfoWrapper: public SysInfo
{
    public:
        SysInfoWrapper() = default;
        ~SysInfoWrapper() = default;
        MOCK_METHOD(nlohmann::json, getHardware, (), (const override));
        MOCK_METHOD(nlohmann::json, getPackages, (), (const override));
        MOCK_METHOD(nlohmann::json, getOsInfo, (), (const override));
        MOCK_METHOD(nlohmann::json, getProcessesInfo, (), (const override));
        MOCK_METHOD(nlohmann::json, getNetworks, (), (const override));
        MOCK_METHOD(nlohmann::json, getPorts, (), (const override));
        MOCK_METHOD(nlohmann::json, getHotfixes, (), (const override));
        MOCK_METHOD(nlohmann::json, getGroups, (), (const override));
        MOCK_METHOD(void, getPackages, (std::function<void(nlohmann::json&)>), (const override));
        MOCK_METHOD(void, getProcessesInfo, (std::function<void(nlohmann::json&)>), (const override));

};

TEST_F(SysInfoTest, hardware)
{
    SysInfoWrapper info;
    EXPECT_CALL(info, getHardware()).WillOnce(Return("hardware"));
    const auto result {info.hardware()};
    EXPECT_FALSE(result.empty());
}

TEST_F(SysInfoTest, packages_cb)
{
    SysInfoWrapper info;
    CallbackMock wrapper;

    auto expectedValue1
    {
        R"({"architecture":"x86_64","hostname":"TINACHO","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 95","os_release":"sp1","os_version":"6.1.7601"})"_json
    };

    auto expectedValue2
    {
        R"({"architecture":"x86_64","hostname":"OCTACORE","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 3.1","os_release":"sp1","os_version":"6.1.7601"})"_json
    };

    const auto packagesCallback
    {
        [&wrapper](nlohmann::json & data)
        {
            wrapper.callbackMock(data);
        }
    };
    EXPECT_CALL(info, getPackages(_)).WillOnce(DoAll(
                                                   testing::InvokeArgument<0>(expectedValue1),
                                                   testing::InvokeArgument<0>(expectedValue2)));
    EXPECT_CALL(wrapper, callbackMock(expectedValue1)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedValue2)).Times(1);
    info.packages(packagesCallback);
}

TEST_F(SysInfoTest, packages)
{
    SysInfoWrapper info;
    EXPECT_CALL(info, getPackages()).WillOnce(Return("packages"));
    const auto result {info.packages()};
    EXPECT_FALSE(result.empty());
}

TEST_F(SysInfoTest, processes_cb)
{
    SysInfoWrapper info;
    CallbackMock wrapper;

    auto expectedValue1
    {
        R"({"argvs":"180","cmd":"sleep","egroup":"root","euser":"root","fgroup":"root","name":"sleep","nice":0,"nlwp":1,"pgrp":2478,"pid":"193797","ppid":2480,"priority":20,"processor":2,"resident":148,"rgroup":"root","ruser":"root","session":2478,"sgroup":"root","share":132,"size":2019,"start_time":6244007,"state":"S","stime":0,"suser":"root","tgid":193797,"tty":0,"utime":0,"vm_size":8076})"_json
    };

    auto expectedValue2
    {
        R"({"argvs":"181","cmd":"ls","egroup":"dword","euser":"dword","fgroup":"dword","name":"sleep","nice":0,"nlwp":1,"pgrp":2478,"pid":"193797","ppid":2480,"priority":20,"processor":2,"resident":148,"rgroup":"root","ruser":"root","session":2478,"sgroup":"root","share":132,"size":2019,"start_time":6244007,"state":"S","stime":0,"suser":"root","tgid":193797,"tty":0,"utime":0,"vm_size":8076})"_json
    };

    const auto processesCallback
    {
        [&wrapper](nlohmann::json & data)
        {
            wrapper.callbackMock(data);
        }
    };
    EXPECT_CALL(info, getProcessesInfo(_)).WillOnce(DoAll(
                                                        testing::InvokeArgument<0>(expectedValue1),
                                                        testing::InvokeArgument<0>(expectedValue2)));
    EXPECT_CALL(wrapper, callbackMock(expectedValue1)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedValue2)).Times(1);
    info.processes(processesCallback);
}

TEST_F(SysInfoTest, processes)
{
    SysInfoWrapper info;
    EXPECT_CALL(info, getProcessesInfo()).WillOnce(Return("processes"));
    const auto result {info.processes()};
    EXPECT_FALSE(result.empty());
}

TEST_F(SysInfoTest, network)
{
    SysInfoWrapper info;
    EXPECT_CALL(info, getNetworks()).WillOnce(Return("networks"));
    const auto result {info.networks()};
    EXPECT_FALSE(result.empty());
}

TEST_F(SysInfoTest, ports)
{
    SysInfoWrapper info;
    EXPECT_CALL(info, getPorts()).WillOnce(Return("ports"));
    const auto result {info.ports()};
    EXPECT_FALSE(result.empty());
}

TEST_F(SysInfoTest, os)
{
    SysInfoWrapper info;
    EXPECT_CALL(info, getOsInfo()).WillOnce(Return("osinfo"));
    const auto result {info.os()};
    EXPECT_FALSE(result.empty());
}

TEST_F(SysInfoTest, hotfixes)
{
    SysInfoWrapper info;
    EXPECT_CALL(info, getHotfixes()).WillOnce(Return("hotfixes"));
    const auto result {info.hotfixes()};
    EXPECT_FALSE(result.empty());
}

TEST_F(SysInfoTest, hardware_c_interface)
{
    cJSON* object = NULL;
    EXPECT_EQ(0, sysinfo_hardware(&object));
    EXPECT_TRUE(object);
    EXPECT_NO_THROW(sysinfo_free_result(&object));
}

TEST_F(SysInfoTest, packages_c_interface)
{
    cJSON* object = NULL;
    EXPECT_EQ(0, sysinfo_packages(&object));
    EXPECT_TRUE(object);
    EXPECT_NO_THROW(sysinfo_free_result(&object));
}

TEST_F(SysInfoTest, packages_cb_c_interface)
{
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    EXPECT_CALL(wrapper, callbackMock(GENERIC, PACKAGES_EXPECTED.dump())).Times(1);
    EXPECT_EQ(0, sysinfo_packages_cb(callbackData));
}

TEST_F(SysInfoTest, packages_cb_c_interface_test_empty_callback)
{
    callback_data_t cb_data = { .callback = NULL, .user_data = NULL };
    EXPECT_EQ(-1, sysinfo_packages_cb(cb_data));
}

TEST_F(SysInfoTest, processes_c_interface)
{
    cJSON* object = NULL;
    EXPECT_EQ(0, sysinfo_processes(&object));
    EXPECT_TRUE(object);
    EXPECT_NO_THROW(sysinfo_free_result(&object));
}

TEST_F(SysInfoTest, processes_cb_c_interface)
{
    CallbackMock wrapper;
    callback_data_t callbackData { callback, &wrapper };
    EXPECT_CALL(wrapper, callbackMock(GENERIC, PROCESSES_EXPECTED.dump())).Times(1);
    EXPECT_EQ(0, sysinfo_processes_cb(callbackData));
}

TEST_F(SysInfoTest, processes_cb_c_interface_test_empty_callback)
{
    callback_data_t cb_data = { .callback = NULL, .user_data = NULL };
    EXPECT_EQ(-1, sysinfo_processes_cb(cb_data));
}

TEST_F(SysInfoTest, network_c_interface)
{
    cJSON* object = NULL;
    EXPECT_EQ(0, sysinfo_networks(&object));
    EXPECT_TRUE(object);
    EXPECT_NO_THROW(sysinfo_free_result(&object));
}

TEST_F(SysInfoTest, ports_c_interface)
{
    cJSON* object = NULL;
    EXPECT_EQ(0, sysinfo_ports(&object));
    EXPECT_TRUE(object);
    EXPECT_NO_THROW(sysinfo_free_result(&object));
}

TEST_F(SysInfoTest, os_c_interface)
{
    cJSON* object = NULL;
    EXPECT_EQ(0, sysinfo_os(&object));
    EXPECT_TRUE(object);
    EXPECT_NO_THROW(sysinfo_free_result(&object));
}

TEST_F(SysInfoTest, hotfixes_c_interface)
{
    cJSON* object = NULL;
    EXPECT_EQ(0, sysinfo_hotfixes(&object));
    EXPECT_TRUE(object);
    EXPECT_NO_THROW(sysinfo_free_result(&object));
}

TEST_F(SysInfoTest, c_interfaces_bad_params)
{
    EXPECT_EQ(-1, sysinfo_hardware(NULL));
    EXPECT_EQ(-1, sysinfo_packages(NULL));
    EXPECT_EQ(-1, sysinfo_processes(NULL));
    EXPECT_EQ(-1, sysinfo_ports(NULL));
    EXPECT_EQ(-1, sysinfo_os(NULL));
    EXPECT_EQ(-1, sysinfo_hotfixes(NULL));
}
