/*
 * Wazuh SyscollectorImp
 * Copyright (C) 2015, Wazuh Inc.
 * November 9, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <cstdio>
#include "syscollectorImp_test.h"
#include "syscollector.hpp"

constexpr auto SYSCOLLECTOR_DB_PATH {"TEMP.db"};

// Defines to replace inline JSON in EXPECT_CALLs
#define EXPECT_CALL_HARDWARE_JSON R"({"board_serial":"Intel Corporation","scan_time":"2020/12/28 21:49:50", "cpu_MHz":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","ram_free":2257872,"ram_total":4972208,"ram_usage":54})"
#define EXPECT_CALL_OS_JSON R"({"architecture":"x86_64","scan_time":"2020/12/28 21:49:50", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601"})"
#define EXPECT_CALL_NETWORKS_JSON R"({"iface":[{"address":"127.0.0.1","scan_time":"2020/12/28 21:49:50", "mac":"d4:5d:64:51:07:5d", "gateway":"192.168.0.1|600","broadcast":"127.255.255.255", "name":"ens1", "mtu":1500, "name":"enp4s0", "adapter":" ", "type":"ethernet", "state":"up", "dhcp":"disabled","iface":"Loopback Pseudo-Interface 1","metric":"75","netmask":"255.0.0.0","proto":"IPv4","rx_bytes":0,"rx_dropped":0,"rx_errors":0,"rx_packets":0,"tx_bytes":0,"tx_dropped":0,"tx_errors":0,"tx_packets":0, "IPv4":[{"address":"192.168.153.1","broadcast":"192.168.153.255","dhcp":"unknown","metric":" ","netmask":"255.255.255.0"}], "IPv6":[{"address":"fe80::250:56ff:fec0:8","dhcp":"unknown","metric":" ","netmask":"ffff:ffff:ffff:ffff::"}]}]})"
#define EXPECT_CALL_PORTS_JSON R"([{"inode":0,"local_ip":"127.0.0.1","scan_time":"2020/12/28 21:49:50", "local_port":631,"pid":0,"process_name":"System Idle Process","protocol":"tcp","remote_ip":"0.0.0.0","remote_port":0,"rx_queue":0,"state":"listening","tx_queue":0}])"
#define EXPECT_CALL_PACKAGES_JSON R"({"architecture":"amd64","scan_time":"2020/12/28 21:49:50", "group":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14","format":"deb","location":" "})"
#define EXPECT_CALL_HOTFIXES_JSON R"([{"hotfix":"KB12345678"}])"
#define EXPECT_CALL_PROCESSES_JSON R"({"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","scan_time":"2020/12/28 21:49:50", "nice":0,"nlwp":1,"pgrp":0,"pid":"431625","ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0})"
#define EXPECT_CALL_GROUPS_JSON R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"
#define EXPECT_CALL_USERS_JSON R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"
#define EXPECT_CALL_SERVICES_JSON R"([{"service_id":"wazuh-agent","service_name":"Wazuh Agent","service_description":"Monitors system activity","service_state":"running","service_sub_state":"subState","service_start_type":"auto","service_type":"type","process_pid":1234,"service_exit_code":0,"service_win32_exit_code":0,"process_executable":"/usr/bin/wazuh-agent","service_address":"/lib/systemd/system/wazuh-agent.service","user_name":"root","service_enabled":"enabled","service_following":"following","service_object_path":"objectPath","service_target_ephemeral_id":0,"service_target_type":"jobType","service_target_address":"jobPath","file_path":"sourcePath"}])"
#define EXPECT_CALL_BROWSER_EXTENSIONS_JSON R"([{"browser_name":"chrome","user_id":"S-1-5-21-1234567890-987654321-1122334455-1001","package_name":"uBlock Origin","package_id":"cjpalhdlnbpafiamejdnhcphjbkeiagm","package_version":"1.52.2","package_description":"Finally, an efficient wide-spectrum content blocker. Easy on CPU and memory.","package_vendor":"Raymond Hill","package_build_version":"","package_path":"C:\\Users\\john.doe\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\cjpalhdlnbpafiamejdnhcphjbkeiagm\\1.52.2_0","browser_profile_name":"Default","browser_profile_path":"C:\\Users\\john.doe\\AppData\\Local\\Google\\Chrome\\User Data\\Default","package_reference":"https://clients2.google.com/service/update2/crx","package_permissions":"[\\\"activeTab\\\",\\\"storage\\\",\\\"tabs\\\",\\\"webNavigation\\\"]","package_type":"extension","package_enabled":1,"package_visible":0,"package_autoupdate":1,"package_persistent":0,"package_from_webstore":1,"browser_profile_referenced":1,"package_installed":"1710489821000","file_hash_sha256":"a1b2c3d4e5f6789012345678901234567890abcdef123456789012345678901234","scan_time":"2020/12/28 21:49:50"}])"

const auto expected_dbsync_hwinfo
{
    R"({"data":{"board_serial":"Intel Corporation","checksum":"af7b22eef8f5e06c04af4db49c9f8d1d28963918","cpu_MHz":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","ram_free":2257872,"ram_total":4972208,"ram_usage":54},"operation":"INSERTED","type":"dbsync_hwinfo"})"
};
const auto expected_dbsync_osinfo
{
    R"({"data":{"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601"},"operation":"INSERTED","type":"dbsync_osinfo"})"
};
const auto expected_dbsync_network_iface
{
    R"({"data":{"adapter":" ","checksum":"165f7160ecd2838479ee4c43c1012b723736d90a","item_id":"25eef9a0a422a9b644fb6b73650453148bc6151c","mac":"d4:5d:64:51:07:5d","mtu":1500,"name":"enp4s0","rx_bytes":0,"rx_dropped":0,"rx_errors":0,"rx_packets":0,"state":"up","tx_bytes":0,"tx_dropped":0,"tx_errors":0,"tx_packets":0,"type":"ethernet"},"operation":"INSERTED","type":"dbsync_network_iface"})"
};
const auto expected_dbsync_network_protocol_1
{
    R"({"data":{"checksum":"ff63981c231f110a0877ac6acd8862ac09877b5d","dhcp":"unknown","gateway":"192.168.0.1|600","iface":"enp4s0","item_id":"d633b040008ea38303d778431ee2fd0b4ee5a37a","metric":" ","type":"ipv4"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
};
const auto expected_dbsync_network_protocol_2
{
    R"({"data":{"checksum":"ea17673e7422c0ab04c4f1f111a5828be8cd366a","dhcp":"unknown","gateway":"192.168.0.1|600","iface":"enp4s0","item_id":"9dff246584835755137820c975f034d089e90b6f","metric":" ","type":"ipv6"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
};
const auto expected_dbsync_network_address_1
{
    R"({"data":{"address":"fe80::250:56ff:fec0:8","checksum":"f606d1a1c551874d8fab33e4e5cfaa0370673ec8","iface":"enp4s0","item_id":"65973316a5dc8615a6d20b2d6c4ce52ecd074496","netmask":"ffff:ffff:ffff:ffff::","proto":1},"operation":"INSERTED","type":"dbsync_network_address"})"
};
const auto expected_dbsync_network_address_2
{
    R"({"data":{"address":"192.168.153.1","broadcast":"192.168.153.255","checksum":"72dfd66759bd8062cdc17607d760a48c906189b3","iface":"enp4s0","item_id":"3d48ddc47fac84c62a19746af66fbfcf78547de9","netmask":"255.255.255.0","proto":0},"operation":"INSERTED","type":"dbsync_network_address"})"
};
const auto expected_dbsync_ports
{
    R"({"data":{"checksum":"f25348b1ce5310f36c1ed859d13138fbb4e6bacb","inode":0,"item_id":"cbf2ac25a6775175f912ebf2abc72f6f51ab48ba","local_ip":"127.0.0.1","local_port":631,"pid":0,"process_name":"System Idle Process","protocol":"tcp","remote_ip":"0.0.0.0","remote_port":0,"rx_queue":0,"state":"listening","tx_queue":0},"operation":"INSERTED","type":"dbsync_ports"})"
};
const auto expected_dbsync_processes
{
    R"({"data":{"checksum":"039934723aa69928b52e470c8d27365b0924b615","egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","nice":0,"nlwp":1,"pgrp":0,"pid":"431625","ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0},"operation":"INSERTED","type":"dbsync_processes"})"
};
const auto expected_dbsync_packages
{
    R"({"data":{"architecture":"amd64","checksum":"6ec380a9a572e439b68cfe87621b8a5611c0866c","format":"deb","group":"x11","item_id":"4846c220a185b0fc251a07843efbfbb0d90ac4a5","location":" ","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14"},"operation":"INSERTED","type":"dbsync_packages"})"
};
const auto expected_dbsync_hotfixes
{
    R"({"data":{"checksum":"56162cd7bb632b4728ec868e8e271b01222ff131","hotfix":"KB12345678"},"operation":"INSERTED","type":"dbsync_hotfixes"})"
};
const auto expected_dbsync_groups
{
    R"({"data":{"checksum":"81793e529c565256a60eff6c6345e2f5c5ee8cb0","group_description":null,"group_id":1,"group_id_signed":1,"group_is_hidden":0,"group_name":"daemon","group_users":"daemon:pollinate:vboxadd","group_uuid":null},"operation":"INSERTED","type":"dbsync_groups"})"
};
const auto expected_dbsync_users
{
    R"({"data":{"checksum":"11769088416d594d547a508e084cec990e282ece","host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null},"operation":"INSERTED","type":"dbsync_users"})"
};
const auto expected_dbsync_services
{
    R"({"data":{"checksum":"daa615e783788aec35ae17eeed912ace3910f209","file_path":"sourcePath","item_id":"cced25cebdc8af9754617e3f42b16720fd7697f6","process_executable":"/usr/bin/wazuh-agent","process_pid":1234,"service_address":"/lib/systemd/system/wazuh-agent.service","service_description":"Monitors system activity","service_enabled":"enabled","service_exit_code":0,"service_following":"following","service_id":"wazuh-agent","service_name":"Wazuh Agent","service_object_path":"objectPath","service_start_type":"auto","service_state":"running","service_sub_state":"subState","service_target_address":"jobPath","service_target_ephemeral_id":0,"service_target_type":"jobType","service_type":"type","service_win32_exit_code":0,"user_name":"root"},"operation":"INSERTED","type":"dbsync_services"})"
};
const auto expected_dbsync_browser_extensions
{
    R"({"data":{"browser_name":"chrome","browser_profile_name":"Default","browser_profile_path":"C:\\Users\\john.doe\\AppData\\Local\\Google\\Chrome\\User Data\\Default","browser_profile_referenced":1,"checksum":"5aa95635af540c2cdea58f889d617622f5abd49e","file_hash_sha256":"a1b2c3d4e5f6789012345678901234567890abcdef123456789012345678901234","item_id":"8fb19502963fccc83099831f9ee9583fe3077540","package_autoupdate":1,"package_description":"Finally, an efficient wide-spectrum content blocker. Easy on CPU and memory.","package_enabled":1,"package_from_webstore":1,"package_id":"cjpalhdlnbpafiamejdnhcphjbkeiagm","package_installed":"1710489821000","package_name":"uBlock Origin","package_path":"C:\\Users\\john.doe\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\cjpalhdlnbpafiamejdnhcphjbkeiagm\\1.52.2_0","package_permissions":"[\\\"activeTab\\\",\\\"storage\\\",\\\"tabs\\\",\\\"webNavigation\\\"]","package_persistent":0,"package_reference":"https://clients2.google.com/service/update2/crx","package_type":"extension","package_vendor":"Raymond Hill","package_version":"1.52.2","package_visible":0,"user_id":"S-1-5-21-1234567890-987654321-1122334455-1001"},"operation":"INSERTED","type":"dbsync_browser_extensions"})"
};


const auto expected_syscollector_osinfo
{
    R"({"component":"syscollector_osinfo","data":{"begin":"Microsoft Windows 7","end":"Microsoft Windows 7"},"type":"integrity_check_global"})"
};
const auto expected_syscollector_hwinfo
{
    R"({"component":"syscollector_hwinfo","data":{"begin":"Intel Corporation","end":"Intel Corporation"},"type":"integrity_check_global"})"
};
const auto expected_syscollector_network_iface
{
    R"({"component":"syscollector_network_iface","data":{"begin":"25eef9a0a422a9b644fb6b73650453148bc6151c","end":"25eef9a0a422a9b644fb6b73650453148bc6151c"},"type":"integrity_check_global"})"
};
const auto expected_syscollector_network_protocol
{
    R"({"component":"syscollector_network_protocol","data":{"begin":"9dff246584835755137820c975f034d089e90b6f","end":"d633b040008ea38303d778431ee2fd0b4ee5a37a"},"type":"integrity_check_global"})"
};
const auto expected_syscollector_network_address
{
    R"({"component":"syscollector_network_address","data":{"begin":"3d48ddc47fac84c62a19746af66fbfcf78547de9","end":"65973316a5dc8615a6d20b2d6c4ce52ecd074496"},"type":"integrity_check_global"})"
};
const auto expected_syscollector_ports
{
    R"({"component":"syscollector_ports","data":{"begin":"cbf2ac25a6775175f912ebf2abc72f6f51ab48ba","end":"cbf2ac25a6775175f912ebf2abc72f6f51ab48ba"},"type":"integrity_check_global"})"
};
const auto expected_syscollector_processes
{
    R"({"component":"syscollector_processes","data":{"begin":"431625","end":"431625"},"type":"integrity_check_global"})"
};
const auto expected_syscollector_packages
{
    R"({"component":"syscollector_packages","data":{"begin":"4846c220a185b0fc251a07843efbfbb0d90ac4a5","end":"4846c220a185b0fc251a07843efbfbb0d90ac4a5"},"type":"integrity_check_global"})"
};
const auto expected_syscollector_hotfixes
{
    R"({"component":"syscollector_hotfixes","data":{"begin":"KB12345678","end":"KB12345678"},"type":"integrity_check_global"})"
};
const auto expected_syscollector_groups
{
    R"({"component":"syscollector_groups","data":{"begin":"daemon","end":"daemon"},"type":"integrity_check_global"})"
};
const auto expected_syscollector_users
{
    R"({"component":"syscollector_users","data":{"begin":"root","end":"root"},"type":"integrity_check_global"})"
};
const auto expected_syscollector_services
{
    R"({"component":"syscollector_services","data":{"begin":"cced25cebdc8af9754617e3f42b16720fd7697f6","end":"cced25cebdc8af9754617e3f42b16720fd7697f6"},"type":"integrity_check_global"})"
};
const auto expected_syscollector_browser_extensions
{
    R"({"component":"syscollector_browser_extensions","data":{"begin":"8fb19502963fccc83099831f9ee9583fe3077540","end":"8fb19502963fccc83099831f9ee9583fe3077540"},"type":"integrity_check_global"})"
};


void SyscollectorImpTest::SetUp() {};

void SyscollectorImpTest::TearDown()
{
    std::remove(SYSCOLLECTOR_DB_PATH);
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
        MOCK_METHOD(void, packages, (std::function<void(nlohmann::json&)>), (override));
        MOCK_METHOD(nlohmann::json, os, (), (override));
        MOCK_METHOD(nlohmann::json, networks, (), (override));
        MOCK_METHOD(nlohmann::json, processes, (), (override));
        MOCK_METHOD(void, processes, (std::function<void(nlohmann::json&)>), (override));
        MOCK_METHOD(nlohmann::json, ports, (), (override));
        MOCK_METHOD(nlohmann::json, hotfixes, (), (override));
        MOCK_METHOD(nlohmann::json, groups, (), (override));
        MOCK_METHOD(nlohmann::json, users, (), (override));
        MOCK_METHOD(nlohmann::json, services, (), (override));
        MOCK_METHOD(nlohmann::json, browserExtensions, (), (override));
};

class CallbackMock
{
    public:
        CallbackMock() = default;
        ~CallbackMock() = default;
        MOCK_METHOD(void, callbackMock, (const std::string&), ());
};

void reportFunction(const std::string& /*payload*/)
{
    //std::cout << payload << std::endl;
}

void logFunction(const modules_log_level_t /*level*/, const std::string& /*log*/)
{
    //static const std::map<modules_log_level_t, std::string> s_logStringMap
    // {
    //     {LOG_ERROR, "ERROR"},
    //     {LOG_INFO, "INFO"},
    //     {LOG_DEBUG, "DEBUG"},
    //     {LOG_DEBUG_VERBOSE, "DEBUG2"}
    // };
    // std::cout << s_logStringMap.at(level) << ": " << log << std::endl;
}

TEST_F(SyscollectorImpTest, defaultCtor)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_NETWORKS_JSON)));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_PORTS_JSON)));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PACKAGES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HOTFIXES_JSON)));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PROCESSES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_GROUPS_JSON)));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_USERS_JSON)));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("id");
            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta.at("type").get_ref<const std::string&>().compare("dbsync_osinfo") == 0)
            {
                delta["data"].erase("checksum");
            }

            delta["data"].erase("scan_time");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hwinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_osinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_iface)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_ports)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_processes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_packages)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_osinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_iface)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_protocol)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_address)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_ports)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_processes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hwinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_packages)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hotfixes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_groups)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_users)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_services)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_browser_extensions)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData, &callbackDataDelta]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackData,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          5, true, true, true, true, true, true, true, true, true, true, true, true, true, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(2));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, intervalSeconds)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_NETWORKS_JSON)));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_PORTS_JSON)));
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix":"KB12345678"},{"hotfix":"KB87654321"}])"_json));
    EXPECT_CALL(*spInfoWrapper, processes(_)).Times(::testing::AtLeast(2)).WillRepeatedly(testing::InvokeArgument<0>(nlohmann::json::parse(EXPECT_CALL_PROCESSES_JSON)));

    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(2))
    .WillRepeatedly(::testing::InvokeArgument<0>
                    (R"({"name":"TEXT", "scan_time":"2020/12/28 21:49:50", "version":"TEXT", "vendor":"TEXT", "install_time":"TEXT", "location":"TEXT", "architecture":"TEXT", "groups":"TEXT", "description":"TEXT", "size":"TEXT", "priority":"TEXT", "multiarch":"TEXT", "source":"TEXT", "os_patch":"TEXT"})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_GROUPS_JSON)));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_USERS_JSON)));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    std::thread t
    {
        [&spInfoWrapper]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          reportFunction,
                                          reportFunction,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          1, true, true, true, true, true, true, true, true, true, true, true, true, true, true);

        }
    };

    std::this_thread::sleep_for(std::chrono::seconds{10});
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, noScanOnStart)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);
    EXPECT_CALL(*spInfoWrapper, packages(_)).Times(0);
    EXPECT_CALL(*spInfoWrapper, networks()).Times(0);
    EXPECT_CALL(*spInfoWrapper, processes(_)).Times(0);
    EXPECT_CALL(*spInfoWrapper, ports()).Times(0);
    EXPECT_CALL(*spInfoWrapper, hotfixes()).Times(0);
    EXPECT_CALL(*spInfoWrapper, groups()).Times(0);
    EXPECT_CALL(*spInfoWrapper, users()).Times(0);

    std::thread t
    {
        [&spInfoWrapper]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          reportFunction,
                                          reportFunction,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, false);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds{2});
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, noHardware)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_NETWORKS_JSON)));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_PORTS_JSON)));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PACKAGES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HOTFIXES_JSON)));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PROCESSES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_GROUPS_JSON)));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_USERS_JSON)));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("id");
            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta["type"].get_ref<const std::string&>().compare("dbsync_osinfo") == 0)
            {
                delta["data"].erase("checksum");
            }

            delta["data"].erase("scan_time");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto integrity_clear
    {
        R"({"component":"syscollector_hwinfo","data":{},"type":"integrity_clear"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_osinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_iface)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_ports)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_processes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_packages)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_osinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_iface)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_protocol)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_address)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_ports)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_processes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_packages)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hotfixes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_groups)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_users)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_services)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(integrity_clear)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData, &callbackDataDelta]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackData,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, false, true, true, true, true, true, true, true, true, true, true, true, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(1));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }

}

TEST_F(SyscollectorImpTest, noOs)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_NETWORKS_JSON)));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_PORTS_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PACKAGES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HOTFIXES_JSON)));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PROCESSES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_GROUPS_JSON)));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_USERS_JSON)));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("id");
            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta["type"].get_ref<const std::string&>().compare("dbsync_osinfo") == 0)
            {
                delta["data"].erase("checksum");
            }

            delta["data"].erase("scan_time");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto integrity_clear
    {
        R"({"component":"syscollector_osinfo","data":{},"type":"integrity_clear"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hwinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_iface)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_ports)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_processes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_packages)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hwinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_iface)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_protocol)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_address)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_ports)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_processes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_packages)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hotfixes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_groups)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_users)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_services)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(integrity_clear)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData, &callbackDataDelta]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackData,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, false, true, true, true, true, true, true, true, true, true, true, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(2));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, noNetwork)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).Times(0);
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_PORTS_JSON)));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PACKAGES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HOTFIXES_JSON)));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PROCESSES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_GROUPS_JSON)));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_USERS_JSON)));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("id");
            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta["type"].get_ref<const std::string&>().compare("dbsync_osinfo") == 0)
            {
                delta["data"].erase("checksum");
            }

            delta["data"].erase("scan_time");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto integrity_clear_network_protocol
    {
        R"({"component":"syscollector_network_protocol","data":{},"type":"integrity_clear"})"
    };
    const auto integrity_clear_network_address
    {
        R"({"component":"syscollector_network_address","data":{},"type":"integrity_clear"})"
    };
    const auto integrity_clear_network_iface
    {
        R"({"component":"syscollector_network_iface","data":{},"type":"integrity_clear"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hwinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_osinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_ports)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_processes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_packages)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hwinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_osinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_ports)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_processes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_packages)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hotfixes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_groups)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_users)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_services)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(integrity_clear_network_protocol)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(integrity_clear_network_address)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(integrity_clear_network_iface)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData, &callbackDataDelta]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackData,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, false, true, true, true, true, true, true, true, true, true, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(1));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, noPackages)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_NETWORKS_JSON)));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_PORTS_JSON)));
    EXPECT_CALL(*spInfoWrapper, packages(_)).Times(0);
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HOTFIXES_JSON)));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PROCESSES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_GROUPS_JSON)));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_USERS_JSON)));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("id");
            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta["type"].get_ref<const std::string&>().compare("dbsync_osinfo") == 0)
            {
                delta["data"].erase("checksum");
            }

            delta["data"].erase("scan_time");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto integrity_clear
    {
        R"({"component":"syscollector_packages","data":{},"type":"integrity_clear"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hwinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_osinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_iface)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_ports)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_processes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hwinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_osinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_iface)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_protocol)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_address)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_ports)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_processes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hotfixes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_groups)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_users)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_services)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(integrity_clear)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackData]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackData,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, true, false, true, true, true, true, true, true, true, true, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds{2});
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, noPorts)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_NETWORKS_JSON)));
    EXPECT_CALL(*spInfoWrapper, ports()).Times(0);
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PACKAGES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HOTFIXES_JSON)));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PROCESSES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_GROUPS_JSON)));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_USERS_JSON)));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("id");
            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta["type"].get_ref<const std::string&>().compare("dbsync_osinfo") == 0)
            {
                delta["data"].erase("checksum");
            }

            delta["data"].erase("scan_time");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto integrity_clear
    {
        R"({"component":"syscollector_ports","data":{},"type":"integrity_clear"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hwinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_osinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_iface)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_packages)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_processes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hwinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_osinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_iface)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_protocol)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_address)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_packages)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_processes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hotfixes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_groups)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_users)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_services)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(integrity_clear)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData, &callbackDataDelta]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackData,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          5, true, true, true, true, true, false, true, true, true, true, true, true, true, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(1));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, noPortsAll)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_NETWORKS_JSON)));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_PORTS_JSON)));

    EXPECT_CALL(*spInfoWrapper, packages(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PACKAGES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HOTFIXES_JSON)));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PROCESSES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_GROUPS_JSON)));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_USERS_JSON)));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("id");
            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta["type"].get_ref<const std::string&>().compare("dbsync_osinfo") == 0)
            {
                delta["data"].erase("checksum");
            }

            delta["data"].erase("scan_time");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hwinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_osinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_iface)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_packages)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_processes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_ports)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hwinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_osinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_iface)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_protocol)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_address)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_packages)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_processes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_ports)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hotfixes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_groups)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_users)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_services)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_browser_extensions)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData, &callbackDataDelta]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackData,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, true, true, true, false, true, true, true, true, true, true, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(1));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, noProcesses)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_NETWORKS_JSON)));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_PORTS_JSON)));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PACKAGES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HOTFIXES_JSON)));
    EXPECT_CALL(*spInfoWrapper, processes(_)).Times(0);
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_GROUPS_JSON)));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_USERS_JSON)));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("id");
            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta["type"].get_ref<const std::string&>().compare("dbsync_osinfo") == 0)
            {
                delta["data"].erase("checksum");
            }

            delta["data"].erase("scan_time");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto integrity_clear
    {
        R"({"component":"syscollector_processes","data":{},"type":"integrity_clear"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hwinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_osinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_iface)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_packages)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_ports)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hwinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_osinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_iface)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_protocol)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_address)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_packages)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_ports)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hotfixes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_groups)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_users)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_services)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(integrity_clear)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData, &callbackDataDelta]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackData,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, true, true, true, true, false, true, true, true, true, true, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds{2});
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, noHotfixes)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_NETWORKS_JSON)));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_PORTS_JSON)));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PACKAGES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, hotfixes()).Times(0);
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PROCESSES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_GROUPS_JSON)));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_USERS_JSON)));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("id");
            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta["type"].get_ref<const std::string&>().compare("dbsync_osinfo") == 0)
            {
                delta["data"].erase("checksum");
            }

            delta["data"].erase("scan_time");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto integrity_clear
    {
        R"({"component":"syscollector_hotfixes","data":{},"type":"integrity_clear"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hwinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_osinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_iface)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_packages)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_ports)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_processes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hwinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_osinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_iface)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_protocol)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_address)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_packages)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_ports)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_processes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_groups)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_users)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_services)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(integrity_clear)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData, &callbackDataDelta]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackData,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, true, true, true, true, true, false, true, true, true, true, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds{2});
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, noUsers)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_NETWORKS_JSON)));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_PORTS_JSON)));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PACKAGES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HOTFIXES_JSON)));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PROCESSES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_GROUPS_JSON)));
    EXPECT_CALL(*spInfoWrapper, users()).Times(0);
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("id");
            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta["type"].get_ref<const std::string&>().compare("dbsync_osinfo") == 0)
            {
                delta["data"].erase("checksum");
            }

            delta["data"].erase("scan_time");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto integrity_clear
    {
        R"({"component":"syscollector_users","data":{},"type":"integrity_clear"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hwinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_osinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_iface)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_packages)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_ports)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_processes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hwinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_osinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_iface)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_protocol)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_address)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_packages)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_ports)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_processes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hotfixes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_groups)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_services)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(integrity_clear)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData, &callbackDataDelta]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackData,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, true, true, true, true, true, true, true, false, true, true, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds{2});
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, noGroups)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_NETWORKS_JSON)));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_PORTS_JSON)));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PACKAGES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HOTFIXES_JSON)));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PROCESSES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, groups()).Times(0);
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_USERS_JSON)));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("id");
            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta["type"].get_ref<const std::string&>().compare("dbsync_osinfo") == 0)
            {
                delta["data"].erase("checksum");
            }

            delta["data"].erase("scan_time");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto integrity_clear
    {
        R"({"component":"syscollector_groups","data":{},"type":"integrity_clear"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hwinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_osinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_iface)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_packages)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_ports)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_processes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hwinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_osinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_iface)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_protocol)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_address)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_packages)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_ports)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_processes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hotfixes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_users)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_services)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(integrity_clear)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData, &callbackDataDelta]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackData,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, true, true, true, true, true, true, false, true, true, true, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(1));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, noServices)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_NETWORKS_JSON)));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_PORTS_JSON)));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PACKAGES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HOTFIXES_JSON)));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PROCESSES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_GROUPS_JSON)));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_USERS_JSON)));
    EXPECT_CALL(*spInfoWrapper, services()).Times(0);
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("id");
            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta["type"].get_ref<const std::string&>().compare("dbsync_osinfo") == 0)
            {
                delta["data"].erase("checksum");
            }

            delta["data"].erase("scan_time");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto integrity_clear
    {
        R"({"component":"syscollector_services","data":{},"type":"integrity_clear"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hwinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_osinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_iface)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_packages)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_ports)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_processes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hwinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_osinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_iface)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_protocol)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_address)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_packages)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_ports)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_processes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hotfixes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_users)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_groups)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(integrity_clear)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData, &callbackDataDelta]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackData,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, true, true, true, true, true, true, true, true, false, true, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(1));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, noBrowserExtensions)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_NETWORKS_JSON)));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_PORTS_JSON)));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PACKAGES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HOTFIXES_JSON)));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PROCESSES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_GROUPS_JSON)));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_USERS_JSON)));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).Times(0);

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("id");
            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta["type"].get_ref<const std::string&>().compare("dbsync_osinfo") == 0)
            {
                delta["data"].erase("checksum");
            }

            delta["data"].erase("scan_time");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto integrity_clear
    {
        R"({"component":"syscollector_browser_extensions","data":{},"type":"integrity_clear"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hwinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_osinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_iface)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_packages)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_ports)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_processes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hwinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_osinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_iface)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_protocol)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_address)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_packages)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_ports)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_processes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hotfixes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_users)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_groups)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_services)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(integrity_clear)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData, &callbackDataDelta]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackData,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, true, true, true, true, true, true, true, true, true, false, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(1));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, pushMessageOk)
{
    constexpr auto messageToPush{R"(syscollector_network_iface dbsync checksum_fail {"begin":"25eef9a0a422a9b644fb6b73650453148bc6151c","end":"25eef9a0a422a9b644fb6b73650453148bc6151c","id":1606851004})"};
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_NETWORKS_JSON)));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_PORTS_JSON)));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PACKAGES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HOTFIXES_JSON)));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PROCESSES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_GROUPS_JSON)));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_USERS_JSON)));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    std::thread t
    {
        [&spInfoWrapper]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          reportFunction,
                                          reportFunction,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          60, true, true, true, true, true, true, true, true, true, true, true, true, true, true);
        }
    };
    std::this_thread::sleep_for(std::chrono::seconds{1});
    Syscollector::instance().push(messageToPush);
    std::this_thread::sleep_for(std::chrono::seconds{1});
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, pushMessageOk1)
{
    constexpr auto messageToPush{R"(syscollector_processes dbsync checksum_fail {"begin":"1","end":"99","id":1})"};
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_NETWORKS_JSON)));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_PORTS_JSON)));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PACKAGES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HOTFIXES_JSON)));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .WillOnce([](const std::function<void(nlohmann::json&)>& cb)
    {
        auto data = nlohmann::json::parse(EXPECT_CALL_PROCESSES_JSON);
        cb(data);
    });
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_GROUPS_JSON)));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_USERS_JSON)));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("id");
            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta["type"].get_ref<const std::string&>().compare("dbsync_osinfo") == 0)
            {
                delta["data"].erase("checksum");
            }

            delta["data"].erase("scan_time");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hwinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_osinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_iface)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_packages)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_ports)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_processes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hwinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_osinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_iface)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_protocol)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_address)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_packages)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_ports)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_processes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hotfixes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_users)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_groups)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_services)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_browser_extensions)).Times(1);

    std::thread t
    {
        [&callbackData, &callbackDataDelta, &spInfoWrapper]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackData,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          60, true, true, true, true, true, true, true, true, true, true, true, true, true, true);
        }
    };
    std::this_thread::sleep_for(std::chrono::seconds{1});
    Syscollector::instance().push(messageToPush);
    std::this_thread::sleep_for(std::chrono::seconds{1});
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, pushMessageInvalid)
{
    constexpr auto messageToPush{R"(syscollector_network_iface dbsync checksum_fail {"end":"Loopback Pseudo-Interface 1","id":1606851004})"};
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"board_serial":"Intel Corporation","scan_time":"2020/12/28 21:49:50", "cpu_MHz":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","ram_free":2257872,"ram_total":4972208,"ram_usage":54})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"address":"127.0.0.1","scan_time":"2020/12/28 21:49:50", "mac":"d4:5d:64:51:07:5d", "gateway":"192.168.0.1|600","broadcast":"127.255.255.255", "name":"ens1", "mtu":1500, "name":"enp4s0", "adapter":" ", "type":"ethernet", "state":"up", "dhcp":"disabled","iface":"Loopback Pseudo-Interface 1","metric":"75","netmask":"255.0.0.0","proto":"IPv4","rx_bytes":0,"rx_dropped":0,"rx_errors":0,"rx_packets":0,"tx_bytes":0,"tx_dropped":0,"tx_errors":0,"tx_packets":0, "IPv4":[{"address":"192.168.153.1","broadcast":"192.168.153.255","dhcp":"unknown","metric":" ","netmask":"255.255.255.0"}], "IPv6":[{"address":"fe80::250:56ff:fec0:8","dhcp":"unknown","metric":" ","netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":"x86_64","scan_time":"2020/12/28 21:49:50", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"inode":0,"local_ip":"127.0.0.1","scan_time":"2020/12/28 21:49:50", "local_port":631,"pid":0,"process_name":"System Idle Process","protocol":"tcp","remote_ip":"0.0.0.0","remote_port":0,"rx_queue":0,"state":"listening","tx_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix":"KB12345678"},{"hotfix":"KB87654321"}])"_json));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"TEXT", "scan_time":"2020/12/28 21:49:50", "version":"TEXT", "vendor":"TEXT", "install_time":"TEXT", "location":"TEXT", "architecture":"TEXT", "groups":"TEXT", "description":"TEXT", "size":"TEXT", "priority":"TEXT", "multiarch":"TEXT", "source":"TEXT", "os_patch":"TEXT"})"_json));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","scan_time":"2020/12/28 21:49:50", "nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    std::thread t
    {
        [&spInfoWrapper]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          reportFunction,
                                          reportFunction,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          60, true, true, true, true, true, true, true, true, true, true, true, true, true, true);
        }
    };
    std::this_thread::sleep_for(std::chrono::seconds{1});
    Syscollector::instance().push(messageToPush);
    std::this_thread::sleep_for(std::chrono::seconds{1});
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, scanInvalidData)
{
    constexpr auto messageToPush{R"(syscollector_network_iface dbsync checksum_fail {"end":"Loopback Pseudo-Interface 1","id":1606851004})"};
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"board_serial":"Intel Corporation","scan_time":"2020/12/28 21:49:50", "cpu_MHz":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","ram_free":2257872,"ram_total":4972208,"ram_usage":54})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"address":"127.0.0.1","scan_time":"2020/12/28 21:49:50", "mac":"d4:5d:64:51:07:5d", "gateway":"192.168.0.1|600","broadcast":"127.255.255.255", "name":"ens1", "mtu":1500, "name":"enp4s0", "adapter":" ", "type":"ethernet", "state":"up", "dhcp":"disabled","iface":"Loopback Pseudo-Interface 1","metric":"75","netmask":"255.0.0.0","proto":"IPv4","rx_bytes":0,"rx_dropped":0,"rx_errors":0,"rx_packets":0,"tx_bytes":0,"tx_dropped":0,"tx_errors":0,"tx_packets":0, "IPv4":[{"address":"192.168.153.1","broadcast":"192.168.153.255","dhcp":"unknown","metric":" ","netmask":"255.255.255.0"}], "IPv6":[{"address":"fe80::250:56ff:fec0:8","dhcp":"unknown","metric":" ","netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":"x86_64","scan_time":"2020/12/28 21:49:50", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"inode":0,"local_ip":"127.0.0.1","scan_time":"2020/12/28 21:49:50", "local_port":631,"pid":0,"process_name":"System Idle Process","protocol":"tcp","remote_ip":"0.0.0.0","remote_port":0,"rx_queue":0,"state":"listening","tx_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix":"KB12345678"},{"hotfix":"KB87654321"}])"_json));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"TEXT", "scan_time":"2020/12/28 21:49:50", "version":"TEXT", "vendor":"TEXT", "install_time":"TEXT", "location":"TEXT", "architecture":"TEXT", "groups":"TEXT", "description":"TEXT", "size":"TEXT", "priority":"TEXT", "multiarch":"TEXT", "source":"TEXT", "os_patch":"TEXT"})"_json));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"egroup":"root","euser":"root","fgroup":"root","name":"kworker/u256:2-","scan_time":"2020/12/28 21:49:50", "nice":0,"nlwp":1,"pgrp":0,"pid":431625,"ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    std::thread t
    {
        [&spInfoWrapper]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          reportFunction,
                                          reportFunction,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          60, true, true, true, true, true, true, true, true, true, true, true, true, true, true);
        }
    };
    std::this_thread::sleep_for(std::chrono::seconds{1});
    Syscollector::instance().push(messageToPush);
    std::this_thread::sleep_for(std::chrono::seconds{1});
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, portAllEnable)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(R"(
    [
        {
            "inode":43481,
            "local_ip":"0.0.0.0",
            "local_port":47748,
            "pid":0,
            "process_name":"",
            "protocol":"udp",
            "remote_ip":"0.0.0.0",
            "remote_port":0,
            "rx_queue":0,
            "state":"",
            "tx_queue":0
        },
        {
            "inode":43482,
            "local_ip":"::",
            "local_port":51087,
            "pid":0,
            "process_name":"",
            "protocol":"udp6",
            "remote_ip":"::",
            "remote_port":0,
            "rx_queue":0,
            "state":"",
            "tx_queue":0
        },
        {
            "inode":50324,
            "local_ip":"127.0.0.1",
            "local_port":33060,
            "pid":0,
            "process_name":"",
            "protocol":"tcp",
            "remote_ip":"0.0.0.0",
            "remote_port":0,
            "rx_queue":0,
            "state":"listening",
            "tx_queue":0
        },
        {
            "inode":122575,
            "local_ip":"192.168.0.104",
            "local_port":39106,
            "pid":0,
            "process_name":"",
            "protocol":"tcp",
            "remote_ip":"44.238.116.130",
            "remote_port":443,
            "rx_queue":0,
            "state":"established",
            "tx_queue":0
        },
        {
            "inode":122575,
            "local_ip":"192.168.0.104",
            "local_port":39106,
            "pid":0,
            "process_name":"",
            "protocol":"tcp",
            "remote_ip":"44.238.116.130",
            "remote_port":443,
            "rx_queue":0,
            "state":"established",
            "tx_queue":0
        }
    ])")));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("scan_time");
            wrapper.callbackMock(delta.dump());
        }
    };
    const auto expectedResult1
    {
        R"({"data":{"inode":43481,"item_id":"12903a43db24ab10d872547cdd1d786a5876a0da","local_ip":"0.0.0.0","local_port":47748,"pid":0,"protocol":"udp","remote_ip":"0.0.0.0","remote_port":0,"rx_queue":0,"tx_queue":0},"operation":"INSERTED","type":"dbsync_ports"})"
    };

    const auto expectedResult2
    {
        R"({"data":{"inode":43482,"item_id":"ca7c9aff241cb251c6ad31e30b806366ecb2ad5f","local_ip":"::","local_port":51087,"pid":0,"protocol":"udp6","remote_ip":"::","remote_port":0,"rx_queue":0,"tx_queue":0},"operation":"INSERTED","type":"dbsync_ports"})"
    };

    const auto expectedResult3
    {
        R"({"data":{"inode":50324,"item_id":"8c790ef53962dd27f4516adb1d7f3f6096bc6d29","local_ip":"127.0.0.1","local_port":33060,"pid":0,"protocol":"tcp","remote_ip":"0.0.0.0","remote_port":0,"rx_queue":0,"state":"listening","tx_queue":0},"operation":"INSERTED","type":"dbsync_ports"})"
    };

    const auto expectedResult4
    {
        R"({"data":{"inode":122575,"item_id":"d5511242275bd3f2d57175f248108d6c3b39c438","local_ip":"192.168.0.104","local_port":39106,"pid":0,"protocol":"tcp","remote_ip":"44.238.116.130","remote_port":443,"rx_queue":0,"state":"established","tx_queue":0},"operation":"INSERTED","type":"dbsync_ports"})"
    };

    EXPECT_CALL(wrapper, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult3)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult4)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackData,
                                          reportFunction,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, false, false, false, false, true, true, false, false, false, false, false, false, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds{2});
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, portAllDisable)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(R"(
    [
        {
            "inode":43481,
            "local_ip":"0.0.0.0",
            "local_port":47748,
            "pid":0,
            "process_name":"",
            "protocol":"udp",
            "remote_ip":"0.0.0.0",
            "remote_port":0,
            "rx_queue":0,
            "state":"",
            "tx_queue":0
        },
        {
            "inode":43482,
            "local_ip":"::",
            "local_port":51087,
            "pid":0,
            "process_name":"",
            "protocol":"udp6",
            "remote_ip":"::",
            "remote_port":0,
            "rx_queue":0,
            "state":"",
            "tx_queue":0
        },
        {
            "inode":50324,
            "local_ip":"127.0.0.1",
            "local_port":33060,
            "pid":0,
            "process_name":"",
            "protocol":"tcp",
            "remote_ip":"0.0.0.0",
            "remote_port":0,
            "rx_queue":0,
            "state":"listening",
            "tx_queue":0
        },
        {
            "inode":50324,
            "local_ip":"127.0.0.1",
            "local_port":33060,
            "pid":0,
            "process_name":"",
            "protocol":"tcp",
            "remote_ip":"0.0.0.0",
            "remote_port":0,
            "rx_queue":0,
            "state":"listening",
            "tx_queue":0
        },
        {
            "inode":122575,
            "local_ip":"192.168.0.104",
            "local_port":39106,
            "pid":0,
            "process_name":"",
            "protocol":"tcp",
            "remote_ip":"44.238.116.130",
            "remote_port":443,
            "rx_queue":0,
            "state":"established",
            "tx_queue":0
        }
    ])")));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("scan_time");
            wrapper.callbackMock(delta.dump());
        }
    };
    const auto expectedResult1
    {
        R"({"data":{"inode":43481,"item_id":"12903a43db24ab10d872547cdd1d786a5876a0da","local_ip":"0.0.0.0","local_port":47748,"pid":0,"protocol":"udp","remote_ip":"0.0.0.0","remote_port":0,"rx_queue":0,"tx_queue":0},"operation":"INSERTED","type":"dbsync_ports"})"
    };

    const auto expectedResult2
    {
        R"({"data":{"inode":43482,"item_id":"ca7c9aff241cb251c6ad31e30b806366ecb2ad5f","local_ip":"::","local_port":51087,"pid":0,"protocol":"udp6","remote_ip":"::","remote_port":0,"rx_queue":0,"tx_queue":0},"operation":"INSERTED","type":"dbsync_ports"})"
    };

    const auto expectedResult3
    {
        R"({"data":{"inode":50324,"item_id":"8c790ef53962dd27f4516adb1d7f3f6096bc6d29","local_ip":"127.0.0.1","local_port":33060,"pid":0,"protocol":"tcp","remote_ip":"0.0.0.0","remote_port":0,"rx_queue":0,"state":"listening","tx_queue":0},"operation":"INSERTED","type":"dbsync_ports"})"
    };

    EXPECT_CALL(wrapper, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult3)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackData,
                                          reportFunction,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, false, false, false, false, true, false, false, false, false, false, false, false, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds{2});
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}


TEST_F(SyscollectorImpTest, PackagesDuplicated)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};

    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::DoAll(
                  ::testing::InvokeArgument<0>
                  (R"({"architecture":"amd64","scan_time":"2020/12/28 21:49:50", "group":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14","format":"deb","location":" "})"_json),
                  ::testing::InvokeArgument<0>
                  (R"({"architecture":"amd64","scan_time":"2020/12/28 21:49:50", "group":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14","format":"deb","location":" "})"_json)));



    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("scan_time");
            wrapper.callbackMock(delta.dump());
        }
    };

    const auto expectedResult1
    {
        R"({"data":{"architecture":"amd64","format":"deb","group":"x11","item_id":"4846c220a185b0fc251a07843efbfbb0d90ac4a5","location":" ","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14"},"operation":"INSERTED","type":"dbsync_packages"})"
    };

    EXPECT_CALL(wrapper, callbackMock(expectedResult1)).Times(1);
    std::thread t
    {
        [&spInfoWrapper, &callbackData]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackData,
                                          reportFunction,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, false, false, false, true, false, false, false, false, false, false, false, false, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds{2});
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, sanitizeJsonValues)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"board_serial":" Intel Corporation","scan_time":"2020/12/28 21:49:50 ", "cpu_MHz":2904,"cpu_cores":2,"cpu_name":" Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz ", "ram_free":2257872,"ram_total":4972208,"ram_usage":54})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":" x86_64","scan_time":"2020/12/28 21:49:50 ", "hostname":" UBUNTU ","os_build":"  7601","os_major":"6  ","os_minor":"  1  ","os_name":" Microsoft   Windows  7 ","os_release":"   sp1","os_version":"6.1.7601   "})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"address":"127.0.0.1 ","scan_time":" 2020/12/28 21:49:50", "mac":" d4:5d:64:51:07:5d ", "gateway":"  192.168.0.1|600","broadcast":"127.255.255.255  ", "name":"  ens1  ", "mtu":1500, "name":"enp4s0", "adapter":" ", "type":"   ethernet", "state":"up   ", "dhcp":"disabled","iface":"Loopback Pseudo-Interface 1","metric":"75","netmask":"255.0.0.0","proto":"IPv4","rx_bytes":0,"rx_dropped":0,"rx_errors":0,"rx_packets":0,"tx_bytes":0,"tx_dropped":0,"tx_errors":0,"tx_packets":0, "IPv4":[{"address":"192.168.153.1","broadcast":"192.168.153.255","dhcp":"unknown","metric":" ","netmask":"255.255.255.0"}], "IPv6":[{"address":"fe80::250:56ff:fec0:8","dhcp":"unknown","metric":" ","netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"inode":0,"local_ip":" 127.0.0.1 ","scan_time":"  2020/12/28 21:49:50  ", "local_port":631,"pid":0,"process_name":"System  Idle Process","protocol":"tcp   ","remote_ip":"   0.0.0.0","remote_port":0,"rx_queue":0,"state":"listening","tx_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"architecture":" amd64","scan_time":"2020/12/28 21:49:50 ", "group":"  x11  ","name":" xserver-xorg","priority":"optional ","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14","format":"deb","location":" "})"_json));

    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix":" KB12345678 "}])"_json));

    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"egroup":" root ","euser":" root","fgroup":"root ","name":" kworker/u256:2-  ","scan_time":"2020/12/28 21:49:50", "nice":0,"nlwp":1,"pgrp":0,"pid":"  431625  ","ppid":2,"priority":20,"processor":1,"resident":0,"rgroup":"root","ruser":"root","session":0,"sgroup":"root","share":0,"size":0,"start_time":9302261,"state":"I","stime":3,"suser":"root","tgid":431625,"tty":0,"utime":0,"vm_size":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));

    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            delta["data"].erase("id");
            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta.at("type").get_ref<const std::string&>().compare("dbsync_osinfo") == 0)
            {
                delta["data"].erase("checksum");
            }

            delta["data"].erase("scan_time");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto expectedResult2
    {
        R"({"data":{"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft   Windows  7","os_release":"sp1","os_version":"6.1.7601"},"operation":"INSERTED","type":"dbsync_osinfo"})"
    };
    const auto expectedResult7
    {
        R"({"data":{"checksum":"b5cee87f8acba50334d2409d474fbac08d8015e0","inode":0,"item_id":"cbf2ac25a6775175f912ebf2abc72f6f51ab48ba","local_ip":"127.0.0.1","local_port":631,"pid":0,"process_name":"System  Idle Process","protocol":"tcp","remote_ip":"0.0.0.0","remote_port":0,"rx_queue":0,"state":"listening","tx_queue":0},"operation":"INSERTED","type":"dbsync_ports"})"
    };
    const auto expectedResult10
    {
        R"({"component":"syscollector_osinfo","data":{"begin":"Microsoft   Windows  7","end":"Microsoft   Windows  7"},"type":"integrity_check_global"})"
    };


    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hwinfo)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_iface)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_address_1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult7)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_processes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_packages)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_network_protocol_2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    EXPECT_CALL(wrapper, callbackMock(expectedResult10)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_iface)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_protocol)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_network_address)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_ports)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_processes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hwinfo)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_packages)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_hotfixes)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_groups)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_users)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_services)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expected_syscollector_browser_extensions)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData, &callbackDataDelta]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackData,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          5, true, true, true, true, true, true, true, true, true, true, true, true, true, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(1));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}
