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
    // std::cout << payload << std::endl;
}

void logFunction(const modules_log_level_t /*level*/, const std::string& /*log*/)
{
    // static const std::map<modules_log_level_t, std::string> s_logStringMap
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
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"serial_number":"Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz", "memory_free":2257872,"memory_total":4972208,"memory_used":54})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":"x86_64", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_distribution_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_mtu":1500, "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"ethernet", "interface_state":"up", "network_dhcp":"disabled","network_metric":"75","network_netmask":"255.0.0.0","network_protocol":"IPv4","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":"unknown","network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":"unknown","network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"architecture":"amd64", "category":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14","type":"deb","path":" "})"_json));

    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix_name":"KB12345678"}])"_json));

    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"kworker/u256:2-","pid":"431625","parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

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
            delta["data"].erase("checksum");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto expectedResult1
    {
        R"({"data":{"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","cpu_speed":2904,"memory_free":2257872,"memory_total":4972208,"memory_used":54,"serial_number":"Intel Corporation"},"operation":"INSERTED","type":"dbsync_hwinfo"})"
    };
    const auto expectedResult2
    {
        R"({"data":{"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_distribution_release":"sp1","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_version":"6.1.7601"},"operation":"INSERTED","type":"dbsync_osinfo"})"
    };
    const auto expectedResult3
    {
        R"({"data":{"host_mac":"d4:5d:64:51:07:5d","host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0,"host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"interface_alias":" ","interface_mtu":1500,"interface_name":"enp4s0","interface_state":"up","interface_type":"ethernet"},"operation":"INSERTED","type":"dbsync_network_iface"})"
    };
    const auto expectedResult4
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv4"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult5
    {
        R"({"data":{"interface_name":"enp4s0","network_broadcast":"192.168.153.255","network_ip":"192.168.153.1","network_netmask":"255.255.255.0","network_protocol":0},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult6
    {
        R"({"data":{"interface_name":"enp4s0","network_ip":"fe80::250:56ff:fec0:8","network_netmask":"ffff:ffff:ffff:ffff::","network_protocol":1},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult7
    {
        R"({"data":{"destination_ip":"0.0.0.0","destination_port":0,"file_inode":0,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":"listening","network_transport":"tcp","process_name":"System Idle Process","process_pid":0,"source_ip":"127.0.0.1","source_port":631},"operation":"INSERTED","type":"dbsync_ports"})"
    };
    const auto expectedResult8
    {
        R"({"data":{"name":"kworker/u256:2-","parent_pid":2,"pid":"431625","start":9302261,"state":"I","stime":3,"utime":0},"operation":"INSERTED","type":"dbsync_processes"})"
    };
    const auto expectedResult9
    {
        R"({"data":{"architecture":"amd64","category":"x11","name":"xserver-xorg","path":" ","priority":"optional","size":4111222333,"source":"xorg","type":"deb","version":"1:7.7+19ubuntu14"},"operation":"INSERTED","type":"dbsync_packages"})"
    };
    const auto expectedResult10
    {
        R"({"component":"syscollector_osinfo","data":{"begin":"Microsoft Windows 7","end":"Microsoft Windows 7"},"type":"integrity_check_global"})"
    };
    const auto expectedResult11
    {
        R"({"component":"syscollector_network_iface","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult12
    {
        R"({"component":"syscollector_network_protocol","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult13
    {
        R"({"component":"syscollector_network_address","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult14
    {
        R"({"component":"syscollector_ports","data":{"begin":"0","end":"0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult15
    {
        R"({"component":"syscollector_processes","data":{"begin":"431625","end":"431625"},"type":"integrity_check_global"})"
    };
    const auto expectedResult16
    {
        R"({"component":"syscollector_hwinfo","data":{"begin":"Intel Corporation","end":"Intel Corporation"},"type":"integrity_check_global"})"
    };
    const auto expectedResult17
    {
        R"({"component":"syscollector_packages","data":{"begin":"xserver-xorg","end":"xserver-xorg"},"type":"integrity_check_global"})"
    };
    const auto expectedResult18
    {
        R"({"data":{"hotfix_name":"KB12345678"},"operation":"INSERTED","type":"dbsync_hotfixes"})"
    };
    const auto expectedResult19
    {
        R"({"component":"syscollector_hotfixes","data":{"begin":"KB12345678","end":"KB12345678"},"type":"integrity_check_global"})"
    };
    const auto expectedResult20
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv6"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult21
    {
        R"({"data":{"group_description":null,"group_id":1,"group_id_signed":1,"group_is_hidden":0,"group_name":"daemon","group_users":"daemon:pollinate:vboxadd","group_uuid":null},"operation":"INSERTED","type":"dbsync_groups"})"
    };
    const auto expectedResult22
    {
        R"({"component":"syscollector_groups","data":{"begin":"daemon","end":"daemon"},"type":"integrity_check_global"})"
    };
    const auto expectedResult23
    {
        R"({"component":"syscollector_users","data":{"begin":"root","end":"root"},"type":"integrity_check_global"})"
    };
    const auto expectedResult24
    {
        R"({"data":{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null},"operation":"INSERTED","type":"dbsync_users"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult3)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult4)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult5)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult6)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult7)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult8)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult9)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult10)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult11)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult12)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult13)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult14)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult15)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult16)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult17)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult18)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult19)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult20)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult21)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult22)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult23)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult24)).Times(1);

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
                                          5, true, true, true, true, true, true, true, true, true, true, true, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(1));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, intervalSeconds)
{
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"serial_number":"Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","memory_free":2257872,"memory_total":4972208,"memory_used":54})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":"x86_64", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_distribution_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_mtu":1500, "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"ethernet", "interface_state":"up", "network_dhcp":"disabled","network_metric":"75","network_netmask":"255.0.0.0","network_protocol":"IPv4","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":"unknown","network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":"unknown","network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix_name":"KB12345678"},{"hotfix_name":"KB87654321"}])"_json));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(::testing::AtLeast(2))
    .WillRepeatedly(testing::InvokeArgument<0>(nlohmann::json::parse(
                                                   R"({"name":"kworker/u256:2-","pid":431625,"parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})")));

    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(2))
    .WillRepeatedly(::testing::InvokeArgument<0>
                    (R"({"name":"TEXT", "version":"TEXT", "vendor":"TEXT", "installed":"TEXT", "path":"TEXT", "architecture":"TEXT", "category":"TEXT", "description":"TEXT", "size":"TEXT", "priority":"TEXT", "multiarch":"TEXT", "source":"TEXT", "os_patch":"TEXT"})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

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
                                          1, true, true, true, true, true, true, true, true, true, true, true, true);

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
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":"x86_64", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_distribution_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_mtu":1500, "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"ethernet", "interface_state":"up", "network_dhcp":"disabled","network_metric":"75","network_netmask":"255.0.0.0","network_protocol":"IPv4","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":"unknown","network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":"unknown","network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"architecture":"amd64", "category":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14","type":"deb","path":" "})"_json));

    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix_name":"KB12345678"}])"_json));

    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"kworker/u256:2-","pid":"431625","parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

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
            delta["data"].erase("checksum");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto expectedResult2
    {
        R"({"data":{"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_distribution_release":"sp1","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_version":"6.1.7601"},"operation":"INSERTED","type":"dbsync_osinfo"})"
    };
    const auto expectedResult3
    {
        R"({"data":{"host_mac":"d4:5d:64:51:07:5d","host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0,"host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"interface_alias":" ","interface_mtu":1500,"interface_name":"enp4s0","interface_state":"up","interface_type":"ethernet"},"operation":"INSERTED","type":"dbsync_network_iface"})"
    };
    const auto expectedResult4
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv4"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult5
    {
        R"({"data":{"interface_name":"enp4s0","network_broadcast":"192.168.153.255","network_ip":"192.168.153.1","network_netmask":"255.255.255.0","network_protocol":0},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult6
    {
        R"({"data":{"interface_name":"enp4s0","network_ip":"fe80::250:56ff:fec0:8","network_netmask":"ffff:ffff:ffff:ffff::","network_protocol":1},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult7
    {
        R"({"data":{"destination_ip":"0.0.0.0","destination_port":0,"file_inode":0,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":"listening","network_transport":"tcp","process_name":"System Idle Process","process_pid":0,"source_ip":"127.0.0.1","source_port":631},"operation":"INSERTED","type":"dbsync_ports"})"
    };
    const auto expectedResult8
    {
        R"({"data":{"name":"kworker/u256:2-","parent_pid":2,"pid":"431625","start":9302261,"state":"I","stime":3,"utime":0},"operation":"INSERTED","type":"dbsync_processes"})"
    };
    const auto expectedResult9
    {
        R"({"data":{"architecture":"amd64","category":"x11","name":"xserver-xorg","path":" ","priority":"optional","size":4111222333,"source":"xorg","type":"deb","version":"1:7.7+19ubuntu14"},"operation":"INSERTED","type":"dbsync_packages"})"
    };
    const auto expectedResult10
    {
        R"({"component":"syscollector_osinfo","data":{"begin":"Microsoft Windows 7","end":"Microsoft Windows 7"},"type":"integrity_check_global"})"
    };
    const auto expectedResult11
    {
        R"({"component":"syscollector_network_iface","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult12
    {
        R"({"component":"syscollector_network_protocol","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult13
    {
        R"({"component":"syscollector_network_address","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult14
    {
        R"({"component":"syscollector_ports","data":{"begin":"0","end":"0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult15
    {
        R"({"component":"syscollector_processes","data":{"begin":"431625","end":"431625"},"type":"integrity_check_global"})"
    };
    const auto expectedResult17
    {
        R"({"component":"syscollector_packages","data":{"begin":"xserver-xorg","end":"xserver-xorg"},"type":"integrity_check_global"})"
    };
    const auto expectedResult18
    {
        R"({"data":{"hotfix_name":"KB12345678"},"operation":"INSERTED","type":"dbsync_hotfixes"})"
    };
    const auto expectedResult19
    {
        R"({"component":"syscollector_hotfixes","data":{"begin":"KB12345678","end":"KB12345678"},"type":"integrity_check_global"})"
    };
    const auto expectedResult20
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv6"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult21
    {
        R"({"component":"syscollector_hwinfo","data":{},"type":"integrity_clear"})"
    };
    const auto expectedResult22
    {
        R"({"data":{"group_description":null,"group_id":1,"group_id_signed":1,"group_is_hidden":0,"group_name":"daemon","group_users":"daemon:pollinate:vboxadd","group_uuid":null},"operation":"INSERTED","type":"dbsync_groups"})"
    };
    const auto expectedResult23
    {
        R"({"component":"syscollector_groups","data":{"begin":"daemon","end":"daemon"},"type":"integrity_check_global"})"
    };
    const auto expectedResult24
    {
        R"({"component":"syscollector_users","data":{"begin":"root","end":"root"},"type":"integrity_check_global"})"
    };
    const auto expectedResult25
    {
        R"({"data":{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null},"operation":"INSERTED","type":"dbsync_users"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult3)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult4)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult5)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult6)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult7)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult8)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult9)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult10)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult11)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult12)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult13)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult14)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult15)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult17)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult18)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult19)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult20)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult21)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult22)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult23)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult24)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult25)).Times(1);

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
                                          3600, true, false, true, true, true, true, true, true, true, true, true, true);
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
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"serial_number":"Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz", "memory_free":2257872,"memory_total":4972208,"memory_used":54})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_mtu":1500, "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"ethernet", "interface_state":"up", "network_dhcp":"disabled","network_metric":"75","network_netmask":"255.0.0.0","network_protocol":"IPv4","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":"unknown","network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":"unknown","network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"architecture":"amd64", "category":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14","type":"deb","path":" "})"_json));

    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix_name":"KB12345678"}])"_json));

    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"kworker/u256:2-","pid":"431625","parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

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
            delta["data"].erase("checksum");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto expectedResult1
    {
        R"({"data":{"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","cpu_speed":2904,"memory_free":2257872,"memory_total":4972208,"memory_used":54,"serial_number":"Intel Corporation"},"operation":"INSERTED","type":"dbsync_hwinfo"})"
    };
    const auto expectedResult3
    {
        R"({"data":{"host_mac":"d4:5d:64:51:07:5d","host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0,"host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"interface_alias":" ","interface_mtu":1500,"interface_name":"enp4s0","interface_state":"up","interface_type":"ethernet"},"operation":"INSERTED","type":"dbsync_network_iface"})"
    };
    const auto expectedResult4
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv4"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult5
    {
        R"({"data":{"interface_name":"enp4s0","network_broadcast":"192.168.153.255","network_ip":"192.168.153.1","network_netmask":"255.255.255.0","network_protocol":0},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult6
    {
        R"({"data":{"interface_name":"enp4s0","network_ip":"fe80::250:56ff:fec0:8","network_netmask":"ffff:ffff:ffff:ffff::","network_protocol":1},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult7
    {
        R"({"data":{"destination_ip":"0.0.0.0","destination_port":0,"file_inode":0,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":"listening","network_transport":"tcp","process_name":"System Idle Process","process_pid":0,"source_ip":"127.0.0.1","source_port":631},"operation":"INSERTED","type":"dbsync_ports"})"
    };
    const auto expectedResult8
    {
        R"({"data":{"name":"kworker/u256:2-","parent_pid":2,"pid":"431625","start":9302261,"state":"I","stime":3,"utime":0},"operation":"INSERTED","type":"dbsync_processes"})"
    };
    const auto expectedResult9
    {
        R"({"data":{"architecture":"amd64","category":"x11","name":"xserver-xorg","path":" ","priority":"optional","size":4111222333,"source":"xorg","type":"deb","version":"1:7.7+19ubuntu14"},"operation":"INSERTED","type":"dbsync_packages"})"
    };
    const auto expectedResult11
    {
        R"({"component":"syscollector_network_iface","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult12
    {
        R"({"component":"syscollector_network_protocol","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult13
    {
        R"({"component":"syscollector_network_address","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult14
    {
        R"({"component":"syscollector_ports","data":{"begin":"0","end":"0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult15
    {
        R"({"component":"syscollector_processes","data":{"begin":"431625","end":"431625"},"type":"integrity_check_global"})"
    };
    const auto expectedResult16
    {
        R"({"component":"syscollector_hwinfo","data":{"begin":"Intel Corporation","end":"Intel Corporation"},"type":"integrity_check_global"})"
    };
    const auto expectedResult17
    {
        R"({"component":"syscollector_packages","data":{"begin":"xserver-xorg","end":"xserver-xorg"},"type":"integrity_check_global"})"
    };
    const auto expectedResult18
    {
        R"({"data":{"hotfix_name":"KB12345678"},"operation":"INSERTED","type":"dbsync_hotfixes"})"
    };
    const auto expectedResult19
    {
        R"({"component":"syscollector_hotfixes","data":{"begin":"KB12345678","end":"KB12345678"},"type":"integrity_check_global"})"
    };
    const auto expectedResult20
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv6"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult21
    {
        R"({"component":"syscollector_osinfo","data":{},"type":"integrity_clear"})"
    };
    const auto expectedResult22
    {
        R"({"data":{"group_description":null,"group_id":1,"group_id_signed":1,"group_is_hidden":0,"group_name":"daemon","group_users":"daemon:pollinate:vboxadd","group_uuid":null},"operation":"INSERTED","type":"dbsync_groups"})"
    };
    const auto expectedResult23
    {
        R"({"component":"syscollector_groups","data":{"begin":"daemon","end":"daemon"},"type":"integrity_check_global"})"
    };
    const auto expectedResult24
    {
        R"({"component":"syscollector_users","data":{"begin":"root","end":"root"},"type":"integrity_check_global"})"
    };
    const auto expectedResult25
    {
        R"({"data":{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null},"operation":"INSERTED","type":"dbsync_users"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult3)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult4)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult5)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult6)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult7)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult8)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult9)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult11)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult12)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult13)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult14)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult15)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult16)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult17)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult18)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult19)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult20)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult21)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult22)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult23)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult24)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult25)).Times(1);

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
                                          3600, true, true, false, true, true, true, true, true, true, true, true, true);
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
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"serial_number":"Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz", "memory_free":2257872,"memory_total":4972208,"memory_used":54})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":"x86_64", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_distribution_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).Times(0);
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"architecture":"amd64", "category":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14","type":"deb","path":" "})"_json));

    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix_name":"KB12345678"}])"_json));

    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"kworker/u256:2-","pid":"431625","parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

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
            delta["data"].erase("checksum");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto expectedResult1
    {
        R"({"data":{"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","cpu_speed":2904,"memory_free":2257872,"memory_total":4972208,"memory_used":54,"serial_number":"Intel Corporation"},"operation":"INSERTED","type":"dbsync_hwinfo"})"
    };
    const auto expectedResult2
    {
        R"({"data":{"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_distribution_release":"sp1","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_version":"6.1.7601"},"operation":"INSERTED","type":"dbsync_osinfo"})"
    };
    const auto expectedResult7
    {
        R"({"data":{"destination_ip":"0.0.0.0","destination_port":0,"file_inode":0,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":"listening","network_transport":"tcp","process_name":"System Idle Process","process_pid":0,"source_ip":"127.0.0.1","source_port":631},"operation":"INSERTED","type":"dbsync_ports"})"
    };
    const auto expectedResult8
    {
        R"({"data":{"name":"kworker/u256:2-","parent_pid":2,"pid":"431625","start":9302261,"state":"I","stime":3,"utime":0},"operation":"INSERTED","type":"dbsync_processes"})"
    };
    const auto expectedResult9
    {
        R"({"data":{"architecture":"amd64","category":"x11","name":"xserver-xorg","path":" ","priority":"optional","size":4111222333,"source":"xorg","type":"deb","version":"1:7.7+19ubuntu14"},"operation":"INSERTED","type":"dbsync_packages"})"
    };
    const auto expectedResult10
    {
        R"({"component":"syscollector_osinfo","data":{"begin":"Microsoft Windows 7","end":"Microsoft Windows 7"},"type":"integrity_check_global"})"
    };
    const auto expectedResult14
    {
        R"({"component":"syscollector_ports","data":{"begin":"0","end":"0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult15
    {
        R"({"component":"syscollector_processes","data":{"begin":"431625","end":"431625"},"type":"integrity_check_global"})"
    };
    const auto expectedResult16
    {
        R"({"component":"syscollector_hwinfo","data":{"begin":"Intel Corporation","end":"Intel Corporation"},"type":"integrity_check_global"})"
    };
    const auto expectedResult17
    {
        R"({"component":"syscollector_packages","data":{"begin":"xserver-xorg","end":"xserver-xorg"},"type":"integrity_check_global"})"
    };
    const auto expectedResult18
    {
        R"({"data":{"hotfix_name":"KB12345678"},"operation":"INSERTED","type":"dbsync_hotfixes"})"
    };
    const auto expectedResult19
    {
        R"({"component":"syscollector_hotfixes","data":{"begin":"KB12345678","end":"KB12345678"},"type":"integrity_check_global"})"
    };
    const auto expectedResult20
    {
        R"({"component":"syscollector_network_address","data":{},"type":"integrity_clear"})"
    };
    const auto expectedResult21
    {
        R"({"component":"syscollector_network_protocol","data":{},"type":"integrity_clear"})"
    };
    const auto expectedResult22
    {
        R"({"component":"syscollector_network_iface","data":{},"type":"integrity_clear"})"
    };
    const auto expectedResult23
    {
        R"({"data":{"group_description":null,"group_id":1,"group_id_signed":1,"group_is_hidden":0,"group_name":"daemon","group_users":"daemon:pollinate:vboxadd","group_uuid":null},"operation":"INSERTED","type":"dbsync_groups"})"
    };
    const auto expectedResult24
    {
        R"({"component":"syscollector_groups","data":{"begin":"daemon","end":"daemon"},"type":"integrity_check_global"})"
    };
    const auto expectedResult25
    {
        R"({"component":"syscollector_users","data":{"begin":"root","end":"root"},"type":"integrity_check_global"})"
    };
    const auto expectedResult26
    {
        R"({"data":{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null},"operation":"INSERTED","type":"dbsync_users"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult7)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult8)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult9)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult10)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult14)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult15)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult16)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult17)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult18)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult19)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult20)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult21)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult22)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult23)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult24)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult25)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult26)).Times(1);

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
                                          3600, true, true, true, false, true, true, true, true, true, true, true, true);
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
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"serial_number":"Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz", "memory_free":2257872,"memory_total":4972208,"memory_used":54})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":"x86_64", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_distribution_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_mtu":1500, "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"ethernet", "interface_state":"up", "network_dhcp":"disabled","network_metric":"75","network_netmask":"255.0.0.0","network_protocol":"IPv4","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":"unknown","network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":"unknown","network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, packages(_)).Times(0);

    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix_name":"KB12345678"}])"_json));

    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"kworker/u256:2-","pid":"431625","parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

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
            delta["data"].erase("checksum");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto expectedResult1
    {
        R"({"data":{"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","cpu_speed":2904,"memory_free":2257872,"memory_total":4972208,"memory_used":54,"serial_number":"Intel Corporation"},"operation":"INSERTED","type":"dbsync_hwinfo"})"
    };
    const auto expectedResult2
    {
        R"({"data":{"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_distribution_release":"sp1","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_version":"6.1.7601"},"operation":"INSERTED","type":"dbsync_osinfo"})"
    };
    const auto expectedResult3
    {
        R"({"data":{"host_mac":"d4:5d:64:51:07:5d","host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0,"host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"interface_alias":" ","interface_mtu":1500,"interface_name":"enp4s0","interface_state":"up","interface_type":"ethernet"},"operation":"INSERTED","type":"dbsync_network_iface"})"
    };
    const auto expectedResult4
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv4"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult5
    {
        R"({"data":{"interface_name":"enp4s0","network_broadcast":"192.168.153.255","network_ip":"192.168.153.1","network_netmask":"255.255.255.0","network_protocol":0},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult6
    {
        R"({"data":{"interface_name":"enp4s0","network_ip":"fe80::250:56ff:fec0:8","network_netmask":"ffff:ffff:ffff:ffff::","network_protocol":1},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult7
    {
        R"({"data":{"destination_ip":"0.0.0.0","destination_port":0,"file_inode":0,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":"listening","network_transport":"tcp","process_name":"System Idle Process","process_pid":0,"source_ip":"127.0.0.1","source_port":631},"operation":"INSERTED","type":"dbsync_ports"})"
    };
    const auto expectedResult8
    {
        R"({"data":{"name":"kworker/u256:2-","parent_pid":2,"pid":"431625","start":9302261,"state":"I","stime":3,"utime":0},"operation":"INSERTED","type":"dbsync_processes"})"
    };
    const auto expectedResult10
    {
        R"({"component":"syscollector_osinfo","data":{"begin":"Microsoft Windows 7","end":"Microsoft Windows 7"},"type":"integrity_check_global"})"
    };
    const auto expectedResult11
    {
        R"({"component":"syscollector_network_iface","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult12
    {
        R"({"component":"syscollector_network_protocol","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult13
    {
        R"({"component":"syscollector_network_address","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult14
    {
        R"({"component":"syscollector_ports","data":{"begin":"0","end":"0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult15
    {
        R"({"component":"syscollector_processes","data":{"begin":"431625","end":"431625"},"type":"integrity_check_global"})"
    };
    const auto expectedResult16
    {
        R"({"component":"syscollector_hwinfo","data":{"begin":"Intel Corporation","end":"Intel Corporation"},"type":"integrity_check_global"})"
    };
    const auto expectedResult18
    {
        R"({"data":{"hotfix_name":"KB12345678"},"operation":"INSERTED","type":"dbsync_hotfixes"})"
    };
    const auto expectedResult19
    {
        R"({"component":"syscollector_hotfixes","data":{"begin":"KB12345678","end":"KB12345678"},"type":"integrity_check_global"})"
    };
    const auto expectedResult20
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv6"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult21
    {
        R"({"component":"syscollector_packages","data":{},"type":"integrity_clear"})"
    };
    const auto expectedResult22
    {
        R"({"data":{"group_description":null,"group_id":1,"group_id_signed":1,"group_is_hidden":0,"group_name":"daemon","group_users":"daemon:pollinate:vboxadd","group_uuid":null},"operation":"INSERTED","type":"dbsync_groups"})"
    };
    const auto expectedResult23
    {
        R"({"component":"syscollector_groups","data":{"begin":"daemon","end":"daemon"},"type":"integrity_check_global"})"
    };
    const auto expectedResult24
    {
        R"({"component":"syscollector_users","data":{"begin":"root","end":"root"},"type":"integrity_check_global"})"
    };
    const auto expectedResult25
    {
        R"({"data":{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null},"operation":"INSERTED","type":"dbsync_users"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult3)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult4)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult5)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult6)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult7)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult8)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult10)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult11)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult12)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult13)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult14)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult15)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult16)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult18)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult19)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult20)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult21)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult22)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult23)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult24)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult25)).Times(1);

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
                                          3600, true, true, true, true, false, true, true, true, true, true, true, true);
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
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"serial_number":"Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz", "memory_free":2257872,"memory_total":4972208,"memory_used":54})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":"x86_64", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_distribution_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_mtu":1500, "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"ethernet", "interface_state":"up", "network_dhcp":"disabled","network_metric":"75","network_netmask":"255.0.0.0","network_protocol":"IPv4","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":"unknown","network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":"unknown","network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, ports()).Times(0);
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"architecture":"amd64", "category":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14","type":"deb","path":" "})"_json));

    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix_name":"KB12345678"}])"_json));

    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"kworker/u256:2-","pid":"431625","parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

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
            delta["data"].erase("checksum");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto expectedResult1
    {
        R"({"data":{"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","cpu_speed":2904,"memory_free":2257872,"memory_total":4972208,"memory_used":54,"serial_number":"Intel Corporation"},"operation":"INSERTED","type":"dbsync_hwinfo"})"
    };
    const auto expectedResult2
    {
        R"({"data":{"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_distribution_release":"sp1","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_version":"6.1.7601"},"operation":"INSERTED","type":"dbsync_osinfo"})"
    };
    const auto expectedResult3
    {
        R"({"data":{"host_mac":"d4:5d:64:51:07:5d","host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0,"host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"interface_alias":" ","interface_mtu":1500,"interface_name":"enp4s0","interface_state":"up","interface_type":"ethernet"},"operation":"INSERTED","type":"dbsync_network_iface"})"
    };
    const auto expectedResult4
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv4"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult5
    {
        R"({"data":{"interface_name":"enp4s0","network_broadcast":"192.168.153.255","network_ip":"192.168.153.1","network_netmask":"255.255.255.0","network_protocol":0},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult6
    {
        R"({"data":{"interface_name":"enp4s0","network_ip":"fe80::250:56ff:fec0:8","network_netmask":"ffff:ffff:ffff:ffff::","network_protocol":1},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult8
    {
        R"({"data":{"name":"kworker/u256:2-","parent_pid":2,"pid":"431625","start":9302261,"state":"I","stime":3,"utime":0},"operation":"INSERTED","type":"dbsync_processes"})"
    };
    const auto expectedResult9
    {
        R"({"data":{"architecture":"amd64","category":"x11","name":"xserver-xorg","path":" ","priority":"optional","size":4111222333,"source":"xorg","type":"deb","version":"1:7.7+19ubuntu14"},"operation":"INSERTED","type":"dbsync_packages"})"
    };
    const auto expectedResult10
    {
        R"({"component":"syscollector_osinfo","data":{"begin":"Microsoft Windows 7","end":"Microsoft Windows 7"},"type":"integrity_check_global"})"
    };
    const auto expectedResult11
    {
        R"({"component":"syscollector_network_iface","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult12
    {
        R"({"component":"syscollector_network_protocol","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult13
    {
        R"({"component":"syscollector_network_address","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult15
    {
        R"({"component":"syscollector_processes","data":{"begin":"431625","end":"431625"},"type":"integrity_check_global"})"
    };
    const auto expectedResult16
    {
        R"({"component":"syscollector_hwinfo","data":{"begin":"Intel Corporation","end":"Intel Corporation"},"type":"integrity_check_global"})"
    };
    const auto expectedResult17
    {
        R"({"component":"syscollector_packages","data":{"begin":"xserver-xorg","end":"xserver-xorg"},"type":"integrity_check_global"})"
    };
    const auto expectedResult18
    {
        R"({"data":{"hotfix_name":"KB12345678"},"operation":"INSERTED","type":"dbsync_hotfixes"})"
    };
    const auto expectedResult19
    {
        R"({"component":"syscollector_hotfixes","data":{"begin":"KB12345678","end":"KB12345678"},"type":"integrity_check_global"})"
    };
    const auto expectedResult20
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv6"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult21
    {
        R"({"component":"syscollector_ports","data":{},"type":"integrity_clear"})"
    };
    const auto expectedResult22
    {
        R"({"data":{"group_description":null,"group_id":1,"group_id_signed":1,"group_is_hidden":0,"group_name":"daemon","group_users":"daemon:pollinate:vboxadd","group_uuid":null},"operation":"INSERTED","type":"dbsync_groups"})"
    };
    const auto expectedResult23
    {
        R"({"component":"syscollector_groups","data":{"begin":"daemon","end":"daemon"},"type":"integrity_check_global"})"
    };
    const auto expectedResult24
    {
        R"({"component":"syscollector_users","data":{"begin":"root","end":"root"},"type":"integrity_check_global"})"
    };
    const auto expectedResult25
    {
        R"({"data":{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null},"operation":"INSERTED","type":"dbsync_users"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult3)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult4)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult5)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult6)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult8)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult9)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult10)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult11)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult12)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult13)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult15)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult16)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult17)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult18)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult19)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult20)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult21)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult22)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult23)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult24)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult25)).Times(1);

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
                                          5, true, true, true, true, true, false, true, true, true, true, true, true);
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
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"serial_number":"Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz", "memory_free":2257872,"memory_total":4972208,"memory_used":54})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":"x86_64", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_distribution_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_mtu":1500, "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"ethernet", "interface_state":"up", "network_dhcp":"disabled","network_metric":"75","network_netmask":"255.0.0.0","network_protocol":"IPv4","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":"unknown","network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":"unknown","network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"udp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"","host_network_egress_queue":0},{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"architecture":"amd64", "category":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14","type":"deb","path":" "})"_json));

    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix_name":"KB12345678"}])"_json));

    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"kworker/u256:2-","pid":"431625","parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

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
            delta["data"].erase("checksum");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto expectedResult1
    {
        R"({"data":{"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","cpu_speed":2904,"memory_free":2257872,"memory_total":4972208,"memory_used":54,"serial_number":"Intel Corporation"},"operation":"INSERTED","type":"dbsync_hwinfo"})"
    };
    const auto expectedResult2
    {
        R"({"data":{"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_distribution_release":"sp1","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_version":"6.1.7601"},"operation":"INSERTED","type":"dbsync_osinfo"})"
    };
    const auto expectedResult3
    {
        R"({"data":{"host_mac":"d4:5d:64:51:07:5d","host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0,"host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"interface_alias":" ","interface_mtu":1500,"interface_name":"enp4s0","interface_state":"up","interface_type":"ethernet"},"operation":"INSERTED","type":"dbsync_network_iface"})"
    };
    const auto expectedResult4
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv4"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult5
    {
        R"({"data":{"interface_name":"enp4s0","network_broadcast":"192.168.153.255","network_ip":"192.168.153.1","network_netmask":"255.255.255.0","network_protocol":0},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult6
    {
        R"({"data":{"interface_name":"enp4s0","network_ip":"fe80::250:56ff:fec0:8","network_netmask":"ffff:ffff:ffff:ffff::","network_protocol":1},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult7
    {
        R"({"data":{"destination_ip":"0.0.0.0","destination_port":0,"file_inode":0,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":"listening","network_transport":"tcp","process_name":"System Idle Process","process_pid":0,"source_ip":"127.0.0.1","source_port":631},"operation":"INSERTED","type":"dbsync_ports"})"
    };
    const auto expectedResult8
    {
        R"({"data":{"name":"kworker/u256:2-","parent_pid":2,"pid":"431625","start":9302261,"state":"I","stime":3,"utime":0},"operation":"INSERTED","type":"dbsync_processes"})"
    };
    const auto expectedResult9
    {
        R"({"data":{"architecture":"amd64","category":"x11","name":"xserver-xorg","path":" ","priority":"optional","size":4111222333,"source":"xorg","type":"deb","version":"1:7.7+19ubuntu14"},"operation":"INSERTED","type":"dbsync_packages"})"
    };
    const auto expectedResult10
    {
        R"({"component":"syscollector_osinfo","data":{"begin":"Microsoft Windows 7","end":"Microsoft Windows 7"},"type":"integrity_check_global"})"
    };
    const auto expectedResult11
    {
        R"({"component":"syscollector_network_iface","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult12
    {
        R"({"component":"syscollector_network_protocol","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult13
    {
        R"({"component":"syscollector_network_address","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult14
    {
        R"({"component":"syscollector_ports","data":{"begin":"0","end":"0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult15
    {
        R"({"component":"syscollector_processes","data":{"begin":"431625","end":"431625"},"type":"integrity_check_global"})"
    };
    const auto expectedResult16
    {
        R"({"component":"syscollector_hwinfo","data":{"begin":"Intel Corporation","end":"Intel Corporation"},"type":"integrity_check_global"})"
    };
    const auto expectedResult17
    {
        R"({"component":"syscollector_packages","data":{"begin":"xserver-xorg","end":"xserver-xorg"},"type":"integrity_check_global"})"
    };
    const auto expectedResult18
    {
        R"({"data":{"hotfix_name":"KB12345678"},"operation":"INSERTED","type":"dbsync_hotfixes"})"
    };
    const auto expectedResult19
    {
        R"({"component":"syscollector_hotfixes","data":{"begin":"KB12345678","end":"KB12345678"},"type":"integrity_check_global"})"
    };
    const auto expectedResult20
    {
        R"({"data":{"destination_ip":"0.0.0.0","destination_port":0,"file_inode":0,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":null,"network_transport":"udp","process_name":"System Idle Process","process_pid":0,"source_ip":"127.0.0.1","source_port":631},"operation":"INSERTED","type":"dbsync_ports"})"
    };
    const auto expectedResult21
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv6"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult22
    {
        R"({"data":{"group_description":null,"group_id":1,"group_id_signed":1,"group_is_hidden":0,"group_name":"daemon","group_users":"daemon:pollinate:vboxadd","group_uuid":null},"operation":"INSERTED","type":"dbsync_groups"})"
    };
    const auto expectedResult23
    {
        R"({"component":"syscollector_groups","data":{"begin":"daemon","end":"daemon"},"type":"integrity_check_global"})"
    };
    const auto expectedResult24
    {
        R"({"component":"syscollector_users","data":{"begin":"root","end":"root"},"type":"integrity_check_global"})"
    };
    const auto expectedResult25
    {
        R"({"data":{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null},"operation":"INSERTED","type":"dbsync_users"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult3)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult4)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult5)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult6)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult7)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult8)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult9)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult10)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult11)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult12)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult13)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult14)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult15)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult16)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult17)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult18)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult19)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult20)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult21)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult22)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult23)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult24)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult25)).Times(1);

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
                                          3600, true, true, true, true, true, true, false, true, true, true, true, true);
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
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"serial_number":"Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz", "memory_free":2257872,"memory_total":4972208,"memory_used":54})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":"x86_64", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_distribution_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_mtu":1500, "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"ethernet", "interface_state":"up", "network_dhcp":"disabled","network_metric":"75","network_netmask":"255.0.0.0","network_protocol":"IPv4","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":"unknown","network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":"unknown","network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"architecture":"amd64", "category":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14","type":"deb","path":" "})"_json));

    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix_name":"KB12345678"}])"_json));

    EXPECT_CALL(*spInfoWrapper, processes(_)).Times(0);

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

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
            delta["data"].erase("checksum");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto expectedResult1
    {
        R"({"data":{"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","cpu_speed":2904,"memory_free":2257872,"memory_total":4972208,"memory_used":54,"serial_number":"Intel Corporation"},"operation":"INSERTED","type":"dbsync_hwinfo"})"
    };
    const auto expectedResult2
    {
        R"({"data":{"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_distribution_release":"sp1","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_version":"6.1.7601"},"operation":"INSERTED","type":"dbsync_osinfo"})"
    };
    const auto expectedResult3
    {
        R"({"data":{"host_mac":"d4:5d:64:51:07:5d","host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0,"host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"interface_alias":" ","interface_mtu":1500,"interface_name":"enp4s0","interface_state":"up","interface_type":"ethernet"},"operation":"INSERTED","type":"dbsync_network_iface"})"
    };
    const auto expectedResult4
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv4"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult5
    {
        R"({"data":{"interface_name":"enp4s0","network_broadcast":"192.168.153.255","network_ip":"192.168.153.1","network_netmask":"255.255.255.0","network_protocol":0},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult6
    {
        R"({"data":{"interface_name":"enp4s0","network_ip":"fe80::250:56ff:fec0:8","network_netmask":"ffff:ffff:ffff:ffff::","network_protocol":1},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult7
    {
        R"({"data":{"destination_ip":"0.0.0.0","destination_port":0,"file_inode":0,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":"listening","network_transport":"tcp","process_name":"System Idle Process","process_pid":0,"source_ip":"127.0.0.1","source_port":631},"operation":"INSERTED","type":"dbsync_ports"})"
    };
    const auto expectedResult9
    {
        R"({"data":{"architecture":"amd64","category":"x11","name":"xserver-xorg","path":" ","priority":"optional","size":4111222333,"source":"xorg","type":"deb","version":"1:7.7+19ubuntu14"},"operation":"INSERTED","type":"dbsync_packages"})"
    };
    const auto expectedResult10
    {
        R"({"component":"syscollector_osinfo","data":{"begin":"Microsoft Windows 7","end":"Microsoft Windows 7"},"type":"integrity_check_global"})"
    };
    const auto expectedResult11
    {
        R"({"component":"syscollector_network_iface","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult12
    {
        R"({"component":"syscollector_network_protocol","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult13
    {
        R"({"component":"syscollector_network_address","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult14
    {
        R"({"component":"syscollector_ports","data":{"begin":"0","end":"0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult16
    {
        R"({"component":"syscollector_hwinfo","data":{"begin":"Intel Corporation","end":"Intel Corporation"},"type":"integrity_check_global"})"
    };
    const auto expectedResult17
    {
        R"({"component":"syscollector_packages","data":{"begin":"xserver-xorg","end":"xserver-xorg"},"type":"integrity_check_global"})"
    };
    const auto expectedResult18
    {
        R"({"data":{"hotfix_name":"KB12345678"},"operation":"INSERTED","type":"dbsync_hotfixes"})"
    };
    const auto expectedResult19
    {
        R"({"component":"syscollector_hotfixes","data":{"begin":"KB12345678","end":"KB12345678"},"type":"integrity_check_global"})"
    };
    const auto expectedResult20
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv6"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult21
    {
        R"({"component":"syscollector_processes","data":{},"type":"integrity_clear"})"
    };
    const auto expectedResult22
    {
        R"({"data":{"group_description":null,"group_id":1,"group_id_signed":1,"group_is_hidden":0,"group_name":"daemon","group_users":"daemon:pollinate:vboxadd","group_uuid":null},"operation":"INSERTED","type":"dbsync_groups"})"
    };
    const auto expectedResult23
    {
        R"({"component":"syscollector_groups","data":{"begin":"daemon","end":"daemon"},"type":"integrity_check_global"})"
    };
    const auto expectedResult24
    {
        R"({"component":"syscollector_users","data":{"begin":"root","end":"root"},"type":"integrity_check_global"})"
    };
    const auto expectedResult25
    {
        R"({"data":{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null},"operation":"INSERTED","type":"dbsync_users"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult3)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult4)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult5)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult6)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult7)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult9)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult10)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult11)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult12)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult13)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult14)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult16)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult17)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult18)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult19)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult20)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult21)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult22)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult23)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult24)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult25)).Times(1);

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
                                          3600, true, true, true, true, true, true, true, false, true, true, true, true);
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
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"serial_number":"Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz", "memory_free":2257872,"memory_total":4972208,"memory_used":54})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":"x86_64", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_distribution_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_mtu":1500, "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"ethernet", "interface_state":"up", "network_dhcp":"disabled","network_metric":"75","network_netmask":"255.0.0.0","network_protocol":"IPv4","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":"unknown","network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":"unknown","network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"architecture":"amd64", "category":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14","type":"deb","path":" "})"_json));

    EXPECT_CALL(*spInfoWrapper, hotfixes()).Times(0);

    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"kworker/u256:2-","pid":"431625","parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

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
            delta["data"].erase("checksum");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto expectedResult1
    {
        R"({"data":{"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","cpu_speed":2904,"memory_free":2257872,"memory_total":4972208,"memory_used":54,"serial_number":"Intel Corporation"},"operation":"INSERTED","type":"dbsync_hwinfo"})"
    };
    const auto expectedResult2
    {
        R"({"data":{"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_distribution_release":"sp1","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_version":"6.1.7601"},"operation":"INSERTED","type":"dbsync_osinfo"})"
    };
    const auto expectedResult3
    {
        R"({"data":{"host_mac":"d4:5d:64:51:07:5d","host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0,"host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"interface_alias":" ","interface_mtu":1500,"interface_name":"enp4s0","interface_state":"up","interface_type":"ethernet"},"operation":"INSERTED","type":"dbsync_network_iface"})"
    };
    const auto expectedResult4
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv4"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult5
    {
        R"({"data":{"interface_name":"enp4s0","network_broadcast":"192.168.153.255","network_ip":"192.168.153.1","network_netmask":"255.255.255.0","network_protocol":0},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult6
    {
        R"({"data":{"interface_name":"enp4s0","network_ip":"fe80::250:56ff:fec0:8","network_netmask":"ffff:ffff:ffff:ffff::","network_protocol":1},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult7
    {
        R"({"data":{"destination_ip":"0.0.0.0","destination_port":0,"file_inode":0,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":"listening","network_transport":"tcp","process_name":"System Idle Process","process_pid":0,"source_ip":"127.0.0.1","source_port":631},"operation":"INSERTED","type":"dbsync_ports"})"
    };
    const auto expectedResult8
    {
        R"({"data":{"name":"kworker/u256:2-","parent_pid":2,"pid":"431625","start":9302261,"state":"I","stime":3,"utime":0},"operation":"INSERTED","type":"dbsync_processes"})"
    };
    const auto expectedResult9
    {
        R"({"data":{"architecture":"amd64","category":"x11","name":"xserver-xorg","path":" ","priority":"optional","size":4111222333,"source":"xorg","type":"deb","version":"1:7.7+19ubuntu14"},"operation":"INSERTED","type":"dbsync_packages"})"
    };
    const auto expectedResult10
    {
        R"({"component":"syscollector_osinfo","data":{"begin":"Microsoft Windows 7","end":"Microsoft Windows 7"},"type":"integrity_check_global"})"
    };
    const auto expectedResult11
    {
        R"({"component":"syscollector_network_iface","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult12
    {
        R"({"component":"syscollector_network_protocol","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult13
    {
        R"({"component":"syscollector_network_address","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult14
    {
        R"({"component":"syscollector_ports","data":{"begin":"0","end":"0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult15
    {
        R"({"component":"syscollector_processes","data":{"begin":"431625","end":"431625"},"type":"integrity_check_global"})"
    };
    const auto expectedResult16
    {
        R"({"component":"syscollector_hwinfo","data":{"begin":"Intel Corporation","end":"Intel Corporation"},"type":"integrity_check_global"})"
    };
    const auto expectedResult17
    {
        R"({"component":"syscollector_packages","data":{"begin":"xserver-xorg","end":"xserver-xorg"},"type":"integrity_check_global"})"
    };
    const auto expectedResult18
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv6"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult19
    {
        R"({"component":"syscollector_hotfixes","data":{},"type":"integrity_clear"})"
    };
    const auto expectedResult20
    {
        R"({"data":{"group_description":null,"group_id":1,"group_id_signed":1,"group_is_hidden":0,"group_name":"daemon","group_users":"daemon:pollinate:vboxadd","group_uuid":null},"operation":"INSERTED","type":"dbsync_groups"})"
    };
    const auto expectedResult21
    {
        R"({"component":"syscollector_groups","data":{"begin":"daemon","end":"daemon"},"type":"integrity_check_global"})"
    };
    const auto expectedResult22
    {
        R"({"component":"syscollector_users","data":{"begin":"root","end":"root"},"type":"integrity_check_global"})"
    };
    const auto expectedResult23
    {
        R"({"data":{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null},"operation":"INSERTED","type":"dbsync_users"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult3)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult4)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult5)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult6)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult7)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult8)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult9)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult10)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult11)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult12)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult13)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult14)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult15)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult16)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult17)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult18)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult19)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult20)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult21)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult22)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult23)).Times(1);

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
                                          3600, true, true, true, true, true, true, true, true, false, true, true, true);
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
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"serial_number":"Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz", "memory_free":2257872,"memory_total":4972208,"memory_used":54})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":"x86_64", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_distribution_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_mtu":1500, "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"ethernet", "interface_state":"up", "network_dhcp":"disabled","network_metric":"75","network_netmask":"255.0.0.0","network_protocol":"IPv4","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":"unknown","network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":"unknown","network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"architecture":"amd64", "category":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14","type":"deb","path":" "})"_json));

    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix_name":"KB12345678"}])"_json));

    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"kworker/u256:2-","pid":"431625","parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));


    EXPECT_CALL(*spInfoWrapper, users()).Times(0);

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
            delta["data"].erase("checksum");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto expectedResult1
    {
        R"({"data":{"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","cpu_speed":2904,"memory_free":2257872,"memory_total":4972208,"memory_used":54,"serial_number":"Intel Corporation"},"operation":"INSERTED","type":"dbsync_hwinfo"})"
    };
    const auto expectedResult2
    {
        R"({"data":{"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_distribution_release":"sp1","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_version":"6.1.7601"},"operation":"INSERTED","type":"dbsync_osinfo"})"
    };
    const auto expectedResult3
    {
        R"({"data":{"host_mac":"d4:5d:64:51:07:5d","host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0,"host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"interface_alias":" ","interface_mtu":1500,"interface_name":"enp4s0","interface_state":"up","interface_type":"ethernet"},"operation":"INSERTED","type":"dbsync_network_iface"})"
    };
    const auto expectedResult4
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv4"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult5
    {
        R"({"data":{"interface_name":"enp4s0","network_broadcast":"192.168.153.255","network_ip":"192.168.153.1","network_netmask":"255.255.255.0","network_protocol":0},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult6
    {
        R"({"data":{"interface_name":"enp4s0","network_ip":"fe80::250:56ff:fec0:8","network_netmask":"ffff:ffff:ffff:ffff::","network_protocol":1},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult7
    {
        R"({"data":{"destination_ip":"0.0.0.0","destination_port":0,"file_inode":0,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":"listening","network_transport":"tcp","process_name":"System Idle Process","process_pid":0,"source_ip":"127.0.0.1","source_port":631},"operation":"INSERTED","type":"dbsync_ports"})"
    };
    const auto expectedResult8
    {
        R"({"data":{"name":"kworker/u256:2-","parent_pid":2,"pid":"431625","start":9302261,"state":"I","stime":3,"utime":0},"operation":"INSERTED","type":"dbsync_processes"})"
    };
    const auto expectedResult9
    {
        R"({"data":{"architecture":"amd64","category":"x11","name":"xserver-xorg","path":" ","priority":"optional","size":4111222333,"source":"xorg","type":"deb","version":"1:7.7+19ubuntu14"},"operation":"INSERTED","type":"dbsync_packages"})"
    };
    const auto expectedResult10
    {
        R"({"component":"syscollector_osinfo","data":{"begin":"Microsoft Windows 7","end":"Microsoft Windows 7"},"type":"integrity_check_global"})"
    };
    const auto expectedResult11
    {
        R"({"component":"syscollector_network_iface","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult12
    {
        R"({"component":"syscollector_network_protocol","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult13
    {
        R"({"component":"syscollector_network_address","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult14
    {
        R"({"component":"syscollector_ports","data":{"begin":"0","end":"0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult15
    {
        R"({"component":"syscollector_processes","data":{"begin":"431625","end":"431625"},"type":"integrity_check_global"})"
    };
    const auto expectedResult16
    {
        R"({"component":"syscollector_hwinfo","data":{"begin":"Intel Corporation","end":"Intel Corporation"},"type":"integrity_check_global"})"
    };
    const auto expectedResult17
    {
        R"({"component":"syscollector_packages","data":{"begin":"xserver-xorg","end":"xserver-xorg"},"type":"integrity_check_global"})"
    };
    const auto expectedResult18
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv6"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult19
    {
        R"({"component":"syscollector_hotfixes","data":{"begin":"KB12345678","end":"KB12345678"},"type":"integrity_check_global"})"
    };
    const auto expectedResult20
    {
        R"({"data":{"hotfix_name":"KB12345678"},"operation":"INSERTED","type":"dbsync_hotfixes"})"
    };
    const auto expectedResult21
    {
        R"({"component":"syscollector_users","data":{},"type":"integrity_clear"})"
    };
    const auto expectedResult22
    {
        R"({"component":"syscollector_groups","data":{"begin":"daemon","end":"daemon"},"type":"integrity_check_global"})"
    };
    const auto expectedResult23
    {
        R"({"data":{"group_description":null,"group_id":1,"group_id_signed":1,"group_is_hidden":0,"group_name":"daemon","group_users":"daemon:pollinate:vboxadd","group_uuid":null},"operation":"INSERTED","type":"dbsync_groups"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult3)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult4)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult5)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult6)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult7)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult8)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult9)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult10)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult11)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult12)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult13)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult14)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult15)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult16)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult17)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult18)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult19)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult20)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult21)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult22)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult23)).Times(1);

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
                                          3600, true, true, true, true, true, true, true, true, true, true, false, true);
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
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"serial_number":"Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz", "memory_free":2257872,"memory_total":4972208,"memory_used":54})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":"x86_64", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_distribution_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_mtu":1500, "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"ethernet", "interface_state":"up", "network_dhcp":"disabled","network_metric":"75","network_netmask":"255.0.0.0","network_protocol":"IPv4","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":"unknown","network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":"unknown","network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"architecture":"amd64", "category":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14","type":"deb","path":" "})"_json));

    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix_name":"KB12345678"}])"_json));

    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"kworker/u256:2-","pid":"431625","parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).Times(0);

    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

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
            delta["data"].erase("checksum");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto expectedResult1
    {
        R"({"data":{"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","cpu_speed":2904,"memory_free":2257872,"memory_total":4972208,"memory_used":54,"serial_number":"Intel Corporation"},"operation":"INSERTED","type":"dbsync_hwinfo"})"
    };
    const auto expectedResult2
    {
        R"({"data":{"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_distribution_release":"sp1","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_version":"6.1.7601"},"operation":"INSERTED","type":"dbsync_osinfo"})"
    };
    const auto expectedResult3
    {
        R"({"data":{"host_mac":"d4:5d:64:51:07:5d","host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0,"host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"interface_alias":" ","interface_mtu":1500,"interface_name":"enp4s0","interface_state":"up","interface_type":"ethernet"},"operation":"INSERTED","type":"dbsync_network_iface"})"
    };
    const auto expectedResult4
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv4"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult5
    {
        R"({"data":{"interface_name":"enp4s0","network_broadcast":"192.168.153.255","network_ip":"192.168.153.1","network_netmask":"255.255.255.0","network_protocol":0},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult6
    {
        R"({"data":{"interface_name":"enp4s0","network_ip":"fe80::250:56ff:fec0:8","network_netmask":"ffff:ffff:ffff:ffff::","network_protocol":1},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult7
    {
        R"({"data":{"destination_ip":"0.0.0.0","destination_port":0,"file_inode":0,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":"listening","network_transport":"tcp","process_name":"System Idle Process","process_pid":0,"source_ip":"127.0.0.1","source_port":631},"operation":"INSERTED","type":"dbsync_ports"})"
    };
    const auto expectedResult8
    {
        R"({"data":{"name":"kworker/u256:2-","parent_pid":2,"pid":"431625","start":9302261,"state":"I","stime":3,"utime":0},"operation":"INSERTED","type":"dbsync_processes"})"
    };
    const auto expectedResult9
    {
        R"({"data":{"architecture":"amd64","category":"x11","name":"xserver-xorg","path":" ","priority":"optional","size":4111222333,"source":"xorg","type":"deb","version":"1:7.7+19ubuntu14"},"operation":"INSERTED","type":"dbsync_packages"})"
    };
    const auto expectedResult10
    {
        R"({"component":"syscollector_osinfo","data":{"begin":"Microsoft Windows 7","end":"Microsoft Windows 7"},"type":"integrity_check_global"})"
    };
    const auto expectedResult11
    {
        R"({"component":"syscollector_network_iface","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult12
    {
        R"({"component":"syscollector_network_protocol","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult13
    {
        R"({"component":"syscollector_network_address","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult14
    {
        R"({"component":"syscollector_ports","data":{"begin":"0","end":"0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult15
    {
        R"({"component":"syscollector_processes","data":{"begin":"431625","end":"431625"},"type":"integrity_check_global"})"
    };
    const auto expectedResult16
    {
        R"({"component":"syscollector_hwinfo","data":{"begin":"Intel Corporation","end":"Intel Corporation"},"type":"integrity_check_global"})"
    };
    const auto expectedResult17
    {
        R"({"component":"syscollector_packages","data":{"begin":"xserver-xorg","end":"xserver-xorg"},"type":"integrity_check_global"})"
    };
    const auto expectedResult18
    {
        R"({"data":{"hotfix_name":"KB12345678"},"operation":"INSERTED","type":"dbsync_hotfixes"})"
    };
    const auto expectedResult19
    {
        R"({"component":"syscollector_hotfixes","data":{"begin":"KB12345678","end":"KB12345678"},"type":"integrity_check_global"})"
    };
    const auto expectedResult20
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv6"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult21
    {
        R"({"component":"syscollector_groups","data":{},"type":"integrity_clear"})"
    };
    const auto expectedResult24
    {
        R"({"component":"syscollector_users","data":{"begin":"root","end":"root"},"type":"integrity_check_global"})"
    };
    const auto expectedResult25
    {
        R"({"data":{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null},"operation":"INSERTED","type":"dbsync_users"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult3)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult4)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult5)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult6)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult7)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult8)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult9)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult10)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult11)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult12)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult13)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult14)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult15)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult16)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult17)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult18)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult19)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult20)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult21)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult24)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult25)).Times(1);

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
                                          3600, true, true, true, true, true, true, true, true, true, false, true, true);
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
    constexpr auto messageToPush{R"(syscollector_network_iface dbsync checksum_fail {"begin":"enp4s0","end":"enp4s0","id":1606851004})"};
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"serial_number":"Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","memory_free":2257872,"memory_total":4972208,"memory_used":54})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_mtu":1500, "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"ethernet", "interface_state":"up", "network_dhcp":"disabled","network_metric":"75","network_netmask":"255.0.0.0","network_protocol":"IPv4","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":"unknown","network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":"unknown","network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":"x86_64", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_distribution_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix_name":"KB12345678"}])"_json));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"TEXT", "version":"TEXT", "vendor":"TEXT", "installed":"TEXT", "path":"TEXT", "architecture":"TEXT", "category":"TEXT", "description":"TEXT", "size":"TEXT", "priority":"TEXT", "multiarch":"TEXT", "source":"TEXT", "os_patch":"TEXT"})"_json));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"kworker/u256:2-","pid":431625,"parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

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
                                          60, true, true, true, true, true, true, true, true, true, true, true, true);
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
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"serial_number":"Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","memory_free":2257872,"memory_total":4972208,"memory_used":54})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_mtu":1500, "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"ethernet", "interface_state":"up", "network_dhcp":"disabled","network_metric":"75","network_netmask":"255.0.0.0","network_protocol":"IPv4","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":"unknown","network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":"unknown","network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":"x86_64", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_distribution_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix_name":"KB12345678"}])"_json));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"architecture":"amd64", "category":"x11","name":"xserver-xorg","priority":"optional","size":"411","source":"xorg","version":"1:7.7+19ubuntu14", "os_patch":"","type":"deb","path":" "})"_json));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"kworker/u256:2-","pid":"45","parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));

    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));
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
            delta["data"].erase("checksum");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto expectedResult1
    {
        R"({"component":"syscollector_hwinfo","data":{"begin":"Intel Corporation","end":"Intel Corporation"},"type":"integrity_check_global"})"
    };
    const auto expectedResult2
    {
        R"({"component":"syscollector_osinfo","data":{"begin":"Microsoft Windows 7","end":"Microsoft Windows 7"},"type":"integrity_check_global"})"
    };
    const auto expectedResult3
    {
        R"({"component":"syscollector_network_iface","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult4
    {
        R"({"component":"syscollector_network_protocol","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult5
    {
        R"({"component":"syscollector_packages","data":{"begin":"xserver-xorg","end":"xserver-xorg"},"type":"integrity_check_global"})"
    };
    const auto expectedResult6
    {
        R"({"component":"syscollector_hotfixes","data":{"begin":"KB12345678","end":"KB12345678"},"type":"integrity_check_global"})"
    };
    const auto expectedResult7
    {
        R"({"component":"syscollector_ports","data":{"begin":"0","end":"0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult8
    {
        R"({"component":"syscollector_processes","data":{"begin":"45","end":"45"},"type":"integrity_check_global"})"
    };
    const auto expectedResult10
    {
        R"({"component":"syscollector_network_address","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult11
    {
        R"({"data":{"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","cpu_speed":2904,"memory_free":2257872,"memory_total":4972208,"memory_used":54,"serial_number":"Intel Corporation"},"operation":"INSERTED","type":"dbsync_hwinfo"})"
    };
    const auto expectedResult12
    {
        R"({"data":{"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_distribution_release":"sp1","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_version":"6.1.7601"},"operation":"INSERTED","type":"dbsync_osinfo"})"
    };
    const auto expectedResult13
    {
        R"({"data":{"host_mac":"d4:5d:64:51:07:5d","host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0,"host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"interface_alias":" ","interface_mtu":1500,"interface_name":"enp4s0","interface_state":"up","interface_type":"ethernet"},"operation":"INSERTED","type":"dbsync_network_iface"})"
    };
    const auto expectedResult14
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv4"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult15
    {
        R"({"data":{"interface_name":"enp4s0","network_broadcast":"192.168.153.255","network_ip":"192.168.153.1","network_netmask":"255.255.255.0","network_protocol":0},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult16
    {
        R"({"data":{"interface_name":"enp4s0","network_ip":"fe80::250:56ff:fec0:8","network_netmask":"ffff:ffff:ffff:ffff::","network_protocol":1},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult17
    {
        R"({"data":{"architecture":"amd64","category":"x11","name":"xserver-xorg","os_patch":null,"path":" ","priority":"optional","size":"411","source":"xorg","type":"deb","version":"1:7.7+19ubuntu14"},"operation":"INSERTED","type":"dbsync_packages"})"
    };
    const auto expectedResult18
    {
        R"({"data":{"hotfix_name":"KB12345678"},"operation":"INSERTED","type":"dbsync_hotfixes"})"
    };
    const auto expectedResult19
    {
        R"({"data":{"destination_ip":"0.0.0.0","destination_port":0,"file_inode":0,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":"listening","network_transport":"tcp","process_name":"System Idle Process","process_pid":0,"source_ip":"127.0.0.1","source_port":631},"operation":"INSERTED","type":"dbsync_ports"})"
    };
    const auto expectedResult20
    {
        R"({"data":{"name":"kworker/u256:2-","parent_pid":2,"pid":"45","start":9302261,"state":"I","stime":3,"utime":0},"operation":"INSERTED","type":"dbsync_processes"})"
    };
    const auto expectedResult21
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv6"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult22
    {
        R"({"component":"syscollector_groups","data":{"begin":"daemon","end":"daemon"},"type":"integrity_check_global"})"
    };
    const auto expectedResult23
    {
        R"({"data":{"group_description":null,"group_id":1,"group_id_signed":1,"group_is_hidden":0,"group_name":"daemon","group_users":"daemon:pollinate:vboxadd","group_uuid":null},"operation":"INSERTED","type":"dbsync_groups"})"
    };
    const auto expectedResult24
    {
        R"({"component":"syscollector_users","data":{"begin":"root","end":"root"},"type":"integrity_check_global"})"
    };
    const auto expectedResult25
    {
        R"({"data":{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null},"operation":"INSERTED","type":"dbsync_users"})"
    };

    EXPECT_CALL(wrapper, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult3)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult4)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult5)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult6)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult7)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult8)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult10)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult11)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult12)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult13)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult14)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult15)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult16)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult17)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult18)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult19)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult20)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult21)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult22)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult23)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult24)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult25)).Times(1);

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
                                          60, true, true, true, true, true, true, true, true, true, true, true, true);
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
    constexpr auto messageToPush{R"(syscollector_network_iface dbsync checksum_fail {"end":"enp4s0","id":1606851004})"};
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"serial_number":"Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","memory_free":2257872,"memory_total":4972208,"memory_used":54})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_mtu":1500, "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"ethernet", "interface_state":"up", "network_dhcp":"disabled","network_metric":"75","network_netmask":"255.0.0.0","network_protocol":"IPv4","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":"unknown","network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":"unknown","network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":"x86_64", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_distribution_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix_name":"KB12345678"},{"hotfix_name":"KB87654321"}])"_json));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"TEXT", "version":"TEXT", "vendor":"TEXT", "installed":"TEXT", "path":"TEXT", "architecture":"TEXT", "category":"TEXT", "description":"TEXT", "size":"TEXT", "priority":"TEXT", "multiarch":"TEXT", "source":"TEXT", "os_patch":"TEXT"})"_json));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"kworker/u256:2-","pid":431625,"parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

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
                                          60, true, true, true, true, true, true, true, true, true, true, true, true);
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
    constexpr auto messageToPush{R"(syscollector_network_iface dbsync checksum_fail {"end":"enp4s0","id":1606851004})"};
    const auto spInfoWrapper{std::make_shared<SysInfoWrapper>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"serial_number":"Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","memory_free":2257872,"memory_total":4972208,"memory_used":54})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_mtu":1500, "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"ethernet", "interface_state":"up", "network_dhcp":"disabled","network_metric":"75","network_netmask":"255.0.0.0","network_protocol":"IPv4","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":"unknown","network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":"unknown","network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":"x86_64", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_distribution_release":"sp1","os_version":"6.1.7601"})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix_name":"KB12345678"},{"hotfix_name":"KB87654321"}])"_json));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"TEXT", "version":"TEXT", "vendor":"TEXT", "installed":"TEXT", "path":"TEXT", "architecture":"TEXT", "category":"TEXT", "description":"TEXT", "size":"TEXT", "priority":"TEXT", "multiarch":"TEXT", "source":"TEXT", "os_patch":"TEXT"})"_json));
    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":"kworker/u256:2-","pid":431625,"parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

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
                                          60, true, true, true, true, true, true, true, true, true, true, true, true);
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
            "destination_ip":"0.0.0.0",
            "destination_port":0,
            "file_inode":43481,
            "host_network_egress_queue":0,
            "host_network_ingress_queue":0,
            "interface_state":"",
            "network_transport":"udp",
            "process_name":"",
            "process_pid":0,
            "source_ip":"0.0.0.0",
            "source_port":47748
        },
        {
            "destination_ip":"::",
            "destination_port":0,
            "file_inode":43482,
            "host_network_egress_queue":0,
            "host_network_ingress_queue":0,
            "interface_state":"",
            "network_transport":"udp6",
            "process_name":"",
            "process_pid":0,
            "source_ip":"::",
            "source_port":51087
        },
        {
            "destination_ip":"0.0.0.0",
            "destination_port":0,
            "file_inode":50324,
            "host_network_egress_queue":0,
            "host_network_ingress_queue":0,
            "interface_state":"listening",
            "network_transport":"tcp",
            "process_name":"",
            "process_pid":0,
            "source_ip":"127.0.0.1",
            "source_port":33060
        },
        {
            "destination_ip":"44.238.116.130",
            "destination_port":443,
            "file_inode":122575,
            "host_network_egress_queue":0,
            "host_network_ingress_queue":0,
            "interface_state":"established",
            "network_transport":"tcp",
            "process_name":"",
            "process_pid":0,
            "source_ip":"192.168.0.104",
            "source_port":39106
        },
        {
            "destination_ip":"44.238.116.130",
            "destination_port":443,
            "file_inode":122575,
            "host_network_egress_queue":0,
            "host_network_ingress_queue":0,
            "interface_state":"established",
            "network_transport":"tcp",
            "process_name":"",
            "process_pid":0,
            "source_ip":"192.168.0.104",
            "source_port":39106
        }
    ])")));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            wrapper.callbackMock(delta.dump());
        }
    };
    const auto expectedResult1
    {
        R"({"data":{"destination_ip":"0.0.0.0","destination_port":0,"file_inode":43481,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":null,"network_transport":"udp","process_name":null,"process_pid":0,"source_ip":"0.0.0.0","source_port":47748},"operation":"INSERTED","type":"dbsync_ports"})"
    };

    const auto expectedResult2
    {
        R"({"data":{"destination_ip":"::","destination_port":0,"file_inode":43482,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":null,"network_transport":"udp6","process_name":null,"process_pid":0,"source_ip":"::","source_port":51087},"operation":"INSERTED","type":"dbsync_ports"})"
    };

    const auto expectedResult3
    {
        R"({"data":{"destination_ip":"0.0.0.0","destination_port":0,"file_inode":50324,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":"listening","network_transport":"tcp","process_name":null,"process_pid":0,"source_ip":"127.0.0.1","source_port":33060},"operation":"INSERTED","type":"dbsync_ports"})"
    };

    const auto expectedResult4
    {
        R"({"data":{"destination_ip":"44.238.116.130","destination_port":443,"file_inode":122575,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":"established","network_transport":"tcp","process_name":null,"process_pid":0,"source_ip":"192.168.0.104","source_port":39106},"operation":"INSERTED","type":"dbsync_ports"})"
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
                                          3600, true, false, false, false, false, true, true, false, false, false, false, true);
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
            "destination_ip":"0.0.0.0",
            "destination_port":0,
            "file_inode":43481,
            "host_network_egress_queue":0,
            "host_network_ingress_queue":0,
            "interface_state":"",
            "network_transport":"udp",
            "process_name":"",
            "process_pid":0,
            "source_ip":"0.0.0.0",
            "source_port":47748
        },
        {
            "destination_ip":"::",
            "destination_port":0,
            "file_inode":43482,
            "host_network_egress_queue":0,
            "host_network_ingress_queue":0,
            "interface_state":"",
            "network_transport":"udp6",
            "process_name":"",
            "process_pid":0,
            "source_ip":"::",
            "source_port":51087
        },
        {
            "destination_ip":"0.0.0.0",
            "destination_port":0,
            "file_inode":50324,
            "host_network_egress_queue":0,
            "host_network_ingress_queue":0,
            "interface_state":"listening",
            "network_transport":"tcp",
            "process_name":"",
            "process_pid":0,
            "source_ip":"127.0.0.1",
            "source_port":33060
        },
        {
            "destination_ip":"0.0.0.0",
            "destination_port":0,
            "file_inode":50324,
            "host_network_egress_queue":0,
            "host_network_ingress_queue":0,
            "interface_state":"listening",
            "network_transport":"tcp",
            "process_name":"",
            "process_pid":0,
            "source_ip":"127.0.0.1",
            "source_port":33060
        },
        {
            "destination_ip":"44.238.116.130",
            "destination_port":443,
            "file_inode":122575,
            "host_network_egress_queue":0,
            "host_network_ingress_queue":0,
            "interface_state":"established",
            "network_transport":"tcp",
            "process_name":"",
            "process_pid":0,
            "source_ip":"192.168.0.104",
            "source_port":39106
        }
    ])")));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            wrapper.callbackMock(delta.dump());
        }
    };
    const auto expectedResult1
    {
        R"({"data":{"destination_ip":"0.0.0.0","destination_port":0,"file_inode":43481,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":null,"network_transport":"udp","process_name":null,"process_pid":0,"source_ip":"0.0.0.0","source_port":47748},"operation":"INSERTED","type":"dbsync_ports"})"
    };

    const auto expectedResult2
    {
        R"({"data":{"destination_ip":"::","destination_port":0,"file_inode":43482,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":null,"network_transport":"udp6","process_name":null,"process_pid":0,"source_ip":"::","source_port":51087},"operation":"INSERTED","type":"dbsync_ports"})"
    };

    const auto expectedResult3
    {
        R"({"data":{"destination_ip":"0.0.0.0","destination_port":0,"file_inode":50324,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":"listening","network_transport":"tcp","process_name":null,"process_pid":0,"source_ip":"127.0.0.1","source_port":33060},"operation":"INSERTED","type":"dbsync_ports"})"
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
                                          3600, true, false, false, false, false, true, false, false, false, false, false, true);
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
                  (R"({"architecture":"amd64", "category":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14","type":"deb","path":" "})"_json),
                  ::testing::InvokeArgument<0>
                  (R"({"architecture":"amd64", "category":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14","type":"deb","path":" "})"_json)));



    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);
            delta["data"].erase("checksum");
            wrapper.callbackMock(delta.dump());
        }
    };

    const auto expectedResult1
    {
        R"({"data":{"architecture":"amd64","category":"x11","name":"xserver-xorg","path":" ","priority":"optional","size":4111222333,"source":"xorg","type":"deb","version":"1:7.7+19ubuntu14"},"operation":"INSERTED","type":"dbsync_packages"})"
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
                                          3600, true, false, false, false, true, false, false, false, false, false, false, true);
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
                                                                      R"({"serial_number":" Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":" Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz ", "memory_free":2257872,"memory_total":4972208,"memory_used":54})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":" x86_64", "hostname":" UBUNTU ","os_build":"  7601","os_major":"6  ","os_minor":"  1  ","os_name":" Microsoft   Windows  7 ","os_distribution_release":"   sp1","os_version":"6.1.7601   "})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"   ethernet", "interface_state":"up   ", "network_dhcp":"disabled","interface_mtu":1500,"host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":"unknown","network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":"unknown","network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"file_inode":0,"source_ip":" 127.0.0.1 ", "source_port":631,"process_pid":0,"process_name":"System  Idle Process","network_transport":"tcp   ","destination_ip":"   0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"architecture":" amd64", "category":"  x11  ","name":" xserver-xorg","priority":"optional ","size":4111222333,"source":"xorg","version":"1:7.7+19ubuntu14","type":"deb","path":" "})"_json));

    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix_name":" KB12345678 "}])"_json));

    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":" kworker/u256:2-  ","pid":"  431625  ","parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));

    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

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
            delta["data"].erase("checksum");
            wrapperDelta.callbackMock(delta.dump());
        }
    };

    const auto expectedResult1
    {
        R"({"data":{"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","cpu_speed":2904,"memory_free":2257872,"memory_total":4972208,"memory_used":54,"serial_number":"Intel Corporation"},"operation":"INSERTED","type":"dbsync_hwinfo"})"
    };
    const auto expectedResult2
    {
        R"({"data":{"architecture":"x86_64","hostname":"UBUNTU","os_build":"7601","os_distribution_release":"sp1","os_major":"6","os_minor":"1","os_name":"Microsoft   Windows  7","os_version":"6.1.7601"},"operation":"INSERTED","type":"dbsync_osinfo"})"
    };
    const auto expectedResult3
    {
        R"({"data":{"host_mac":"d4:5d:64:51:07:5d","host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0,"host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"interface_alias":" ","interface_mtu":1500,"interface_name":"enp4s0","interface_state":"up","interface_type":"ethernet"},"operation":"INSERTED","type":"dbsync_network_iface"})"
    };
    const auto expectedResult4
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv4"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult5
    {
        R"({"data":{"interface_name":"enp4s0","network_broadcast":"192.168.153.255","network_ip":"192.168.153.1","network_netmask":"255.255.255.0","network_protocol":0},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult6
    {
        R"({"data":{"interface_name":"enp4s0","network_ip":"fe80::250:56ff:fec0:8","network_netmask":"ffff:ffff:ffff:ffff::","network_protocol":1},"operation":"INSERTED","type":"dbsync_network_address"})"
    };
    const auto expectedResult7
    {
        R"({"data":{"destination_ip":"0.0.0.0","destination_port":0,"file_inode":0,"host_network_egress_queue":0,"host_network_ingress_queue":0,"interface_state":"listening","network_transport":"tcp","process_name":"System  Idle Process","process_pid":0,"source_ip":"127.0.0.1","source_port":631},"operation":"INSERTED","type":"dbsync_ports"})"
    };
    const auto expectedResult8
    {
        R"({"data":{"name":"kworker/u256:2-","parent_pid":2,"pid":"431625","start":9302261,"state":"I","stime":3,"utime":0},"operation":"INSERTED","type":"dbsync_processes"})"
    };
    const auto expectedResult9
    {
        R"({"data":{"architecture":"amd64","category":"x11","name":"xserver-xorg","path":" ","priority":"optional","size":4111222333,"source":"xorg","type":"deb","version":"1:7.7+19ubuntu14"},"operation":"INSERTED","type":"dbsync_packages"})"
    };
    const auto expectedResult10
    {
        R"({"component":"syscollector_osinfo","data":{"begin":"Microsoft   Windows  7","end":"Microsoft   Windows  7"},"type":"integrity_check_global"})"
    };
    const auto expectedResult11
    {
        R"({"component":"syscollector_network_iface","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult12
    {
        R"({"component":"syscollector_network_protocol","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult13
    {
        R"({"component":"syscollector_network_address","data":{"begin":"enp4s0","end":"enp4s0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult14
    {
        R"({"component":"syscollector_ports","data":{"begin":"0","end":"0"},"type":"integrity_check_global"})"
    };
    const auto expectedResult15
    {
        R"({"component":"syscollector_processes","data":{"begin":"431625","end":"431625"},"type":"integrity_check_global"})"
    };
    const auto expectedResult16
    {
        R"({"component":"syscollector_hwinfo","data":{"begin":"Intel Corporation","end":"Intel Corporation"},"type":"integrity_check_global"})"
    };
    const auto expectedResult17
    {
        R"({"component":"syscollector_packages","data":{"begin":"xserver-xorg","end":"xserver-xorg"},"type":"integrity_check_global"})"
    };
    const auto expectedResult18
    {
        R"({"data":{"hotfix_name":"KB12345678"},"operation":"INSERTED","type":"dbsync_hotfixes"})"
    };
    const auto expectedResult19
    {
        R"({"component":"syscollector_hotfixes","data":{"begin":"KB12345678","end":"KB12345678"},"type":"integrity_check_global"})"
    };
    const auto expectedResult20
    {
        R"({"data":{"interface_name":"enp4s0","network_dhcp":"unknown","network_gateway":"192.168.0.1|600","network_metric":" ","network_type":"ipv6"},"operation":"INSERTED","type":"dbsync_network_protocol"})"
    };
    const auto expectedResult21
    {
        R"({"data":{"group_description":null,"group_id":1,"group_id_signed":1,"group_is_hidden":0,"group_name":"daemon","group_users":"daemon:pollinate:vboxadd","group_uuid":null},"operation":"INSERTED","type":"dbsync_groups"})"
    };
    const auto expectedResult22
    {
        R"({"component":"syscollector_groups","data":{"begin":"daemon","end":"daemon"},"type":"integrity_check_global"})"
    };
    const auto expectedResult23
    {
        R"({"component":"syscollector_users","data":{"begin":"root","end":"root"},"type":"integrity_check_global"})"
    };
    const auto expectedResult24
    {
        R"({"data":{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null},"operation":"INSERTED","type":"dbsync_users"})"
    };

    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult3)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult4)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult5)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult6)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult7)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult8)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult9)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult10)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult11)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult12)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult13)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult14)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult15)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult16)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult17)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult18)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult19)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult20)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult21)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult22)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult23)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expectedResult24)).Times(1);

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
                                          5, true, true, true, true, true, true, true, true, true, true, true, true);
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(1));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}
