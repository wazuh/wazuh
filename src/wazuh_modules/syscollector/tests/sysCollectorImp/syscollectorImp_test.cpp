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

#include <mock_sysinfo.hpp>

constexpr auto SYSCOLLECTOR_DB_PATH {":memory:"};

// Defines to replace inline JSON in EXPECT_CALLs
#define EXPECT_CALL_HARDWARE_JSON R"({"serial_number":"Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz", "memory_free":2257872,"memory_total":4972208,"memory_used":54})"
#define EXPECT_CALL_OS_JSON R"({"architecture":"x86_64", "hostname":"UBUNTU","os_build":"7601","os_major":"6","os_minor":"1","os_name":"Microsoft Windows 7","os_distribution_release":"sp1","os_version":"6.1.7601","os_type":"windows"})"
#define EXPECT_CALL_NETWORKS_JSON R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_mtu":1500, "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"ethernet", "interface_state":"up", "network_dhcp":0,"network_metric":"75","network_netmask":"255.0.0.0","network_type":"IPv4","host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":0,"network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":0,"network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})"
#define EXPECT_CALL_PORTS_JSON R"([{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])"
#define EXPECT_CALL_PORTS_ALL_JSON R"([{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"udp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"","host_network_egress_queue":0},{"file_inode":0,"source_ip":"127.0.0.1", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])"
#define EXPECT_CALL_PACKAGES_JSON R"({"architecture":"amd64", "category":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version_":"1:7.7+19ubuntu14","type":"deb","path":" "})"
#define EXPECT_CALL_HOTFIXES_JSON R"([{"hotfix_name":"KB12345678"}])"
#define EXPECT_CALL_PROCESSES_JSON R"({"name":"kworker/u256:2-","pid":"431625","parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"
#define EXPECT_CALL_GROUPS_JSON R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"
#define EXPECT_CALL_USERS_JSON R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"
#define EXPECT_CALL_SERVICES_JSON R"([{"service_id":"wazuh-agent","service_name":"Wazuh Agent","service_description":"Monitors system activity","service_state":"running","service_sub_state":"subState","service_start_type":"auto","service_type":"type","process_pid":1234,"service_exit_code":0,"service_win32_exit_code":0,"process_executable":"/usr/bin/wazuh-agent","service_address":"/lib/systemd/system/wazuh-agent.service","user_name":"root","service_enabled":"enabled","service_following":"following","service_object_path":"objectPath","service_target_ephemeral_id":0,"service_target_type":"jobType","service_target_address":"jobPath","file_path":"sourcePath"}])"
#define EXPECT_CALL_BROWSER_EXTENSIONS_JSON R"([{"browser_name":"chrome","user_id":"S-1-5-21-1234567890-987654321-1122334455-1001","package_name":"uBlock Origin","package_id":"cjpalhdlnbpafiamejdnhcphjbkeiagm","package_version_":"1.52.2","package_description":"Finally, an efficient wide-spectrum content blocker. Easy on CPU and memory.","package_vendor":"Raymond Hill","package_build_version":"","package_path":"C:\\Users\\john.doe\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\cjpalhdlnbpafiamejdnhcphjbkeiagm\\1.52.2_0","browser_profile_name":"Default","browser_profile_path":"C:\\Users\\john.doe\\AppData\\Local\\Google\\Chrome\\User Data\\Default","package_reference":"https://clients2.google.com/service/update2/crx","package_permissions":"[\\\"activeTab\\\",\\\"storage\\\",\\\"tabs\\\",\\\"webNavigation\\\"]","package_type":"extension","package_enabled":1,"package_visible":0,"package_autoupdate":1,"package_persistent":0,"package_from_webstore":1,"browser_profile_referenced":1,"package_installed":"1710489821000","file_hash_sha256":"a1b2c3d4e5f6789012345678901234567890abcdef123456789012345678901234","scan_time":"2020/12/28 21:49:50"}])"

const auto expected_dbsync_hwinfo
{
    R"({"collector":"dbsync_hwinfo","data":{"event":{"changed_fields":[],"type":"created"},"host":{"cpu":{"cores":2,"name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","speed":2904},"memory":{"free":2257872,"total":4972208,"used":54},"serial_number":"Intel Corporation"}},"module":"inventory"})"
};
const auto expected_dbsync_osinfo
{
    R"({"collector":"dbsync_osinfo","data":{"event":{"changed_fields":[],"type":"created"},"host":{"architecture":"x86_64","hostname":"UBUNTU","os":{"build":"7601","codename":null,"distribution":{"release":"sp1"},"full":null,"kernel":{"name":null,"release":null,"version":null},"major":"6","minor":"1","name":"Microsoft Windows 7","patch":null,"platform":null,"type":"windows","version":"6.1.7601"}}},"module":"inventory"})"
};
const auto expected_dbsync_network_iface
{
    R"({"collector":"dbsync_network_iface","data":{"event":{"changed_fields":[],"type":"created"},"host":{"mac":["d4:5d:64:51:07:5d"],"network":{"egress":{"bytes":0,"drops":0,"errors":0,"packets":0},"ingress":{"bytes":0,"drops":0,"errors":0,"packets":0}}},"interface":{"alias":null,"mtu":1500,"name":"enp4s0","state":"up","type":"ethernet"}},"module":"inventory"})"
};
const auto expected_dbsync_network_protocol_1
{
    R"({"collector":"dbsync_network_protocol","data":{"event":{"changed_fields":[],"type":"created"},"interface":{"name":"enp4s0"},"network":{"dhcp":false,"gateway":"192.168.0.1|600","metric":null,"type":"ipv4"}},"module":"inventory"})"
};
const auto expected_dbsync_network_protocol_2
{
    R"({"collector":"dbsync_network_protocol","data":{"event":{"changed_fields":[],"type":"created"},"interface":{"name":"enp4s0"},"network":{"dhcp":false,"gateway":"192.168.0.1|600","metric":null,"type":"ipv6"}},"module":"inventory"})"
};
const auto expected_dbsync_network_address_1
{
    R"({"collector":"dbsync_network_address","data":{"event":{"changed_fields":[],"type":"created"},"interface":{"name":"enp4s0"},"network":{"broadcast":null,"ip":"fe80::250:56ff:fec0:8","netmask":"ffff:ffff:ffff:ffff::","type":1}},"module":"inventory"})"
};
const auto expected_dbsync_network_address_2
{
    R"({"collector":"dbsync_network_address","data":{"event":{"changed_fields":[],"type":"created"},"interface":{"name":"enp4s0"},"network":{"broadcast":"192.168.153.255","ip":"192.168.153.1","netmask":"255.255.255.0","type":0}},"module":"inventory"})"
};
const auto expected_dbsync_ports
{
    R"({"collector":"dbsync_ports","data":{"destination":{"ip":"0.0.0.0","port":0},"event":{"changed_fields":[],"type":"created"},"file":{"inode":0},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":"listening"},"network":{"transport":"tcp"},"process":{"name":"System Idle Process","pid":0},"source":{"ip":"127.0.0.1","port":631}},"module":"inventory"})"
};
const auto expected_dbsync_ports_udp
{
    R"({"collector":"dbsync_ports","data":{"destination":{"ip":"0.0.0.0","port":0},"event":{"changed_fields":[],"type":"created"},"file":{"inode":0},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp"},"process":{"name":"System Idle Process","pid":0},"source":{"ip":"127.0.0.1","port":631}},"module":"inventory"})"
};
const auto expected_dbsync_processes
{
    R"({"collector":"dbsync_processes","data":{"event":{"changed_fields":[],"type":"created"},"process":{"args":null,"args_count":null,"command_line":null,"name":"kworker/u256:2-","parent":{"pid":2},"pid":"431625","start":9302261,"state":"I","stime":3,"utime":0}},"module":"inventory"})"
};
const auto expected_dbsync_packages
{
    R"({"collector":"dbsync_packages","data":{"event":{"changed_fields":[],"type":"created"},"package":{"architecture":"amd64","category":"x11","description":null,"installed":null,"multiarch":null,"name":"xserver-xorg","path":null,"priority":"optional","size":4111222333,"source":"xorg","type":"deb","vendor":null,"version":"1:7.7+19ubuntu14"}},"module":"inventory"})"
};
const auto expected_dbsync_hotfixes
{
    R"({"collector":"dbsync_hotfixes","data":{"event":{"changed_fields":[],"type":"created"},"package":{"hotfix":{"name":"KB12345678"}}},"module":"inventory"})"
};
const auto expected_dbsync_groups
{
    R"({"collector":"dbsync_groups","data":{"event":{"changed_fields":[],"type":"created"},"group":{"description":null,"id":1,"id_signed":1,"is_hidden":false,"name":"daemon","users":["daemon:pollinate:vboxadd"],"uuid":null}},"module":"inventory"})"
};
const auto expected_dbsync_users
{
    R"({"collector":"dbsync_users","data":{"event":{"changed_fields":[],"type":"created"},"host":{"ip":["192.168.0.84"]},"login":{"status":false,"tty":"pts/0","type":"user"},"process":{"pid":"129870"},"user":{"auth_failures":{"count":0,"timestamp":0},"created":0,"full_name":"root","group":{"id":0,"id_signed":0},"groups":[0],"home":"/root","id":0,"is_hidden":false,"is_remote":true,"last_login":"1749605216","name":"root","password":{"expiration_date":-1,"hash_algorithm":"y","inactive_days":-1,"last_change":1745971200.0,"max_days_between_changes":99999,"min_days_between_changes":0,"status":"active","warning_days_before_expiration":7},"roles":["sudo"],"shell":"/bin/bash","type":null,"uid_signed":0,"uuid":null}},"module":"inventory"})"
};
const auto expected_dbsync_services
{
    R"({"collector":"dbsync_services","data":{"error":{"log":{"file":{"path":null}}},"event":{"changed_fields":[],"type":"created"},"file":{"path":"sourcePath"},"log":{"file":{"path":null}},"process":{"args":null,"executable":"/usr/bin/wazuh-agent","group":{"name":null},"pid":1234,"root_directory":null,"user":{"name":null},"working_directory":null},"service":{"address":"/lib/systemd/system/wazuh-agent.service","description":"Monitors system activity","enabled":"enabled","exit_code":0,"following":"following","frequency":null,"id":"wazuh-agent","inetd_compatibility":null,"name":"Wazuh Agent","object_path":"objectPath","restart":null,"start_type":"auto","starts":{"on_mount":null,"on_not_empty_directory":null,"on_path_modified":null},"state":"running","sub_state":"subState","target":{"address":"jobPath","ephemeral_id":0,"type":"jobType"},"type":"type","win32_exit_code":0}},"module":"inventory"})"
};
const auto expected_dbsync_browser_extensions
{
    R"({"collector":"dbsync_browser_extensions","data":{"browser":{"name":"chrome","profile":{"name":"Default","path":"C:\\Users\\john.doe\\AppData\\Local\\Google\\Chrome\\User Data\\Default","referenced":true}},"event":{"changed_fields":[],"type":"created"},"file":{"hash":{"sha256":"a1b2c3d4e5f6789012345678901234567890abcdef123456789012345678901234"}},"package":{"autoupdate":true,"build_version":null,"description":"Finally, an efficient wide-spectrum content blocker. Easy on CPU and memory.","enabled":true,"from_webstore":true,"id":"cjpalhdlnbpafiamejdnhcphjbkeiagm","installed":1710489821000,"name":"uBlock Origin","path":"C:\\Users\\john.doe\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\cjpalhdlnbpafiamejdnhcphjbkeiagm\\1.52.2_0","permissions":["[\\\"activeTab\\\"","\\\"storage\\\"","\\\"tabs\\\"","\\\"webNavigation\\\"]"],"persistent":false,"reference":"https://clients2.google.com/service/update2/crx","type":"extension","vendor":"Raymond Hill","version":"1.52.2","visible":false},"user":{"id":"S-1-5-21-1234567890-987654321-1122334455-1001"}},"module":"inventory"})"
};

void SyscollectorImpTest::SetUp() {};

void SyscollectorImpTest::TearDown() {};

using ::testing::_;
using ::testing::Return;

class CallbackMock
{
    public:
        CallbackMock() = default;
        ~CallbackMock() = default;
        MOCK_METHOD(void, callbackMock, (const std::string&), ());
};

class CallbackMockPersist
{
    public:
        CallbackMockPersist() = default;
        ~CallbackMockPersist() = default;
        MOCK_METHOD(void, callbackMock, (const std::string&, Operation_t, const std::string&, const std::string&, uint64_t), ());
};

void reportFunction(const std::string& /*payload*/)
{
    //std::cout << payload << std::endl;
}

void persistFunction(const std::string&, Operation_t, const std::string&, const std::string& /*payload*/, uint64_t /*version*/)
{
    // std::cout << payload << std::endl;
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

// Expected results for persist callback - shared across all tests
static const auto expectedPersistHW
{
    R"({"checksum":{"hash":{"sha1":"0288831cec1334e0d67eb2f7b83e0c96d2abb9be"}},"host":{"cpu":{"cores":2,"name":"Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz","speed":2904},"memory":{"free":2257872,"total":4972208,"used":54},"serial_number":"Intel Corporation"}})"
};
static const auto expectedPersistOS
{
    R"({"checksum":{"hash":{"sha1":"5f16f23e53a4549d34861187bf592a76bee51282"}},"host":{"architecture":"x86_64","hostname":"UBUNTU","os":{"build":"7601","codename":null,"distribution":{"release":"sp1"},"full":null,"kernel":{"name":null,"release":null,"version":null},"major":"6","minor":"1","name":"Microsoft Windows 7","patch":null,"platform":null,"type":"windows","version":"6.1.7601"}}})"
};
static const auto expectedPersistNetIface
{
    R"({"checksum":{"hash":{"sha1":"712c4c9e6d65a48bc8fb0e99f8ce9238d88bbca4"}},"host":{"mac":["d4:5d:64:51:07:5d"],"network":{"egress":{"bytes":0,"drops":0,"errors":0,"packets":0},"ingress":{"bytes":0,"drops":0,"errors":0,"packets":0}}},"interface":{"alias":null,"mtu":1500,"name":"enp4s0","state":"up","type":"ethernet"}})"
};
static const auto expectedPersistNetProtoIPv4
{
    R"({"checksum":{"hash":{"sha1":"50f3c227c2278cdf43b6107da8455901a09dfa49"}},"interface":{"name":"enp4s0"},"network":{"dhcp":false,"gateway":"192.168.0.1|600","metric":null,"type":"ipv4"}})"
};
static const auto expectedPersistNetAddrIPv4
{
    R"({"checksum":{"hash":{"sha1":"24ecdd6a316b2320c809085106812f6cf8a4cf67"}},"interface":{"name":"enp4s0"},"network":{"broadcast":"192.168.153.255","ip":"192.168.153.1","netmask":"255.255.255.0","type":0}})"
};
static const auto expectedPersistNetProtoIPv6
{
    R"({"checksum":{"hash":{"sha1":"53a9aa90a75f0264beae6beb9bf19192cfc23df1"}},"interface":{"name":"enp4s0"},"network":{"dhcp":false,"gateway":"192.168.0.1|600","metric":null,"type":"ipv6"}})"
};
static const auto expectedPersistNetAddrIPv6
{
    R"({"checksum":{"hash":{"sha1":"7271714e0616caea85422916dd6ab2fbdac2b5cd"}},"interface":{"name":"enp4s0"},"network":{"broadcast":null,"ip":"fe80::250:56ff:fec0:8","netmask":"ffff:ffff:ffff:ffff::","type":1}})"
};
static const auto expectedPersistPorts
{
    R"({"checksum":{"hash":{"sha1":"7223807075622557e855677b47f23f321091353c"}},"destination":{"ip":"0.0.0.0","port":0},"file":{"inode":0},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":"listening"},"network":{"transport":"tcp"},"process":{"name":"System Idle Process","pid":0},"source":{"ip":"127.0.0.1","port":631}})"
};
static const auto expectedPersistPortsUdp
{
    R"({"checksum":{"hash":{"sha1":"dff9e7c5127ea90f4e9c38840683330b8c1351c9"}},"destination":{"ip":"0.0.0.0","port":0},"file":{"inode":0},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp"},"process":{"name":"System Idle Process","pid":0},"source":{"ip":"127.0.0.1","port":631}})"
};
static const auto expectedPersistProcess
{
    R"({"checksum":{"hash":{"sha1":"78e4e090e42f88d949428eb56836287f99de9f4f"}},"process":{"args":null,"args_count":null,"command_line":null,"name":"kworker/u256:2-","parent":{"pid":2},"pid":"431625","start":9302261,"state":"I","stime":3,"utime":0}})"
};
static const auto expectedPersistPackage
{
    R"({"checksum":{"hash":{"sha1":"403cf592e642409153762c635d50c05415f74dc0"}},"package":{"architecture":"amd64","category":"x11","description":null,"installed":null,"multiarch":null,"name":"xserver-xorg","path":null,"priority":"optional","size":4111222333,"source":"xorg","type":"deb","vendor":null,"version":"1:7.7+19ubuntu14"}})"
};
static const auto expectedPersistHotfix
{
    R"({"checksum":{"hash":{"sha1":"759c555df92c606e73b435e5e768d692b9815e29"}},"package":{"hotfix":{"name":"KB12345678"}}})"
};
static const auto expectedPersistGroup
{
    R"({"checksum":{"hash":{"sha1":"81793e529c565256a60eff6c6345e2f5c5ee8cb0"}},"group":{"description":null,"id":1,"id_signed":1,"is_hidden":false,"name":"daemon","users":["daemon:pollinate:vboxadd"],"uuid":null}})"
};
static const auto expectedPersistUser
{
    R"({"checksum":{"hash":{"sha1":"11769088416d594d547a508e084cec990e282ece"}},"host":{"ip":["192.168.0.84"]},"login":{"status":false,"tty":"pts/0","type":"user"},"process":{"pid":"129870"},"user":{"auth_failures":{"count":0,"timestamp":0},"created":0,"full_name":"root","group":{"id":0,"id_signed":0},"groups":[0],"home":"/root","id":0,"is_hidden":false,"is_remote":true,"last_login":"1749605216","name":"root","password":{"expiration_date":-1,"hash_algorithm":"y","inactive_days":-1,"last_change":1745971200.0,"max_days_between_changes":99999,"min_days_between_changes":0,"status":"active","warning_days_before_expiration":7},"roles":["sudo"],"shell":"/bin/bash","type":null,"uid_signed":0,"uuid":null}})"
};
static const auto expectedPersistService
{
    R"({"checksum":{"hash":{"sha1":"daa615e783788aec35ae17eeed912ace3910f209"}},"error":{"log":{"file":{"path":null}}},"file":{"path":"sourcePath"},"log":{"file":{"path":null}},"process":{"args":null,"executable":"/usr/bin/wazuh-agent","group":{"name":null},"pid":1234,"root_directory":null,"user":{"name":null},"working_directory":null},"service":{"address":"/lib/systemd/system/wazuh-agent.service","description":"Monitors system activity","enabled":"enabled","exit_code":0,"following":"following","frequency":null,"id":"wazuh-agent","inetd_compatibility":null,"name":"Wazuh Agent","object_path":"objectPath","restart":null,"start_type":"auto","starts":{"on_mount":null,"on_not_empty_directory":null,"on_path_modified":null},"state":"running","sub_state":"subState","target":{"address":"jobPath","ephemeral_id":0,"type":"jobType"},"type":"type","win32_exit_code":0}})"
};
static const auto expectedPersistBrowserExtension
{
    R"({"browser":{"name":"chrome","profile":{"name":"Default","path":"C:\\Users\\john.doe\\AppData\\Local\\Google\\Chrome\\User Data\\Default","referenced":true}},"checksum":{"hash":{"sha1":"e3a871756b2489415d8e6b985bf8ca7c8a43ede2"}},"file":{"hash":{"sha256":"a1b2c3d4e5f6789012345678901234567890abcdef123456789012345678901234"}},"package":{"autoupdate":true,"build_version":null,"description":"Finally, an efficient wide-spectrum content blocker. Easy on CPU and memory.","enabled":true,"from_webstore":true,"id":"cjpalhdlnbpafiamejdnhcphjbkeiagm","installed":1710489821000,"name":"uBlock Origin","path":"C:\\Users\\john.doe\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\cjpalhdlnbpafiamejdnhcphjbkeiagm\\1.52.2_0","permissions":["[\\\"activeTab\\\"","\\\"storage\\\"","\\\"tabs\\\"","\\\"webNavigation\\\"]"],"persistent":false,"reference":"https://clients2.google.com/service/update2/crx","type":"extension","vendor":"Raymond Hill","version":"1.52.2","visible":false},"user":{"id":"S-1-5-21-1234567890-987654321-1122334455-1001"}})"
};

TEST_F(SyscollectorImpTest, defaultCtor)
{
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
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

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta.contains("data") && delta["data"].contains("event") && delta["data"]["event"].contains("created"))
            {
                delta["data"]["event"].erase("created");
            }

            wrapperDelta.callbackMock(delta.dump());
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            auto persist = nlohmann::json::parse(data);

            // Validate that state object exists and contains document_version
            if (persist.contains("state"))
            {
                EXPECT_TRUE(persist["state"].contains("document_version"));
                EXPECT_TRUE(persist["state"].contains("modified_at"));
                // Validate document_version is a positive integer
                EXPECT_TRUE(persist["state"]["document_version"].is_number_integer());
                EXPECT_GT(persist["state"]["document_version"].get<int>(), 0);
                // Remove state before comparing with expected values (since modified_at is dynamic)
                persist.erase("state");
            }

            wrapperPersist.callbackMock(id, operation, index, persist.dump(), version);
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

    // All modules enabled in this test
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHW, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistOS, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetIface, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistProcess, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPackage, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHotfix, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistGroup, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistUser, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistService, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistBrowserExtension, testing::_)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          5, true, true, true, true, true, true, true, true, true, true, true, true, true, true);

            Syscollector::instance().start();
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
#ifdef WIN32
    GTEST_SKIP() << "Skipping intervalSeconds test on Windows due to sync protocol issues in Wine environment";
#endif
    const auto spInfoWrapper {std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_NETWORKS_JSON)));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_PORTS_JSON)));
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix":"KB12345678"},{"hotfix":"KB87654321"}])"_json));
    EXPECT_CALL(*spInfoWrapper, processes(_)).Times(::testing::AtLeast(2)).WillRepeatedly(testing::InvokeArgument<0>(nlohmann::json::parse(EXPECT_CALL_PROCESSES_JSON)));

    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(2))
    .WillRepeatedly(::testing::InvokeArgument<0>
                    (R"({"name":"TEXT", "version_":"TEXT", "vendor":"TEXT", "installed":"TEXT", "path":"TEXT", "architecture":"TEXT", "category":"TEXT", "description":"TEXT", "size":"TEXT", "priority":"TEXT", "multiarch":"TEXT", "source":"TEXT", "os_patch":"TEXT"})"_json));

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
                                          persistFunction,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          1, true, true, true, true, true, true, true, true, true, true, true, true, true, true);

            Syscollector::instance().start();
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
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
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
                                          persistFunction,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, false);

            Syscollector::instance().start();
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
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
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

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta.contains("data") && delta["data"].contains("event") && delta["data"]["event"].contains("created"))
            {
                delta["data"]["event"].erase("created");
            }

            wrapperDelta.callbackMock(delta.dump());
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            auto persist = nlohmann::json::parse(data);

            // Validate that state object exists and contains document_version
            if (persist.contains("state"))
            {
                EXPECT_TRUE(persist["state"].contains("document_version"));
                EXPECT_TRUE(persist["state"].contains("modified_at"));
                // Validate document_version is a positive integer
                EXPECT_TRUE(persist["state"]["document_version"].is_number_integer());
                EXPECT_GT(persist["state"]["document_version"].get<int>(), 0);
                // Remove state before comparing with expected values (since modified_at is dynamic)
                persist.erase("state");
            }

            wrapperPersist.callbackMock(id, operation, index, persist.dump(), version);
        }
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

    // All modules except Hardware (disabled in this test)
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistOS, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetIface, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistProcess, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPackage, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHotfix, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistGroup, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistUser, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistService, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistBrowserExtension, testing::_)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, false, true, true, true, true, true, true, true, true, true, true, true, true);

            Syscollector::instance().start();
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
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
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

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta.contains("data") && delta["data"].contains("event") && delta["data"]["event"].contains("created"))
            {
                delta["data"]["event"].erase("created");
            }

            wrapperDelta.callbackMock(delta.dump());
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            auto persist = nlohmann::json::parse(data);

            // Validate that state object exists and contains document_version
            if (persist.contains("state"))
            {
                EXPECT_TRUE(persist["state"].contains("document_version"));
                EXPECT_TRUE(persist["state"].contains("modified_at"));
                // Validate document_version is a positive integer
                EXPECT_TRUE(persist["state"]["document_version"].is_number_integer());
                EXPECT_GT(persist["state"]["document_version"].get<int>(), 0);
                // Remove state before comparing with expected values (since modified_at is dynamic)
                persist.erase("state");
            }

            wrapperPersist.callbackMock(id, operation, index, persist.dump(), version);
        }
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

    // All modules except OS (disabled in this test)
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHW, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetIface, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistProcess, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPackage, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHotfix, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistGroup, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistUser, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistService, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistBrowserExtension, testing::_)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, false, true, true, true, true, true, true, true, true, true, true, true);

            Syscollector::instance().start();
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
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
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

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta.contains("data") && delta["data"].contains("event") && delta["data"]["event"].contains("created"))
            {
                delta["data"]["event"].erase("created");
            }

            wrapperDelta.callbackMock(delta.dump());
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            auto persist = nlohmann::json::parse(data);

            // Validate that state object exists and contains document_version
            if (persist.contains("state"))
            {
                EXPECT_TRUE(persist["state"].contains("document_version"));
                EXPECT_TRUE(persist["state"].contains("modified_at"));
                // Validate document_version is a positive integer
                EXPECT_TRUE(persist["state"]["document_version"].is_number_integer());
                EXPECT_GT(persist["state"]["document_version"].get<int>(), 0);
                // Remove state before comparing with expected values (since modified_at is dynamic)
                persist.erase("state");
            }

            wrapperPersist.callbackMock(id, operation, index, persist.dump(), version);
        }
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

    // All modules except Network (disabled in this test)
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHW, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistOS, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistProcess, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPackage, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHotfix, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistGroup, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistUser, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistService, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistBrowserExtension, testing::_)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, false, true, true, true, true, true, true, true, true, true, true);

            Syscollector::instance().start();
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
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
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

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta.contains("data") && delta["data"].contains("event") && delta["data"]["event"].contains("created"))
            {
                delta["data"]["event"].erase("created");
            }

            wrapperDelta.callbackMock(delta.dump());
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            auto persist = nlohmann::json::parse(data);

            // Validate that state object exists and contains document_version
            if (persist.contains("state"))
            {
                EXPECT_TRUE(persist["state"].contains("document_version"));
                EXPECT_TRUE(persist["state"].contains("modified_at"));
                // Validate document_version is a positive integer
                EXPECT_TRUE(persist["state"]["document_version"].is_number_integer());
                EXPECT_GT(persist["state"]["document_version"].get<int>(), 0);
                // Remove state before comparing with expected values (since modified_at is dynamic)
                persist.erase("state");
            }

            wrapperPersist.callbackMock(id, operation, index, persist.dump(), version);
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
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    // All modules except Packages (disabled in this test)
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHW, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistOS, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetIface, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistProcess, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHotfix, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistGroup, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistUser, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistService, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistBrowserExtension, testing::_)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, true, false, true, true, true, true, true, true, true, true, true);

            Syscollector::instance().start();
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
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
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

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta.contains("data") && delta["data"].contains("event") && delta["data"]["event"].contains("created"))
            {
                delta["data"]["event"].erase("created");
            }

            wrapperDelta.callbackMock(delta.dump());
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            auto persist = nlohmann::json::parse(data);

            // Validate that state object exists and contains document_version
            if (persist.contains("state"))
            {
                EXPECT_TRUE(persist["state"].contains("document_version"));
                EXPECT_TRUE(persist["state"].contains("modified_at"));
                // Validate document_version is a positive integer
                EXPECT_TRUE(persist["state"]["document_version"].is_number_integer());
                EXPECT_GT(persist["state"]["document_version"].get<int>(), 0);
                // Remove state before comparing with expected values (since modified_at is dynamic)
                persist.erase("state");
            }

            wrapperPersist.callbackMock(id, operation, index, persist.dump(), version);
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
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    // All modules except Ports (disabled in this test)
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHW, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistOS, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetIface, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistProcess, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPackage, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHotfix, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistGroup, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistUser, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistService, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistBrowserExtension, testing::_)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          5, true, true, true, true, true, false, true, true, true, true, true, true, true, true);

            Syscollector::instance().start();
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
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_NETWORKS_JSON)));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_PORTS_ALL_JSON)));

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

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta.contains("data") && delta["data"].contains("event") && delta["data"]["event"].contains("created"))
            {
                delta["data"]["event"].erase("created");
            }

            wrapperDelta.callbackMock(delta.dump());
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            auto persist = nlohmann::json::parse(data);

            // Validate that state object exists and contains document_version
            if (persist.contains("state"))
            {
                EXPECT_TRUE(persist["state"].contains("document_version"));
                EXPECT_TRUE(persist["state"].contains("modified_at"));
                // Validate document_version is a positive integer
                EXPECT_TRUE(persist["state"]["document_version"].is_number_integer());
                EXPECT_GT(persist["state"]["document_version"].get<int>(), 0);
                // Remove state before comparing with expected values (since modified_at is dynamic)
                persist.erase("state");
            }

            wrapperPersist.callbackMock(id, operation, index, persist.dump(), version);
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
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_ports_udp)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    // All modules except PortsAll
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHW, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistOS, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetIface, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPortsUdp, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistProcess, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPackage, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHotfix, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistGroup, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistUser, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistService, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistBrowserExtension, testing::_)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, true, true, true, false, true, true, true, true, true, true, true);

            Syscollector::instance().start();
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
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
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

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta.contains("data") && delta["data"].contains("event") && delta["data"]["event"].contains("created"))
            {
                delta["data"]["event"].erase("created");
            }

            wrapperDelta.callbackMock(delta.dump());
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            auto persist = nlohmann::json::parse(data);

            // Validate that state object exists and contains document_version
            if (persist.contains("state"))
            {
                EXPECT_TRUE(persist["state"].contains("document_version"));
                EXPECT_TRUE(persist["state"].contains("modified_at"));
                // Validate document_version is a positive integer
                EXPECT_TRUE(persist["state"]["document_version"].is_number_integer());
                EXPECT_GT(persist["state"]["document_version"].get<int>(), 0);
                // Remove state before comparing with expected values (since modified_at is dynamic)
                persist.erase("state");
            }

            wrapperPersist.callbackMock(id, operation, index, persist.dump(), version);
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
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_hotfixes)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    // All modules except Processes (disabled in this test)
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHW, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistOS, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetIface, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPackage, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHotfix, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistGroup, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistUser, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistService, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistBrowserExtension, testing::_)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, true, true, true, true, false, true, true, true, true, true, true);

            Syscollector::instance().start();
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
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
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

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta.contains("data") && delta["data"].contains("event") && delta["data"]["event"].contains("created"))
            {
                delta["data"]["event"].erase("created");
            }

            wrapperDelta.callbackMock(delta.dump());
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            auto persist = nlohmann::json::parse(data);

            // Validate that state object exists and contains document_version
            if (persist.contains("state"))
            {
                EXPECT_TRUE(persist["state"].contains("document_version"));
                EXPECT_TRUE(persist["state"].contains("modified_at"));
                // Validate document_version is a positive integer
                EXPECT_TRUE(persist["state"]["document_version"].is_number_integer());
                EXPECT_GT(persist["state"]["document_version"].get<int>(), 0);
                // Remove state before comparing with expected values (since modified_at is dynamic)
                persist.erase("state");
            }

            wrapperPersist.callbackMock(id, operation, index, persist.dump(), version);
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
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_users)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    // All modules except Hotfixes (disabled in this test)
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHW, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistOS, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetIface, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistProcess, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPackage, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistGroup, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistUser, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistService, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistBrowserExtension, testing::_)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, true, true, true, true, true, false, true, true, true, true, true);

            Syscollector::instance().start();
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
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
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

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta.contains("data") && delta["data"].contains("event") && delta["data"]["event"].contains("created"))
            {
                delta["data"]["event"].erase("created");
            }

            wrapperDelta.callbackMock(delta.dump());
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            auto persist = nlohmann::json::parse(data);

            // Validate that state object exists and contains document_version
            if (persist.contains("state"))
            {
                EXPECT_TRUE(persist["state"].contains("document_version"));
                EXPECT_TRUE(persist["state"].contains("modified_at"));
                // Validate document_version is a positive integer
                EXPECT_TRUE(persist["state"]["document_version"].is_number_integer());
                EXPECT_GT(persist["state"]["document_version"].get<int>(), 0);
                // Remove state before comparing with expected values (since modified_at is dynamic)
                persist.erase("state");
            }

            wrapperPersist.callbackMock(id, operation, index, persist.dump(), version);
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
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_groups)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    // All modules except Users (disabled in this test)
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHW, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistOS, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetIface, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistProcess, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPackage, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHotfix, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistGroup, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistService, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistBrowserExtension, testing::_)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, true, true, true, true, true, true, true, false, true, true, true);

            Syscollector::instance().start();
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
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
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

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta.contains("data") && delta["data"].contains("event") && delta["data"]["event"].contains("created"))
            {
                delta["data"]["event"].erase("created");
            }

            wrapperDelta.callbackMock(delta.dump());
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            auto persist = nlohmann::json::parse(data);

            // Validate that state object exists and contains document_version
            if (persist.contains("state"))
            {
                EXPECT_TRUE(persist["state"].contains("document_version"));
                EXPECT_TRUE(persist["state"].contains("modified_at"));
                // Validate document_version is a positive integer
                EXPECT_TRUE(persist["state"]["document_version"].is_number_integer());
                EXPECT_GT(persist["state"]["document_version"].get<int>(), 0);
                // Remove state before comparing with expected values (since modified_at is dynamic)
                persist.erase("state");
            }

            wrapperPersist.callbackMock(id, operation, index, persist.dump(), version);
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
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_services)).Times(1);
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    // All modules except Groups (disabled in this test)
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHW, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistOS, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetIface, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistProcess, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPackage, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHotfix, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistUser, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistService, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistBrowserExtension, testing::_)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, true, true, true, true, true, true, false, true, true, true, true);

            Syscollector::instance().start();
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
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
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

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta.contains("data") && delta["data"].contains("event") && delta["data"]["event"].contains("created"))
            {
                delta["data"]["event"].erase("created");
            }

            wrapperDelta.callbackMock(delta.dump());
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            auto persist = nlohmann::json::parse(data);

            // Validate that state object exists and contains document_version
            if (persist.contains("state"))
            {
                EXPECT_TRUE(persist["state"].contains("document_version"));
                EXPECT_TRUE(persist["state"].contains("modified_at"));
                // Validate document_version is a positive integer
                EXPECT_TRUE(persist["state"]["document_version"].is_number_integer());
                EXPECT_GT(persist["state"]["document_version"].get<int>(), 0);
                // Remove state before comparing with expected values (since modified_at is dynamic)
                persist.erase("state");
            }

            wrapperPersist.callbackMock(id, operation, index, persist.dump(), version);
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
    EXPECT_CALL(wrapperDelta, callbackMock(expected_dbsync_browser_extensions)).Times(1);

    // All modules except Services (disabled in this test)
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHW, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistOS, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetIface, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistProcess, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPackage, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHotfix, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistUser, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistGroup, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistBrowserExtension, testing::_)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, true, true, true, true, true, true, true, true, false, true, true);

            Syscollector::instance().start();
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
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
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

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta.contains("data") && delta["data"].contains("event") && delta["data"]["event"].contains("created"))
            {
                delta["data"]["event"].erase("created");
            }

            wrapperDelta.callbackMock(delta.dump());
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            auto persist = nlohmann::json::parse(data);

            // Validate that state object exists and contains document_version
            if (persist.contains("state"))
            {
                EXPECT_TRUE(persist["state"].contains("document_version"));
                EXPECT_TRUE(persist["state"].contains("modified_at"));
                // Validate document_version is a positive integer
                EXPECT_TRUE(persist["state"]["document_version"].is_number_integer());
                EXPECT_GT(persist["state"]["document_version"].get<int>(), 0);
                // Remove state before comparing with expected values (since modified_at is dynamic)
                persist.erase("state");
            }

            wrapperPersist.callbackMock(id, operation, index, persist.dump(), version);
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

    // All modules except Browser Extensions (disabled in this test)
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHW, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistOS, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetIface, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistProcess, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPackage, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHotfix, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistUser, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistGroup, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistService, testing::_)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, true, true, true, true, true, true, true, true, true, true, true, false, true);

            Syscollector::instance().start();
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(1));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, portAllEnable)
{
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
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

            if (delta.contains("data") && delta["data"].contains("event") && delta["data"]["event"].contains("created"))
            {
                delta["data"]["event"].erase("created");
            }

            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            auto persist = nlohmann::json::parse(data);

            // Validate that state object exists and contains document_version
            if (persist.contains("state"))
            {
                EXPECT_TRUE(persist["state"].contains("document_version"));
                EXPECT_TRUE(persist["state"].contains("modified_at"));
                // Validate document_version is a positive integer
                EXPECT_TRUE(persist["state"]["document_version"].is_number_integer());
                EXPECT_GT(persist["state"]["document_version"].get<int>(), 0);
                // Remove state before comparing with expected values (since modified_at is dynamic)
                persist.erase("state");
            }

            wrapperPersist.callbackMock(id, operation, index, persist.dump(), version);
        }
    };

    const auto expectedResult1
    {
        R"({"collector":"dbsync_ports","data":{"destination":{"ip":"0.0.0.0","port":0},"event":{"changed_fields":[],"type":"created"},"file":{"inode":43481},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp"},"process":{"name":null,"pid":0},"source":{"ip":"0.0.0.0","port":47748}},"module":"inventory"})"
    };

    const auto expectedResult2
    {
        R"({"collector":"dbsync_ports","data":{"destination":{"ip":"::","port":0},"event":{"changed_fields":[],"type":"created"},"file":{"inode":43482},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp6"},"process":{"name":null,"pid":0},"source":{"ip":"::","port":51087}},"module":"inventory"})"
    };

    const auto expectedResult3
    {
        R"({"collector":"dbsync_ports","data":{"destination":{"ip":"0.0.0.0","port":0},"event":{"changed_fields":[],"type":"created"},"file":{"inode":50324},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":"listening"},"network":{"transport":"tcp"},"process":{"name":null,"pid":0},"source":{"ip":"127.0.0.1","port":33060}},"module":"inventory"})"
    };

    const auto expectedResult4
    {
        R"({"collector":"dbsync_ports","data":{"destination":{"ip":"44.238.116.130","port":443},"event":{"changed_fields":[],"type":"created"},"file":{"inode":122575},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":"established"},"network":{"transport":"tcp"},"process":{"name":null,"pid":0},"source":{"ip":"192.168.0.104","port":39106}},"module":"inventory"})"
    };

    EXPECT_CALL(wrapper, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult3)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult4)).Times(1);

    const auto expectedPersistPorts1
    {
        R"({"checksum":{"hash":{"sha1":"88b40f1347d9ef9d381287b00c9e924e800a25f7"}},"destination":{"ip":"0.0.0.0","port":0},"file":{"inode":43481},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp"},"process":{"name":null,"pid":0},"source":{"ip":"0.0.0.0","port":47748}})"
    };

    const auto expectedPersistPorts2
    {
        R"({"checksum":{"hash":{"sha1":"62a2fc1c9277988df156c208c2a7897b1fb41236"}},"destination":{"ip":"::","port":0},"file":{"inode":43482},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp6"},"process":{"name":null,"pid":0},"source":{"ip":"::","port":51087}})"
    };

    const auto expectedPersistPorts3
    {
        R"({"checksum":{"hash":{"sha1":"e049eb5f4a3dbf71dc1e6bdd11a4d070459b36fe"}},"destination":{"ip":"0.0.0.0","port":0},"file":{"inode":50324},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":"listening"},"network":{"transport":"tcp"},"process":{"name":null,"pid":0},"source":{"ip":"127.0.0.1","port":33060}})"
    };

    const auto expectedPersistPorts4
    {
        R"({"checksum":{"hash":{"sha1":"1fcee2154ec4ad7e68c2627a731760dd72fb45ae"}},"destination":{"ip":"44.238.116.130","port":443},"file":{"inode":122575},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":"established"},"network":{"transport":"tcp"},"process":{"name":null,"pid":0},"source":{"ip":"192.168.0.104","port":39106}})"
    };

    // Only ports enabled in this test
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts1, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts2, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts3, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts4, testing::_)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData, &callbackDataPersist]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackData,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, false, false, false, false, true, true, false, false, false, false, false, false, true);

            Syscollector::instance().start();
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
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
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

            if (delta.contains("data") && delta["data"].contains("event") && delta["data"]["event"].contains("created"))
            {
                delta["data"]["event"].erase("created");
            }

            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            auto persist = nlohmann::json::parse(data);

            // Validate that state object exists and contains document_version
            if (persist.contains("state"))
            {
                EXPECT_TRUE(persist["state"].contains("document_version"));
                EXPECT_TRUE(persist["state"].contains("modified_at"));
                // Validate document_version is a positive integer
                EXPECT_TRUE(persist["state"]["document_version"].is_number_integer());
                EXPECT_GT(persist["state"]["document_version"].get<int>(), 0);
                // Remove state before comparing with expected values (since modified_at is dynamic)
                persist.erase("state");
            }

            wrapperPersist.callbackMock(id, operation, index, persist.dump(), version);
        }
    };

    const auto expectedResult1
    {
        R"({"collector":"dbsync_ports","data":{"destination":{"ip":"0.0.0.0","port":0},"event":{"changed_fields":[],"type":"created"},"file":{"inode":43481},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp"},"process":{"name":null,"pid":0},"source":{"ip":"0.0.0.0","port":47748}},"module":"inventory"})"
    };

    const auto expectedResult2
    {
        R"({"collector":"dbsync_ports","data":{"destination":{"ip":"::","port":0},"event":{"changed_fields":[],"type":"created"},"file":{"inode":43482},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp6"},"process":{"name":null,"pid":0},"source":{"ip":"::","port":51087}},"module":"inventory"})"
    };

    const auto expectedResult3
    {
        R"({"collector":"dbsync_ports","data":{"destination":{"ip":"0.0.0.0","port":0},"event":{"changed_fields":[],"type":"created"},"file":{"inode":50324},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":"listening"},"network":{"transport":"tcp"},"process":{"name":null,"pid":0},"source":{"ip":"127.0.0.1","port":33060}},"module":"inventory"})"
    };

    EXPECT_CALL(wrapper, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult3)).Times(1);

    const auto expectedPersistPorts1
    {
        R"({"checksum":{"hash":{"sha1":"88b40f1347d9ef9d381287b00c9e924e800a25f7"}},"destination":{"ip":"0.0.0.0","port":0},"file":{"inode":43481},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp"},"process":{"name":null,"pid":0},"source":{"ip":"0.0.0.0","port":47748}})"
    };

    const auto expectedPersistPorts2
    {
        R"({"checksum":{"hash":{"sha1":"62a2fc1c9277988df156c208c2a7897b1fb41236"}},"destination":{"ip":"::","port":0},"file":{"inode":43482},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp6"},"process":{"name":null,"pid":0},"source":{"ip":"::","port":51087}})"
    };

    const auto expectedPersistPorts3
    {
        R"({"checksum":{"hash":{"sha1":"e049eb5f4a3dbf71dc1e6bdd11a4d070459b36fe"}},"destination":{"ip":"0.0.0.0","port":0},"file":{"inode":50324},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":"listening"},"network":{"transport":"tcp"},"process":{"name":null,"pid":0},"source":{"ip":"127.0.0.1","port":33060}})"
    };

    // Only ports enabled in this test
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts1, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts2, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts3, testing::_)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData, &callbackDataPersist]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackData,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, false, false, false, false, true, false, false, false, false, false, false, false, true);

            Syscollector::instance().start();
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
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};

    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::DoAll(
                  ::testing::InvokeArgument<0>
                  (R"({"architecture":"amd64", "category":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version_":"1:7.7+19ubuntu14","type":"deb","path":" "})"_json),
                  ::testing::InvokeArgument<0>
                  (R"({"architecture":"amd64", "category":"x11","name":"xserver-xorg","priority":"optional","size":4111222333,"source":"xorg","version_":"1:7.7+19ubuntu14","type":"deb","path":" "})"_json)));

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackData
    {
        [&wrapper](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta.contains("data") && delta["data"].contains("event") && delta["data"]["event"].contains("created"))
            {
                delta["data"]["event"].erase("created");
            }

            wrapper.callbackMock(delta.dump());
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            auto persist = nlohmann::json::parse(data);

            // Validate that state object exists and contains document_version
            if (persist.contains("state"))
            {
                EXPECT_TRUE(persist["state"].contains("document_version"));
                EXPECT_TRUE(persist["state"].contains("modified_at"));
                // Validate document_version is a positive integer
                EXPECT_TRUE(persist["state"]["document_version"].is_number_integer());
                EXPECT_GT(persist["state"]["document_version"].get<int>(), 0);
                // Remove state before comparing with expected values (since modified_at is dynamic)
                persist.erase("state");
            }

            wrapperPersist.callbackMock(id, operation, index, persist.dump(), version);
        }
    };

    EXPECT_CALL(wrapper, callbackMock(expected_dbsync_packages)).Times(1);

    // Only packages enabled in this test
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPackage, testing::_)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackData, &callbackDataPersist]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackData,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, true, false, false, false, true, false, false, false, false, false, false, false, false, true);

            Syscollector::instance().start();
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
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"serial_number":" Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":" Intel(R) Core(TM) i5-9400 CPU @ 2.90GHz ", "memory_free":2257872,"memory_total":4972208,"memory_used":54})")));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                R"({"architecture":" x86_64", "hostname":" UBUNTU ","os_build":"  7601","os_major":"6  ","os_minor":"  1  ","os_name":" Microsoft Windows 7 ","os_distribution_release":"   sp1","os_version":"6.1.7601   ","os_type":" windows "})")));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                      R"({"iface":[{"network_ip":"127.0.0.1", "host_mac":"d4:5d:64:51:07:5d", "network_gateway":"192.168.0.1|600","network_broadcast":"127.255.255.255", "interface_name":"enp4s0", "interface_alias":" ", "interface_type":"   ethernet", "interface_state":"up   ", "network_dhcp":0,"interface_mtu":1500,"host_network_ingress_bytes":0,"host_network_ingress_drops":0,"host_network_ingress_errors":0,"host_network_ingress_packages":0,"host_network_egress_bytes":0,"host_network_egress_drops":0,"host_network_egress_errors":0,"host_network_egress_packages":0, "IPv4":[{"network_ip":"192.168.153.1","network_broadcast":"192.168.153.255","network_dhcp":0,"network_metric":" ","network_netmask":"255.255.255.0"}], "IPv6":[{"network_ip":"fe80::250:56ff:fec0:8","network_dhcp":0,"network_metric":" ","network_netmask":"ffff:ffff:ffff:ffff::"}]}]})")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(
                                                                   R"([{"file_inode":0,"source_ip":" 127.0.0.1 ", "source_port":631,"process_pid":0,"process_name":"System Idle Process","network_transport":"tcp   ","destination_ip":"   0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])")));
    EXPECT_CALL(*spInfoWrapper, packages(_))
    .Times(::testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"architecture":" amd64", "category":"  x11  ","name":" xserver-xorg","priority":"optional ","size":4111222333,"source":"xorg","version_":"1:7.7+19ubuntu14","type":"deb","path":" "})"_json));

    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(R"([{"hotfix_name":" KB12345678 "}])"_json));

    EXPECT_CALL(*spInfoWrapper, processes(_))
    .Times(testing::AtLeast(1))
    .WillOnce(::testing::InvokeArgument<0>
              (R"({"name":" kworker/u256:2-  ","pid":"  431625  ","parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"_json));

    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(
                                                             R"([{"group_description": null, "group_id": 1, "group_id_signed": 1, "group_is_hidden": 0, "group_name": "daemon", "group_users": "daemon:pollinate:vboxadd", "group_uuid": null }])"_json));

    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return
                                                        (R"([{"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":0,"user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null}])"_json));

    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_SERVICES_JSON)));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_BROWSER_EXTENSIONS_JSON)));

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            auto delta = nlohmann::json::parse(data);

            if (delta.contains("data") && delta["data"].contains("event") && delta["data"]["event"].contains("created"))
            {
                delta["data"]["event"].erase("created");
            }

            wrapperDelta.callbackMock(delta.dump());
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            auto persist = nlohmann::json::parse(data);

            // Validate that state object exists and contains document_version
            if (persist.contains("state"))
            {
                EXPECT_TRUE(persist["state"].contains("document_version"));
                EXPECT_TRUE(persist["state"].contains("modified_at"));
                // Validate document_version is a positive integer
                EXPECT_TRUE(persist["state"]["document_version"].is_number_integer());
                EXPECT_GT(persist["state"]["document_version"].get<int>(), 0);
                // Remove state before comparing with expected values (since modified_at is dynamic)
                persist.erase("state");
            }

            wrapperPersist.callbackMock(id, operation, index, persist.dump(), version);
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

    // All modules enabled in this test
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHW, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistOS, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetIface, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv4, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetProtoIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistNetAddrIPv6, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPorts, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistProcess, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistPackage, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistHotfix, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistGroup, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistUser, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistService, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::_, expectedPersistBrowserExtension, testing::_)).Times(1);

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          5, true, true, true, true, true, true, true, true, true, true, true, true, true, true);

            Syscollector::instance().start();
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(1));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}
