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
#include <sqlite3.h>

#include "syscollectorImp_test.h"
#include "syscollector.hpp"
#include "module_query_errors.h"
#include "syscollectorTablesDef.hpp"
#include "schemaValidator.hpp"

#include <mock_sysinfo.hpp>

constexpr auto SYSCOLLECTOR_DB_PATH {":memory:"};
constexpr auto SYSCOLLECTOR_TEST_DB_PATH {"syscollector_test.db"};

// Mock SchemaValidatorEngine for dependency injection in tests
class MockSchemaValidatorEngine : public SchemaValidator::ISchemaValidatorEngine
{
    public:
        MOCK_METHOD(SchemaValidator::ValidationResult, validate, (const std::string&), (override));
        MOCK_METHOD(SchemaValidator::ValidationResult, validate, (const nlohmann::json&), (override));
        MOCK_METHOD(std::string, getSchemaName, (), (const, override));
};

// Helper to populate test DB manually
void populateTestDb()
{
    std::string sql;
    sql += OS_SQL_STATEMENT;
    sql += HW_SQL_STATEMENT;
    sql += PACKAGES_SQL_STATEMENT;
    sql += HOTFIXES_SQL_STATEMENT;
    sql += PROCESSES_SQL_STATEMENT;
    sql += PORTS_SQL_STATEMENT;
    sql += NETIFACE_SQL_STATEMENT;
    sql += NETPROTO_SQL_STATEMENT;
    sql += NETADDR_SQL_STATEMENT;
    sql += USERS_SQL_STATEMENT;
    sql += GROUPS_SQL_STATEMENT;
    sql += SERVICES_SQL_STATEMENT;
    sql += BROWSER_EXTENSIONS_SQL_STATEMENT;
    sql += TABLE_METADATA_SQL_STATEMENT;

    // Use DBSync to create the database structure correctly (including metadata tables)
    {
        auto callbackErrorLogWrapper = [](const std::string& /*data*/) {};
        // Ensure DBSync is initialized with our dummy logger
        DBSync::initialize(callbackErrorLogWrapper);
        DBSync dbSync(HostType::AGENT, DbEngineType::SQLITE3, SYSCOLLECTOR_TEST_DB_PATH, sql, DbManagement::PERSISTENT);
    }

    sqlite3* db = nullptr;
    // Open existing DB created by DBSync
    int rc = sqlite3_open_v2(SYSCOLLECTOR_TEST_DB_PATH, &db, SQLITE_OPEN_READWRITE, nullptr);

    if (rc != SQLITE_OK)
    {
        if (db) sqlite3_close(db);

        throw std::runtime_error("Failed to open test DB");
    }

    // Insert dummy data to trigger "disabled collector with data" detection
    const char* inserts[] =
    {
        "INSERT INTO dbsync_packages (name, version_, architecture, type, path, checksum) VALUES ('pkg1', '1.0', 'arch', 'type', 'path', 'sum');",
        "INSERT INTO dbsync_processes (pid, name, checksum) VALUES ('123', 'proc1', 'sum');",
        "INSERT INTO dbsync_hwinfo (serial_number, checksum) VALUES ('sn1', 'sum');",
        "INSERT INTO dbsync_osinfo (os_name, os_version, checksum) VALUES ('os1', 'version1', 'sum');",
        "INSERT INTO dbsync_ports (file_inode, network_transport, source_ip, source_port, checksum) VALUES (1, 'tcp', '127.0.0.1', 80, 'sum');",
        "INSERT INTO dbsync_network_iface (interface_name, interface_alias, interface_type, checksum) VALUES ('eth0', 'alias', 'ethernet', 'sum');",
        "INSERT INTO dbsync_network_protocol (interface_name, network_type, checksum) VALUES ('eth0', 'ipv4', 'sum');",
        "INSERT INTO dbsync_network_address (interface_name, network_type, network_ip, checksum) VALUES ('eth0', 0, '1.1.1.1', 'sum');"
    };

    char* errMsg = 0;

    for (const auto& insertSql : inserts)
    {
        rc = sqlite3_exec(db, insertSql, 0, 0, &errMsg);

        if (rc != SQLITE_OK)
        {
            std::string msg = errMsg;
            sqlite3_free(errMsg);
            sqlite3_close(db);
            throw std::runtime_error("Failed to insert data: " + msg);
        }
    }

    // Ensure all data is flushed to disk (important for WAL mode)
    sqlite3_exec(db, "PRAGMA wal_checkpoint(FULL);", 0, 0, 0);

    sqlite3_close(db);
}

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
    R"({"collector":"dbsync_network_address","data":{"event":{"changed_fields":[],"type":"created"},"interface":{"name":"enp4s0"},"network":{"broadcast":null,"ip":"fe80::250:56ff:fec0:8","netmask":"ffff:ffff:ffff:ffff::","type":"1"}},"module":"inventory"})"
};
const auto expected_dbsync_network_address_2
{
    R"({"collector":"dbsync_network_address","data":{"event":{"changed_fields":[],"type":"created"},"interface":{"name":"enp4s0"},"network":{"broadcast":"192.168.153.255","ip":"192.168.153.1","netmask":"255.255.255.0","type":"0"}},"module":"inventory"})"
};
const auto expected_dbsync_ports
{
    R"({"collector":"dbsync_ports","data":{"destination":{"ip":"0.0.0.0","port":0},"event":{"changed_fields":[],"type":"created"},"file":{"inode":"0"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":"listening"},"network":{"transport":"tcp"},"process":{"name":"System Idle Process","pid":0},"source":{"ip":"127.0.0.1","port":631}},"module":"inventory"})"
};
const auto expected_dbsync_ports_udp
{
    R"({"collector":"dbsync_ports","data":{"destination":{"ip":"0.0.0.0","port":0},"event":{"changed_fields":[],"type":"created"},"file":{"inode":"0"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp"},"process":{"name":"System Idle Process","pid":0},"source":{"ip":"127.0.0.1","port":631}},"module":"inventory"})"
};
const auto expected_dbsync_processes
{
    R"({"collector":"dbsync_processes","data":{"event":{"changed_fields":[],"type":"created"},"process":{"args":null,"args_count":null,"command_line":null,"name":"kworker/u256:2-","parent":{"pid":2},"pid":431625,"start":9302261,"state":"I","stime":3,"utime":0}},"module":"inventory"})"
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
    R"({"collector":"dbsync_users","data":{"event":{"changed_fields":[],"type":"created"},"host":{"ip":["192.168.0.84"]},"login":{"status":false,"tty":"pts/0","type":"user"},"process":{"pid":"129870"},"user":{"auth_failures":{"count":0,"timestamp":0},"created":0,"full_name":"root","group":{"id":0,"id_signed":0},"groups":[0],"home":"/root","id":"0","is_hidden":false,"is_remote":true,"last_login":"1749605216","name":"root","password":{"expiration_date":-1,"hash_algorithm":"y","inactive_days":-1,"last_change":1745971200.0,"max_days_between_changes":99999,"min_days_between_changes":0,"status":"active","warning_days_before_expiration":7},"roles":["sudo"],"shell":"/bin/bash","type":null,"uid_signed":0,"uuid":null}},"module":"inventory"})"
};
const auto expected_dbsync_services
{
    R"({"collector":"dbsync_services","data":{"error":{"log":{"file":{"path":null}}},"event":{"changed_fields":[],"type":"created"},"file":{"path":"sourcePath"},"log":{"file":{"path":null}},"process":{"args":null,"executable":"/usr/bin/wazuh-agent","group":{"name":null},"pid":1234,"root_directory":null,"user":{"name":null},"working_directory":null},"service":{"address":"/lib/systemd/system/wazuh-agent.service","description":"Monitors system activity","enabled":"enabled","exit_code":0,"following":"following","frequency":null,"id":"wazuh-agent","inetd_compatibility":null,"name":"Wazuh Agent","object_path":"objectPath","restart":null,"start_type":"auto","starts":{"on_mount":null,"on_not_empty_directory":null,"on_path_modified":null},"state":"running","sub_state":"subState","target":{"address":"jobPath","ephemeral_id":"0","type":"jobType"},"type":"type","win32_exit_code":0}},"module":"inventory"})"
};
const auto expected_dbsync_browser_extensions
{
    R"({"collector":"dbsync_browser_extensions","data":{"browser":{"name":"chrome","profile":{"name":"Default","path":"C:\\Users\\john.doe\\AppData\\Local\\Google\\Chrome\\User Data\\Default","referenced":true}},"event":{"changed_fields":[],"type":"created"},"file":{"hash":{"sha256":"a1b2c3d4e5f6789012345678901234567890abcdef123456789012345678901234"}},"package":{"autoupdate":true,"build_version":null,"description":"Finally, an efficient wide-spectrum content blocker. Easy on CPU and memory.","enabled":true,"from_webstore":true,"id":"cjpalhdlnbpafiamejdnhcphjbkeiagm","installed":1710489821000,"name":"uBlock Origin","path":"C:\\Users\\john.doe\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\cjpalhdlnbpafiamejdnhcphjbkeiagm\\1.52.2_0","permissions":["[\\\"activeTab\\\"","\\\"storage\\\"","\\\"tabs\\\"","\\\"webNavigation\\\"]"],"persistent":false,"reference":"https://clients2.google.com/service/update2/crx","type":"extension","vendor":"Raymond Hill","version":"1.52.2","visible":false},"user":{"id":"S-1-5-21-1234567890-987654321-1122334455-1001"}},"module":"inventory"})"
};

void SyscollectorImpTest::SetUp()
{
    std::remove(SYSCOLLECTOR_TEST_DB_PATH);

    // Initialize SchemaValidatorFactory with mocks to prevent issues in Wine/Windows tests
    // This ensures all tests use mock validators instead of loading real embedded schemas
    m_mockValidator = std::make_shared<MockSchemaValidatorEngine>();
    SchemaValidator::ValidationResult successResult;
    successResult.isValid = true;

    EXPECT_CALL(*m_mockValidator, validate(testing::An<const std::string&>()))
    .WillRepeatedly(testing::Return(successResult));
    EXPECT_CALL(*m_mockValidator, validate(testing::An<const nlohmann::json&>()))
    .WillRepeatedly(testing::Return(successResult));
    EXPECT_CALL(*m_mockValidator, getSchemaName())
    .WillRepeatedly(testing::Return("mock-validator"));

    // Inject mock validators for all indices
    std::map<std::string, std::shared_ptr<SchemaValidator::ISchemaValidatorEngine>> mockValidators;
    mockValidators["wazuh-states-inventory-hardware"] = m_mockValidator;
    mockValidators["wazuh-states-inventory-system"] = m_mockValidator;
    mockValidators["wazuh-states-inventory-interfaces"] = m_mockValidator;
    mockValidators["wazuh-states-inventory-networks"] = m_mockValidator;
    mockValidators["wazuh-states-inventory-ports"] = m_mockValidator;
    mockValidators["wazuh-states-inventory-packages"] = m_mockValidator;
    mockValidators["wazuh-states-inventory-processes"] = m_mockValidator;
    mockValidators["wazuh-states-inventory-hotfixes"] = m_mockValidator;
    mockValidators["wazuh-states-inventory-groups"] = m_mockValidator;
    mockValidators["wazuh-states-inventory-users"] = m_mockValidator;
    mockValidators["wazuh-states-inventory-services"] = m_mockValidator;
    mockValidators["wazuh-states-inventory-browser-extensions"] = m_mockValidator;

    SchemaValidator::SchemaValidatorFactory::getInstance().reset();
    SchemaValidator::SchemaValidatorFactory::getInstance().initialize(mockValidators);
};

void SyscollectorImpTest::TearDown()
{
    std::remove(SYSCOLLECTOR_TEST_DB_PATH);

    // Ensure Syscollector singleton is destroyed after each test
    // This prevents stale function pointer issues between tests
    Syscollector::instance().destroy();

    // Clean up SchemaValidatorFactory after each test
    SchemaValidator::SchemaValidatorFactory::getInstance().reset();
};

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

// Log capturing structure for testing
struct LogEntry
{
    modules_log_level_t level;
    std::string message;
};

class LogCapture
{
    public:
        std::vector<LogEntry> logs;

        void clear()
        {
            logs.clear();
        }

        void capture(modules_log_level_t level, const std::string& message)
        {
            logs.push_back({level, message});
        }

        bool contains(modules_log_level_t level, const std::string& substring) const
        {
            for (const auto& entry : logs)
            {
                if (entry.level == level && entry.message.find(substring) != std::string::npos)
                {
                    return true;
                }
            }

            return false;
        }

        size_t count(modules_log_level_t level) const
        {
            size_t cnt = 0;

            for (const auto& entry : logs)
            {
                if (entry.level == level)
                {
                    cnt++;
                }
            }

            return cnt;
        }
};

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
    R"({"checksum":{"hash":{"sha1":"24ecdd6a316b2320c809085106812f6cf8a4cf67"}},"interface":{"name":"enp4s0"},"network":{"broadcast":"192.168.153.255","ip":"192.168.153.1","netmask":"255.255.255.0","type":"0"}})"
};
static const auto expectedPersistNetProtoIPv6
{
    R"({"checksum":{"hash":{"sha1":"53a9aa90a75f0264beae6beb9bf19192cfc23df1"}},"interface":{"name":"enp4s0"},"network":{"dhcp":false,"gateway":"192.168.0.1|600","metric":null,"type":"ipv6"}})"
};
static const auto expectedPersistNetAddrIPv6
{
    R"({"checksum":{"hash":{"sha1":"7271714e0616caea85422916dd6ab2fbdac2b5cd"}},"interface":{"name":"enp4s0"},"network":{"broadcast":null,"ip":"fe80::250:56ff:fec0:8","netmask":"ffff:ffff:ffff:ffff::","type":"1"}})"
};
static const auto expectedPersistPorts
{
    R"({"checksum":{"hash":{"sha1":"7223807075622557e855677b47f23f321091353c"}},"destination":{"ip":"0.0.0.0","port":0},"file":{"inode":"0"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":"listening"},"network":{"transport":"tcp"},"process":{"name":"System Idle Process","pid":0},"source":{"ip":"127.0.0.1","port":631}})"
};
static const auto expectedPersistPortsUdp
{
    R"({"checksum":{"hash":{"sha1":"dff9e7c5127ea90f4e9c38840683330b8c1351c9"}},"destination":{"ip":"0.0.0.0","port":0},"file":{"inode":"0"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp"},"process":{"name":"System Idle Process","pid":0},"source":{"ip":"127.0.0.1","port":631}})"
};
static const auto expectedPersistProcess
{
    R"({"checksum":{"hash":{"sha1":"78e4e090e42f88d949428eb56836287f99de9f4f"}},"process":{"args":null,"args_count":null,"command_line":null,"name":"kworker/u256:2-","parent":{"pid":2},"pid":431625,"start":9302261,"state":"I","stime":3,"utime":0}})"
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
    R"({"checksum":{"hash":{"sha1":"11769088416d594d547a508e084cec990e282ece"}},"host":{"ip":["192.168.0.84"]},"login":{"status":false,"tty":"pts/0","type":"user"},"process":{"pid":"129870"},"user":{"auth_failures":{"count":0,"timestamp":0},"created":0,"full_name":"root","group":{"id":0,"id_signed":0},"groups":[0],"home":"/root","id":"0","is_hidden":false,"is_remote":true,"last_login":"1749605216","name":"root","password":{"expiration_date":-1,"hash_algorithm":"y","inactive_days":-1,"last_change":1745971200.0,"max_days_between_changes":99999,"min_days_between_changes":0,"status":"active","warning_days_before_expiration":7},"roles":["sudo"],"shell":"/bin/bash","type":null,"uid_signed":0,"uuid":null}})"
};
static const auto expectedPersistService
{
    R"({"checksum":{"hash":{"sha1":"daa615e783788aec35ae17eeed912ace3910f209"}},"error":{"log":{"file":{"path":null}}},"file":{"path":"sourcePath"},"log":{"file":{"path":null}},"process":{"args":null,"executable":"/usr/bin/wazuh-agent","group":{"name":null},"pid":1234,"root_directory":null,"user":{"name":null},"working_directory":null},"service":{"address":"/lib/systemd/system/wazuh-agent.service","description":"Monitors system activity","enabled":"enabled","exit_code":0,"following":"following","frequency":null,"id":"wazuh-agent","inetd_compatibility":null,"name":"Wazuh Agent","object_path":"objectPath","restart":null,"start_type":"auto","starts":{"on_mount":null,"on_not_empty_directory":null,"on_path_modified":null},"state":"running","sub_state":"subState","target":{"address":"jobPath","ephemeral_id":"0","type":"jobType"},"type":"type","win32_exit_code":0}})"
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

    // Note: Mock validators are automatically initialized in SetUp() to prevent Wine issues

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
        R"({"collector":"dbsync_ports","data":{"destination":{"ip":"0.0.0.0","port":0},"event":{"changed_fields":[],"type":"created"},"file":{"inode":"43481"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp"},"process":{"name":null,"pid":0},"source":{"ip":"0.0.0.0","port":47748}},"module":"inventory"})"
    };

    const auto expectedResult2
    {
        R"({"collector":"dbsync_ports","data":{"destination":{"ip":"::","port":0},"event":{"changed_fields":[],"type":"created"},"file":{"inode":"43482"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp6"},"process":{"name":null,"pid":0},"source":{"ip":"::","port":51087}},"module":"inventory"})"
    };

    const auto expectedResult3
    {
        R"({"collector":"dbsync_ports","data":{"destination":{"ip":"0.0.0.0","port":0},"event":{"changed_fields":[],"type":"created"},"file":{"inode":"50324"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":"listening"},"network":{"transport":"tcp"},"process":{"name":null,"pid":0},"source":{"ip":"127.0.0.1","port":33060}},"module":"inventory"})"
    };

    const auto expectedResult4
    {
        R"({"collector":"dbsync_ports","data":{"destination":{"ip":"44.238.116.130","port":443},"event":{"changed_fields":[],"type":"created"},"file":{"inode":"122575"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":"established"},"network":{"transport":"tcp"},"process":{"name":null,"pid":0},"source":{"ip":"192.168.0.104","port":39106}},"module":"inventory"})"
    };

    EXPECT_CALL(wrapper, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult3)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult4)).Times(1);

    const auto expectedPersistPorts1
    {
        R"({"checksum":{"hash":{"sha1":"88b40f1347d9ef9d381287b00c9e924e800a25f7"}},"destination":{"ip":"0.0.0.0","port":0},"file":{"inode":"43481"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp"},"process":{"name":null,"pid":0},"source":{"ip":"0.0.0.0","port":47748}})"
    };

    const auto expectedPersistPorts2
    {
        R"({"checksum":{"hash":{"sha1":"62a2fc1c9277988df156c208c2a7897b1fb41236"}},"destination":{"ip":"::","port":0},"file":{"inode":"43482"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp6"},"process":{"name":null,"pid":0},"source":{"ip":"::","port":51087}})"
    };

    const auto expectedPersistPorts3
    {
        R"({"checksum":{"hash":{"sha1":"e049eb5f4a3dbf71dc1e6bdd11a4d070459b36fe"}},"destination":{"ip":"0.0.0.0","port":0},"file":{"inode":"50324"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":"listening"},"network":{"transport":"tcp"},"process":{"name":null,"pid":0},"source":{"ip":"127.0.0.1","port":33060}})"
    };

    const auto expectedPersistPorts4
    {
        R"({"checksum":{"hash":{"sha1":"1fcee2154ec4ad7e68c2627a731760dd72fb45ae"}},"destination":{"ip":"44.238.116.130","port":443},"file":{"inode":"122575"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":"established"},"network":{"transport":"tcp"},"process":{"name":null,"pid":0},"source":{"ip":"192.168.0.104","port":39106}})"
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
        R"({"collector":"dbsync_ports","data":{"destination":{"ip":"0.0.0.0","port":0},"event":{"changed_fields":[],"type":"created"},"file":{"inode":"43481"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp"},"process":{"name":null,"pid":0},"source":{"ip":"0.0.0.0","port":47748}},"module":"inventory"})"
    };

    const auto expectedResult2
    {
        R"({"collector":"dbsync_ports","data":{"destination":{"ip":"::","port":0},"event":{"changed_fields":[],"type":"created"},"file":{"inode":"43482"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp6"},"process":{"name":null,"pid":0},"source":{"ip":"::","port":51087}},"module":"inventory"})"
    };

    const auto expectedResult3
    {
        R"({"collector":"dbsync_ports","data":{"destination":{"ip":"0.0.0.0","port":0},"event":{"changed_fields":[],"type":"created"},"file":{"inode":"50324"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":"listening"},"network":{"transport":"tcp"},"process":{"name":null,"pid":0},"source":{"ip":"127.0.0.1","port":33060}},"module":"inventory"})"
    };

    EXPECT_CALL(wrapper, callbackMock(expectedResult1)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult2)).Times(1);
    EXPECT_CALL(wrapper, callbackMock(expectedResult3)).Times(1);

    const auto expectedPersistPorts1
    {
        R"({"checksum":{"hash":{"sha1":"88b40f1347d9ef9d381287b00c9e924e800a25f7"}},"destination":{"ip":"0.0.0.0","port":0},"file":{"inode":"43481"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp"},"process":{"name":null,"pid":0},"source":{"ip":"0.0.0.0","port":47748}})"
    };

    const auto expectedPersistPorts2
    {
        R"({"checksum":{"hash":{"sha1":"62a2fc1c9277988df156c208c2a7897b1fb41236"}},"destination":{"ip":"::","port":0},"file":{"inode":"43482"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":null},"network":{"transport":"udp6"},"process":{"name":null,"pid":0},"source":{"ip":"::","port":51087}})"
    };

    const auto expectedPersistPorts3
    {
        R"({"checksum":{"hash":{"sha1":"e049eb5f4a3dbf71dc1e6bdd11a4d070459b36fe"}},"destination":{"ip":"0.0.0.0","port":0},"file":{"inode":"50324"},"host":{"network":{"egress":{"queue":0},"ingress":{"queue":0}}},"interface":{"state":"listening"},"network":{"transport":"tcp"},"process":{"name":null,"pid":0},"source":{"ip":"127.0.0.1","port":33060}})"
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
              (R"({"name":" kworker/u256:2-  ","pid":"431625","parent_pid":2,"start":9302261,"state":"I","stime":3,"utime":0})"_json));

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

// ========================================
// Tests for query method and coordination commands
// ========================================

TEST_F(SyscollectorImpTest, queryCommandPause)
{
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600, false, false, false, false, false, false, false, false, false, false, false, false, false, false);

    // Start the module in a thread
    std::thread t
    {
        []()
        {
            Syscollector::instance().start();
        }
    };

    // Give it time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Test pause command
    std::string queryJson = R"({"command":"pause"})";
    std::string response = Syscollector::instance().query(queryJson);

    // Parse response
    auto responseJson = nlohmann::json::parse(response);

    // Verify response structure
    EXPECT_TRUE(responseJson.contains("error"));
    EXPECT_TRUE(responseJson.contains("message"));
    EXPECT_TRUE(responseJson.contains("data"));

    // Verify success
    EXPECT_EQ(responseJson["error"], MQ_SUCCESS);
    EXPECT_EQ(responseJson["data"]["module"], "syscollector");
    EXPECT_EQ(responseJson["data"]["action"], "pause");

    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, queryCommandResume)
{
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600, false, false, false, false, false, false, false, false, false, false, false, false, false, false);

    // Start the module in a thread
    std::thread t
    {
        []()
        {
            Syscollector::instance().start();
        }
    };

    // Give it time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // First pause
    std::string pauseJson = R"({"command":"pause"})";
    Syscollector::instance().query(pauseJson);

    // Then test resume command
    std::string queryJson = R"({"command":"resume"})";
    std::string response = Syscollector::instance().query(queryJson);

    // Parse response
    auto responseJson = nlohmann::json::parse(response);

    // Verify response structure
    EXPECT_TRUE(responseJson.contains("error"));
    EXPECT_TRUE(responseJson.contains("message"));
    EXPECT_TRUE(responseJson.contains("data"));

    // Verify success
    EXPECT_EQ(responseJson["error"], MQ_SUCCESS);
    EXPECT_EQ(responseJson["data"]["module"], "syscollector");
    EXPECT_EQ(responseJson["data"]["action"], "resume");

    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, queryCommandFlushNoSyncProtocol)
{
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600, false, false, false, false, false, false, false, false, false, false, false, false, false, false);

    // Test flush command without sync protocol initialized
    std::string queryJson = R"({"command":"flush"})";
    std::string response = Syscollector::instance().query(queryJson);

    // Parse response
    auto responseJson = nlohmann::json::parse(response);

    // Verify response structure
    EXPECT_TRUE(responseJson.contains("error"));
    EXPECT_TRUE(responseJson.contains("message"));
    EXPECT_TRUE(responseJson.contains("data"));

    // Verify success (flush returns 0 even if sync protocol not initialized)
    EXPECT_EQ(responseJson["error"], MQ_SUCCESS);
    EXPECT_EQ(responseJson["data"]["module"], "syscollector");
    EXPECT_EQ(responseJson["data"]["action"], "flush");

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, queryCommandGetVersion)
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

    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600, true, true, true, true, true, true, true, true, true, true, true, true, true, false);

    std::thread t
    {
        [&spInfoWrapper]()
        {
            Syscollector::instance().start();
        }
    };

    // Wait for scan to complete
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Test get_version command
    std::string queryJson = R"({"command":"get_version"})";
    std::string response = Syscollector::instance().query(queryJson);

    auto responseJson = nlohmann::json::parse(response);

    // Verify response structure
    EXPECT_TRUE(responseJson.contains("error"));
    EXPECT_TRUE(responseJson.contains("message"));
    EXPECT_TRUE(responseJson.contains("data"));

    // Verify success
    EXPECT_EQ(responseJson["error"], MQ_SUCCESS);
    EXPECT_TRUE(responseJson["data"].contains("version"));
    // Version should be > 0 since we did a scan
    EXPECT_GT(responseJson["data"]["version"].get<int>(), 0);

    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, queryCommandSetVersion)
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

    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600, true, true, true, true, true, true, true, true, true, true, true, true, true, false);

    std::thread t
    {
        [&spInfoWrapper]()
        {
            Syscollector::instance().start();
        }
    };

    // Wait for scan to complete
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Test set_version command
    int newVersion = 42;
    std::string queryJson = R"({"command":"set_version","parameters":{"version":)" + std::to_string(newVersion) + R"(}})";
    std::string response = Syscollector::instance().query(queryJson);

    // Parse response
    auto responseJson = nlohmann::json::parse(response);

    // Verify response structure
    EXPECT_TRUE(responseJson.contains("error"));
    EXPECT_TRUE(responseJson.contains("message"));
    EXPECT_TRUE(responseJson.contains("data"));

    // Verify success
    EXPECT_EQ(responseJson["error"], MQ_SUCCESS);
    EXPECT_TRUE(responseJson["data"].contains("version"));
    EXPECT_EQ(responseJson["data"]["version"].get<int>(), newVersion);

    // Verify version was actually set
    std::string getVersionJson = R"({"command":"get_version"})";
    std::string getVersionResponse = Syscollector::instance().query(getVersionJson);
    auto getVersionResponseJson = nlohmann::json::parse(getVersionResponse);
    EXPECT_EQ(getVersionResponseJson["data"]["version"].get<int>(), newVersion);

    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }
}

TEST_F(SyscollectorImpTest, queryCommandUnknown)
{
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600, false, false, false, false, false, false, false, false, false, false, false, false, false, false);

    // Test unknown command
    std::string queryJson = R"({"command":"unknown_command"})";
    std::string response = Syscollector::instance().query(queryJson);

    // Parse response
    auto responseJson = nlohmann::json::parse(response);

    // Verify response structure
    EXPECT_TRUE(responseJson.contains("error"));
    EXPECT_TRUE(responseJson.contains("message"));
    EXPECT_TRUE(responseJson.contains("data"));

    // Verify error
    EXPECT_EQ(responseJson["error"], MQ_ERR_UNKNOWN_COMMAND);
    EXPECT_EQ(responseJson["data"]["command"], "unknown_command");

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, queryInvalidJson)
{
#ifdef WIN32
    GTEST_SKIP() << "Skipping queryInvalidJson test on Windows due to exception handling issues in Wine environment";
#endif
    const auto spInfoWrapper {std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600, false, false, false, false, false, false, false, false, false, false, false, false, false, false);

    // Test invalid JSON
    std::string queryJson = "invalid json";
    std::string response = Syscollector::instance().query(queryJson);

    // Parse response
    auto responseJson = nlohmann::json::parse(response);

    // Verify response structure
    EXPECT_TRUE(responseJson.contains("error"));
    EXPECT_TRUE(responseJson.contains("message"));

    // Verify error
    EXPECT_EQ(responseJson["error"], MQ_ERR_INTERNAL);

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, queryMissingCommand)
{
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600, false, false, false, false, false, false, false, false, false, false, false, false, false, false);

    // Test missing command field
    std::string queryJson = R"({"parameters":{"version":1}})";
    std::string response = Syscollector::instance().query(queryJson);

    // Parse response
    auto responseJson = nlohmann::json::parse(response);

    // Verify response structure
    EXPECT_TRUE(responseJson.contains("error"));
    EXPECT_TRUE(responseJson.contains("message"));

    // Verify error
    EXPECT_EQ(responseJson["error"], MQ_ERR_INVALID_PARAMS);

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, querySetVersionMissingParameter)
{
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600, false, false, false, false, false, false, false, false, false, false, false, false, false, false);

    // Test set_version without version parameter
    std::string queryJson = R"({"command":"set_version","parameters":{}})";
    std::string response = Syscollector::instance().query(queryJson);

    // Parse response
    auto responseJson = nlohmann::json::parse(response);

    // Verify response structure
    EXPECT_TRUE(responseJson.contains("error"));
    EXPECT_TRUE(responseJson.contains("message"));

    // Verify error
    EXPECT_EQ(responseJson["error"], MQ_ERR_INVALID_PARAMS);

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, querySetVersionInvalidParameterType)
{
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600, false, false, false, false, false, false, false, false, false, false, false, false, false, false);

    // Test set_version with invalid parameter type (string instead of number)
    std::string queryJson = R"({"command":"set_version","parameters":{"version":"not_a_number"}})";
    std::string response = Syscollector::instance().query(queryJson);

    // Parse response
    auto responseJson = nlohmann::json::parse(response);

    // Verify response structure
    EXPECT_TRUE(responseJson.contains("error"));
    EXPECT_TRUE(responseJson.contains("message"));

    // Verify error
    EXPECT_EQ(responseJson["error"], MQ_ERR_INVALID_PARAMS);

    Syscollector::instance().destroy();
}

// ========================================
// Tests for initSyncProtocol()
// ========================================

TEST_F(SyscollectorImpTest, initSyncProtocol_AllModulesEnabled)
{
    /**
     * Test: Verify initSyncProtocol initializes both sync protocols correctly
     * when all VD-relevant modules (packages, OS, hotfixes) are enabled
     */

    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    // Initialize with all VD-relevant modules enabled
    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600,
                                  false,   // scanOnStart
                                  false,   // hardware
                                  true,    // os (enabled)
                                  false,   // network
                                  true,    // packages (enabled)
                                  false,   // ports
                                  false,   // portsAll
                                  false,   // processes
#ifdef _WIN32
                                  true,    // hotfixes (enabled on Windows)
#else
                                  false,   // hotfixes (not available on Linux)
#endif
                                  false,   // groups
                                  false,   // users
                                  false,   // services
                                  false,   // browserExtensions
                                  false);  // notifyOnFirstScan

    // Mock MQ functions
    MQ_Functions mqFuncs;
    mqFuncs.start = [](const char*, short, short) -> int { return 0; };
    mqFuncs.send_binary = [](int, const void*, size_t, const char*, char) -> int { return 0; };

    // Test initSyncProtocol - should not throw
    EXPECT_NO_THROW(
    {
        Syscollector::instance().initSyncProtocol(
            "syscollector",
            ":memory:",
            ":memory:",
            mqFuncs,
            std::chrono::seconds(10),
            std::chrono::seconds(5),
            3,
            100,
            86400
        );
    });

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, initSyncProtocol_PackagesDisabled)
{
    /**
     * Test: Verify initSyncProtocol handles packages being disabled
     * VD sync should still be enabled if OS or hotfixes are enabled
     */

    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    // Initialize with packages disabled but OS enabled
    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600,
                                  false,   // scanOnStart
                                  false,   // hardware
                                  true,    // os (enabled)
                                  false,   // network
                                  false,   // packages (disabled)
                                  false,   // ports
                                  false,   // portsAll
                                  false,   // processes
                                  false,   // hotfixes (disabled)
                                  false,   // groups
                                  false,   // users
                                  false,   // services
                                  false,   // browserExtensions
                                  false);  // notifyOnFirstScan

    // Mock MQ functions
    MQ_Functions mqFuncs;
    mqFuncs.start = [](const char*, short, short) -> int { return 0; };
    mqFuncs.send_binary = [](int, const void*, size_t, const char*, char) -> int { return 0; };

    // Test initSyncProtocol - should not throw
    EXPECT_NO_THROW(
    {
        Syscollector::instance().initSyncProtocol(
            "syscollector",
            ":memory:",
            ":memory:",
            mqFuncs,
            std::chrono::seconds(10),
            std::chrono::seconds(5),
            3,
            100,
            86400
        );
    });

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, initSyncProtocol_OsDisabled)
{
    /**
     * Test: Verify initSyncProtocol handles OS being disabled
     * VD sync should still be enabled if packages are enabled
     */

    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    // Initialize with OS disabled but packages enabled
    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600,
                                  false,   // scanOnStart
                                  false,   // hardware
                                  false,   // os (disabled)
                                  false,   // network
                                  true,    // packages (enabled)
                                  false,   // ports
                                  false,   // portsAll
                                  false,   // processes
                                  false,   // hotfixes (disabled)
                                  false,   // groups
                                  false,   // users
                                  false,   // services
                                  false,   // browserExtensions
                                  false);  // notifyOnFirstScan

    // Mock MQ functions
    MQ_Functions mqFuncs;
    mqFuncs.start = [](const char*, short, short) -> int { return 0; };
    mqFuncs.send_binary = [](int, const void*, size_t, const char*, char) -> int { return 0; };

    // Test initSyncProtocol - should not throw
    EXPECT_NO_THROW(
    {
        Syscollector::instance().initSyncProtocol(
            "syscollector",
            ":memory:",
            ":memory:",
            mqFuncs,
            std::chrono::seconds(10),
            std::chrono::seconds(5),
            3,
            100,
            86400
        );
    });

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, initSyncProtocol_DifferentParameters)
{
    /**
     * Test: Verify initSyncProtocol accepts and handles different parameter values
     * Tests various timeout, retry, and maxEps values
     */

    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).Times(0);
    EXPECT_CALL(*spInfoWrapper, os()).Times(0);

    // Initialize with packages enabled
    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600,
                                  false,   // scanOnStart
                                  false,   // hardware
                                  true,    // os (enabled)
                                  false,   // network
                                  true,    // packages (enabled)
                                  false,   // ports
                                  false,   // portsAll
                                  false,   // processes
                                  false,   // hotfixes (disabled)
                                  false,   // groups
                                  false,   // users
                                  false,   // services
                                  false,   // browserExtensions
                                  false);  // notifyOnFirstScan

    // Mock MQ functions
    MQ_Functions mqFuncs;
    mqFuncs.start = [](const char*, short, short) -> int { return 0; };
    mqFuncs.send_binary = [](int, const void*, size_t, const char*, char) -> int { return 0; };

    // Test with different parameter values
    EXPECT_NO_THROW(
    {
        Syscollector::instance().initSyncProtocol(
            "syscollector",
            ":memory:",
            ":memory:",
            mqFuncs,
            std::chrono::seconds(30),  // Different syncEndDelay
            std::chrono::seconds(15),  // Different timeout
            5,                          // Different retries
            500,                        // Different maxEps
            86400
        );
    });

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, notifyDisableCollectorsDataCleanNoDisabledCollectors)
{
    // Test case: All collectors enabled, no data to clean
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};

    // Setup log capturing
    LogCapture logCapture;
    auto captureLogFunction = [&logCapture](modules_log_level_t level, const std::string & log)
    {
        logCapture.capture(level, log);
    };

    // Initialize with all collectors enabled
    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  captureLogFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600,
                                  true,
                                  true,   // hardware
                                  true,   // os
                                  true,   // network
                                  true,   // packages
                                  true,   // ports
                                  true,
                                  true,   // processes
                                  true,   // hotfixes
                                  true,   // groups
                                  true,   // users
                                  true,   // services
                                  true,   // browser_extensions
                                  false);

    // Verify no "Disabled collectors with data detected" log (all collectors enabled)
    EXPECT_FALSE(logCapture.contains(LOG_INFO, "Disabled collectors indices with data detected"));

    // Call notifyDisableCollectorsDataClean - should return true (no data to clean)
    EXPECT_TRUE(Syscollector::instance().notifyDisableCollectorsDataClean());

    // Verify log message for no disabled collectors
    EXPECT_TRUE(logCapture.contains(LOG_DEBUG, "No disabled collectors indices with data to notify for cleanup"));

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, notifyDisableCollectorsDataCleanWithDisabledCollectorsNoData)
{
    // Test case: Some collectors disabled but no data in database
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};

    // Setup log capturing
    LogCapture logCapture;
    auto captureLogFunction = [&logCapture](modules_log_level_t level, const std::string & log)
    {
        logCapture.capture(level, log);
    };

    // Initialize with packages and processes collectors disabled
    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  captureLogFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600,
                                  true,
                                  true,   // hardware
                                  true,   // os
                                  true,   // network
                                  false,  // packages - DISABLED
                                  true,   // ports
                                  true,
                                  false,  // processes - DISABLED
                                  true,   // hotfixes
                                  true,   // groups
                                  true,   // users
                                  true,   // services
                                  true,   // browser_extensions
                                  false);

    // Verify no "Disabled collectors with data detected" log (no data in tables)
    EXPECT_FALSE(logCapture.contains(LOG_INFO, "Disabled collectors indices with data detected"));

    // Call notifyDisableCollectorsDataClean - should return true (no data in tables)
    EXPECT_TRUE(Syscollector::instance().notifyDisableCollectorsDataClean());

    // Verify log message for no disabled collectors with data
    EXPECT_TRUE(logCapture.contains(LOG_DEBUG, "No disabled collectors indices with data to notify for cleanup"));

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, notifyDisableCollectorsDataCleanWithDisabledCollectorsAndData)
{
    // Test case: Disabled collectors with data in database
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};

    // Manually populate test DB
    populateTestDb();

    // Setup log capturing for initialization
    LogCapture logCapture;
    auto captureLogFunction = [&logCapture](modules_log_level_t level, const std::string & log)
    {
        logCapture.capture(level, log);
    };

    // Initialize with packages and processes disabled
    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  captureLogFunction,
                                  SYSCOLLECTOR_TEST_DB_PATH,
                                  "",
                                  "",
                                  3600,
                                  false,
                                  true,   // hardware
                                  true,   // os
                                  true,   // network
                                  false,  // packages - DISABLED
                                  true,   // ports
                                  true,
                                  false,  // processes - DISABLED
                                  true,   // hotfixes
                                  true,   // groups
                                  true,   // users
                                  true,   // services
                                  true,   // browser_extensions
                                  false);

    // Verify "Disabled collectors with data detected" log (packages and processes have data)
    EXPECT_TRUE(logCapture.contains(LOG_INFO, "Disabled collectors indices with data detected"));
    EXPECT_TRUE(logCapture.contains(LOG_INFO, "packages"));
    EXPECT_TRUE(logCapture.contains(LOG_INFO, "processes"));

    // Note: notifyDisableCollectorsDataClean requires sync protocol to be initialized
    // Without sync protocol, it should return false
    // This tests the error handling path
    EXPECT_FALSE(Syscollector::instance().notifyDisableCollectorsDataClean());

    // Verify error log for missing sync protocol
    EXPECT_TRUE(logCapture.contains(LOG_ERROR, "Sync protocol not initialized, cannot notify data clean"));

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, deleteDisableCollectorsDataNoDisabledCollectors)
{
    // Test case: No disabled collectors, nothing to delete
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};

    // Setup log capturing
    LogCapture logCapture;
    auto captureLogFunction = [&logCapture](modules_log_level_t level, const std::string & log)
    {
        logCapture.capture(level, log);
    };

    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  captureLogFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600,
                                  true,
                                  true,   // hardware
                                  true,   // os
                                  true,   // network
                                  true,   // packages
                                  true,   // ports
                                  true,
                                  true,   // processes
                                  true,   // hotfixes
                                  true,   // groups
                                  true,   // users
                                  true,   // services
                                  true,   // browser_extensions
                                  false);

    // Call deleteDisableCollectorsData - should not throw and handle empty case gracefully
    EXPECT_NO_THROW(Syscollector::instance().deleteDisableCollectorsData());

    // Verify log message for no disabled collectors
    EXPECT_TRUE(logCapture.contains(LOG_DEBUG, "No disabled collectors indices with data to delete"));

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, deleteDisableCollectorsDataWithDisabledCollectorsAndData)
{
    // Test case: Delete data for disabled collectors
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};

    // Manually populate test DB
    populateTestDb();

    // Setup log capturing for initialization
    LogCapture logCapture;
    auto captureLogFunction = [&logCapture](modules_log_level_t level, const std::string & log)
    {
        logCapture.capture(level, log);
    };

    // Initialize with packages disabled
    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  captureLogFunction,
                                  SYSCOLLECTOR_TEST_DB_PATH,
                                  "",
                                  "",
                                  3600,
                                  false,
                                  true,   // hardware
                                  true,   // os
                                  true,   // network
                                  false,  // packages - DISABLED
                                  true,   // ports
                                  true,
                                  true,   // processes
                                  false,  // hotfixes
                                  false,  // groups
                                  false,  // users
                                  false,  // services
                                  false,  // browser_extensions
                                  false);

    // Verify "Disabled collectors with data detected" log (packages has data)
    EXPECT_TRUE(logCapture.contains(LOG_INFO, "Disabled collectors indices with data detected"));
    EXPECT_TRUE(logCapture.contains(LOG_INFO, "packages"));

    // Call deleteDisableCollectorsData - should clear tables for disabled collectors
    EXPECT_NO_THROW(Syscollector::instance().deleteDisableCollectorsData());

    // Verify log messages for deletion
    EXPECT_TRUE(logCapture.contains(LOG_INFO, "Deleting data for disabled collectors indices"));
    EXPECT_TRUE(logCapture.contains(LOG_DEBUG, "Cleared table dbsync_packages"));

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, allCollectorsDisabledWithData)
{
    // Test case: All collectors disabled - should detect it during initialization
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};

    // Manually populate test DB
    populateTestDb();

    // Setup log capturing for initialization
    LogCapture logCapture;
    auto captureLogFunction = [&logCapture](modules_log_level_t level, const std::string & log)
    {
        logCapture.capture(level, log);
    };

    // Re-initialize with ALL collectors disabled
    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  captureLogFunction,
                                  SYSCOLLECTOR_TEST_DB_PATH,
                                  "",
                                  "",
                                  3600,
                                  false,
                                  false,  // hardware - DISABLED
                                  false,  // os - DISABLED
                                  false,  // network - DISABLED
                                  false,  // packages - DISABLED
                                  false,  // ports - DISABLED
                                  true,
                                  false,  // processes - DISABLED
                                  false,  // hotfixes - DISABLED
                                  false,  // groups - DISABLED
                                  false,  // users - DISABLED
                                  false,  // services - DISABLED
                                  false,  // browser_extensions - DISABLED
                                  false);

    // Verify "Disabled collectors with data detected" log mentions all collectors with data
    EXPECT_TRUE(logCapture.contains(LOG_INFO, "Disabled collectors indices with data detected"));
    // Should contain hardware, os, network (3 indices), packages, ports and processes
    EXPECT_TRUE(logCapture.contains(LOG_INFO, "hardware"));
    EXPECT_TRUE(logCapture.contains(LOG_INFO, "system"));
    EXPECT_TRUE(logCapture.contains(LOG_INFO, "interfaces") ||
                logCapture.contains(LOG_INFO, "protocols") ||
                logCapture.contains(LOG_INFO, "networks"));
    EXPECT_TRUE(logCapture.contains(LOG_INFO, "packages"));
    EXPECT_TRUE(logCapture.contains(LOG_INFO, "ports"));
    EXPECT_TRUE(logCapture.contains(LOG_INFO, "processes"));

    // The populateDisabledCollectorsIndexes() should have detected all disabled collectors with data
    // We can verify this by calling notifyDisableCollectorsDataClean (will fail without sync protocol)
    EXPECT_FALSE(Syscollector::instance().notifyDisableCollectorsDataClean());

    // Verify error log for missing sync protocol
    EXPECT_TRUE(logCapture.contains(LOG_ERROR, "Sync protocol not initialized, cannot notify data clean"));

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, networkCollectorDisabledThreeIndices)
{
    // Test case: Network collector disabled - should detect 3 indices (interfaces, protocols, networks)
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};

    // Manually populate test DB
    populateTestDb();

    // Setup log capturing for initialization
    LogCapture logCapture;
    auto captureLogFunction = [&logCapture](modules_log_level_t level, const std::string & log)
    {
        logCapture.capture(level, log);
    };

    // Re-initialize with network disabled
    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  captureLogFunction,
                                  SYSCOLLECTOR_TEST_DB_PATH,
                                  "",
                                  "",
                                  3600,
                                  false,
                                  true,  // hardware
                                  true,  // os
                                  false,  // network - DISABLED (should trigger 3 indices cleanup)
                                  true,  // packages
                                  true,  // ports
                                  true,
                                  true,  // processes
                                  false,  // hotfixes
                                  false,  // groups
                                  false,  // users
                                  false,  // services
                                  false,  // browser_extensions
                                  false);

    // Verify "Disabled collectors with data detected" log contains network-related indices
    EXPECT_TRUE(logCapture.contains(LOG_INFO, "Disabled collectors indices with data detected"));
    // Network collector produces 3 indices
    EXPECT_TRUE(logCapture.contains(LOG_INFO, "interfaces") ||
                logCapture.contains(LOG_INFO, "protocols") ||
                logCapture.contains(LOG_INFO, "networks"));

    // Should have detected network collector disabled with 3 indices
    // Verify by attempting notification (will fail without sync protocol but tests the detection)
    EXPECT_FALSE(Syscollector::instance().notifyDisableCollectorsDataClean());

    // Verify error log for missing sync protocol
    EXPECT_TRUE(logCapture.contains(LOG_ERROR, "Sync protocol not initialized, cannot notify data clean"));

    // Cleanup should work even without sync protocol
    EXPECT_NO_THROW(Syscollector::instance().deleteDisableCollectorsData());

    // Verify log messages for deletion of 3 network tables
    EXPECT_TRUE(logCapture.contains(LOG_INFO, "Deleting data for disabled collectors indices"));
    EXPECT_TRUE(logCapture.contains(LOG_DEBUG, "Cleared table dbsync_network_iface"));
    EXPECT_TRUE(logCapture.contains(LOG_DEBUG, "Cleared table dbsync_network_protocol"));
    EXPECT_TRUE(logCapture.contains(LOG_DEBUG, "Cleared table dbsync_network_address"));

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, destroyWaitsForSyncLoopCompletion)
{
    auto spInfoWrapper
    {
        std::make_shared<MockSysInfo>()
    };

    CallbackMock wrapper;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapper](const std::string & data)
        {
            wrapper.callbackMock(data);
        }
    };

    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapper](const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)
        {
            // Empty callback for this test
        }
    };

    // Allow any number of callback invocations
    EXPECT_CALL(wrapper, callbackMock(testing::_)).Times(testing::AnyNumber());
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));

    std::atomic<bool> syncLoopExited{false};
    std::atomic<bool> destroyReturned{false};

    std::thread t
    {
        [&]()
        {
            // Start syscollector with a long interval
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          logFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          3600, // 1 hour interval to ensure we control the timing
                                          true, true, true, false, false, false, false, false, false, false, false, false, false, false);
            syncLoopExited = true;
        }
    };

    // Wait for init to start and complete first scan
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    // Call destroy in separate thread to verify it blocks
    std::thread destroyThread{[&]()
    {
        Syscollector::instance().destroy();
        destroyReturned = true;
    }};

    // Give destroy time to be called
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // At this point, destroy should have been called and should be waiting
    // Now wait for syncLoop to actually exit
    destroyThread.join();

    // Verify the correct order: syncLoop must exit before destroy returns
    // If destroy returned, syncLoop must have exited
    EXPECT_TRUE(destroyReturned);
    EXPECT_TRUE(syncLoopExited);

    if (t.joinable())
    {
        t.join();
    }

}

// Recovery functions tests via public interface
TEST_F(SyscollectorImpTest, initSyncProtocolWithIntegrityInterval)
{
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};

    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600, false, false, false, false, false, false, false, false, false, false, false, false, false, false);

    // Initialize sync protocol with integrity interval
    MQ_Functions mqFuncs{};
    mqFuncs.start = [](const char*, short, short)
    {
        return 0;
    };
    mqFuncs.send_binary = [](int, const void*, size_t, const char*, char)
    {
        return 0;
    };

    EXPECT_NO_THROW(
        Syscollector::instance().initSyncProtocol(
            "syscollector",
            ":memory:",
            ":memory:",
            mqFuncs,
            std::chrono::seconds(10),
            std::chrono::seconds(30),
            3,
            1000,
            86400  // 24 hours integrity interval
        )
    );

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, runRecoveryProcessWithoutSyncProtocol)
{
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};

    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600, false, false, false, false, false, false, false, false, false, false, false, false, false, false);

    // Running recovery without sync protocol should not crash
    EXPECT_NO_THROW(Syscollector::instance().runRecoveryProcess());

    Syscollector::instance().destroy();
}

TEST_F(SyscollectorImpTest, runRecoveryProcessWithSyncProtocol)
{
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};

    Syscollector::instance().init(spInfoWrapper,
                                  reportFunction,
                                  persistFunction,
                                  logFunction,
                                  SYSCOLLECTOR_DB_PATH,
                                  "",
                                  "",
                                  3600, false, true, false, false, false, false, false, false, false, false, false, false, false, false);

    // Initialize sync protocol
    MQ_Functions mqFuncs{};
    mqFuncs.start = [](const char*, short, short)
    {
        return 0;
    };
    mqFuncs.send_binary = [](int, const void*, size_t, const char*, char)
    {
        return 0;
    };

    Syscollector::instance().initSyncProtocol(
        "syscollector",
        ":memory:",
        ":memory:",
        mqFuncs,
        std::chrono::seconds(10),
        std::chrono::seconds(30),
        3,
        1000,
        86400
    );

    // Run recovery process - should execute without throwing
    EXPECT_NO_THROW(Syscollector::instance().runRecoveryProcess());

    Syscollector::instance().destroy();
}

// Schema validation tests
TEST_F(SyscollectorImpTest, schemaValidationAcceptsValidDataAfterCorrections)
{
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};

    // Return valid hardware data (cpu_speed as integer, which our correction handles)
    const std::string validHardwareJson =
        R"({"serial_number":"Intel Corporation", "cpu_speed":2904,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400","memory_free":2257872,"memory_total":4972208,"memory_used":54})";

    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(validHardwareJson)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, packages(_)).Times(0);
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, processes(_)).Times(0);
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json{}));

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            wrapperDelta.callbackMock(data);
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            wrapperPersist.callbackMock(id, operation, index, data, version);
        }
    };

    // Expect persist callback for valid hardware data (will pass validation)
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::Eq("wazuh-states-inventory-hardware"), testing::_, testing::_)).Times(1);

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
                                          5, true, true, false, false, false, false, false, false, false, false, false, false, false, false);

            // Initialize sync protocol to enable schema validation
            MQ_Functions mqFuncs;
            mqFuncs.start = [](const char*, short, short) -> int { return 0; };
            mqFuncs.send_binary = [](int, const void*, size_t, const char*, char) -> int { return 0; };

            Syscollector::instance().initSyncProtocol(
                "syscollector",
                ":memory:",
                ":memory:",
                mqFuncs,
                std::chrono::seconds(10),
                std::chrono::seconds(5),
                3,
                100,
                86400
            );

            Syscollector::instance().start();
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(2));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }

    // Reset factory after test
    SchemaValidator::SchemaValidatorFactory::getInstance().reset();
}

TEST_F(SyscollectorImpTest, schemaValidationWithCorrectedDataTypes)
{
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};

    // Data that our corrections should handle:
    // - file_inode as number (will be converted to string)
    // - cpu_speed as float (will be converted to integer)
    const std::string hardwareJson = R"({"serial_number":"Intel", "cpu_speed":2688.0,"cpu_cores":2,"cpu_name":"Intel i5","memory_free":1000000,"memory_total":2000000,"memory_used":1000000})";
    const std::string portsJson =
        R"([{"file_inode":6822,"source_ip":"127.0.0.1","source_port":22,"process_pid":822,"process_name":"sshd","network_transport":"tcp","destination_ip":"0.0.0.0","destination_port":0,"host_network_ingress_queue":0,"interface_state":"listening","host_network_egress_queue":0}])";

    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(hardwareJson)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse(portsJson)));
    EXPECT_CALL(*spInfoWrapper, packages(_)).Times(0);
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, processes(_)).Times(0);
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json{}));

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            wrapperDelta.callbackMock(data);
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            // Verify corrected data types in the actual data
            auto jsonData = nlohmann::json::parse(data);

            if (index == "wazuh-states-inventory-hardware")
            {
                // cpu_speed should be integer now
                EXPECT_TRUE(jsonData["host"]["cpu"]["speed"].is_number_integer());
                EXPECT_EQ(jsonData["host"]["cpu"]["speed"].get<int>(), 2688);
            }
            else if (index == "wazuh-states-inventory-ports")
            {
                // file.inode should be string now
                EXPECT_TRUE(jsonData["file"]["inode"].is_string());
                EXPECT_EQ(jsonData["file"]["inode"].get<std::string>(), "6822");
            }

            wrapperPersist.callbackMock(id, operation, index, data, version);
        }
    };

    // Expect persist callbacks for valid data after corrections
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::Eq("wazuh-states-inventory-hardware"), testing::_, testing::_)).Times(1);
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::Eq("wazuh-states-inventory-ports"), testing::_, testing::_)).Times(1);

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
                                          5, true, true, false, false, false, true, false, false, false, false, false, false, false, false);

            // Initialize sync protocol to enable schema validation
            MQ_Functions mqFuncs;
            mqFuncs.start = [](const char*, short, short) -> int { return 0; };
            mqFuncs.send_binary = [](int, const void*, size_t, const char*, char) -> int { return 0; };

            Syscollector::instance().initSyncProtocol(
                "syscollector",
                ":memory:",
                ":memory:",
                mqFuncs,
                std::chrono::seconds(10),
                std::chrono::seconds(5),
                3,
                100,
                86400
            );

            Syscollector::instance().start();
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(2));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }

    // Reset factory after test
    SchemaValidator::SchemaValidatorFactory::getInstance().reset();
}

// Schema validation test using mock to force rejection
TEST_F(SyscollectorImpTest, schemaValidationRejectsInvalidDataWithMock)
{
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};

    // Return any hardware data (content doesn't matter, mock will force failure)
    const std::string hardwareJson =
        R"({"serial_number":"Intel Corporation", "cpu_speed":2688,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400","memory_free":2257872,"memory_total":4972208,"memory_used":54})";

    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(hardwareJson)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, packages(_)).Times(0);
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, processes(_)).Times(0);
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json{}));

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            wrapperDelta.callbackMock(data);
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            wrapperPersist.callbackMock(id, operation, index, data, version);
        }
    };

    // Expect NO persist callback for invalid hardware data (will be rejected by mock validator)
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::Eq("wazuh-states-inventory-hardware"), testing::_, testing::_)).Times(0);

    // Capture log messages to verify validation errors
    std::vector<std::string> loggedMessages;
    auto customLogFunction = [&loggedMessages](modules_log_level_t, const std::string & message)
    {
        loggedMessages.push_back(message);
    };

    // Create mock validator that will reject all validations
    auto mockValidator = std::make_shared<MockSchemaValidatorEngine>();

    SchemaValidator::ValidationResult failureResult;
    failureResult.isValid = false;
    failureResult.errors = {"Field 'host.memory.free' has invalid type: expected 'long', got 'string'"};

    EXPECT_CALL(*mockValidator, validate(testing::An<const std::string&>()))
    .WillRepeatedly(testing::Return(failureResult));

    EXPECT_CALL(*mockValidator, getSchemaName())
    .WillRepeatedly(testing::Return("wazuh-states-inventory-hardware"));

    // Inject mock validator into factory
    std::map<std::string, std::shared_ptr<SchemaValidator::ISchemaValidatorEngine>> mockValidators;
    mockValidators["wazuh-states-inventory-hardware"] = mockValidator;

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist, &customLogFunction, &mockValidators]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          customLogFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          5, true, true, false, false, false, false, false, false, false, false, false, false, false, false);

            // Reset and initialize factory with mock BEFORE initSyncProtocol
            SchemaValidator::SchemaValidatorFactory::getInstance().reset();
            SchemaValidator::SchemaValidatorFactory::getInstance().initialize(mockValidators);

            // Initialize sync protocol
            MQ_Functions mqFuncs;
            mqFuncs.start = [](const char*, short, short) -> int { return 0; };
            mqFuncs.send_binary = [](int, const void*, size_t, const char*, char) -> int { return 0; };

            Syscollector::instance().initSyncProtocol(
                "syscollector",
                ":memory:",
                ":memory:",
                mqFuncs,
                std::chrono::seconds(10),
                std::chrono::seconds(5),
                3,
                100,
                86400
            );

            Syscollector::instance().start();
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(2));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }

    // Reset factory after test
    SchemaValidator::SchemaValidatorFactory::getInstance().reset();

    // Verify that validation errors were logged
    EXPECT_FALSE(loggedMessages.empty());

    bool foundValidationError = false;
    bool foundDiscardMessage = false;
    bool foundDeferredDeletion = false;

    for (const auto& msg : loggedMessages)
    {
        if (msg.find("Schema validation failed") != std::string::npos)
        {
            foundValidationError = true;
        }

        if (msg.find("Discarding invalid Syscollector message") != std::string::npos)
        {
            foundDiscardMessage = true;
        }

        if (msg.find("Marking entry from table") != std::string::npos &&
                msg.find("for deferred deletion") != std::string::npos)
        {
            foundDeferredDeletion = true;
        }
    }

    EXPECT_TRUE(foundValidationError) << "Expected validation error not found";
    EXPECT_TRUE(foundDiscardMessage) << "Expected discard message not found";
    EXPECT_TRUE(foundDeferredDeletion) << "Expected deferred deletion log not found";
}

// Test for missing validator: factory is initialized but no validator for the index
TEST_F(SyscollectorImpTest, schemaValidationQueuesWhenValidatorNotFound)
{
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};

    const std::string hardwareJson =
        R"({"serial_number":"Intel Corporation", "cpu_speed":2688,"cpu_cores":2,"cpu_name":"Intel(R) Core(TM) i5-9400","memory_free":2257872,"memory_total":4972208,"memory_used":54})";

    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(hardwareJson)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, packages(_)).Times(0);
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, processes(_)).Times(0);
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json{}));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json{}));

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string & data)
        {
            wrapperDelta.callbackMock(data);
        }
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string & id, Operation_t operation, const std::string & index, const std::string & data, uint64_t version)
        {
            wrapperPersist.callbackMock(id, operation, index, data, version);
        }
    };

    // Expect persist callback for hardware data (should be queued despite missing validator)
    EXPECT_CALL(wrapperPersist, callbackMock(testing::_, testing::_, testing::Eq("wazuh-states-inventory-hardware"), testing::_, testing::_)).Times(1);

    // Capture log messages to verify warning is logged
    // Use shared_ptr to prevent dangling references after test completes
    auto loggedMessages = std::make_shared<std::vector<std::string>>();
    auto customLogFunction = [loggedMessages](modules_log_level_t, const std::string & message)
    {
        loggedMessages->push_back(message);
    };

    // Create mock validator for a DIFFERENT index (not for hardware)
    auto mockValidator = std::make_shared<MockSchemaValidatorEngine>();

    EXPECT_CALL(*mockValidator, getSchemaName())
    .WillRepeatedly(testing::Return("some-other-index"));

    // Inject mock validator for a different index (factory is initialized, but no validator for hardware)
    std::map<std::string, std::shared_ptr<SchemaValidator::ISchemaValidatorEngine>> mockValidators;
    mockValidators["some-other-index"] = mockValidator;

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist, &customLogFunction, &mockValidators]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          customLogFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          5, true, true, false, false, false, false, false, false, false, false, false, false, false, false);

            // Reset and initialize factory with mock for DIFFERENT index
            SchemaValidator::SchemaValidatorFactory::getInstance().reset();
            SchemaValidator::SchemaValidatorFactory::getInstance().initialize(mockValidators);

            // Initialize sync protocol
            MQ_Functions mqFuncs;
            mqFuncs.start = [](const char*, short, short) -> int { return 0; };
            mqFuncs.send_binary = [](int, const void*, size_t, const char*, char) -> int { return 0; };

            Syscollector::instance().initSyncProtocol(
                "syscollector",
                ":memory:",
                ":memory:",
                mqFuncs,
                std::chrono::seconds(10),
                std::chrono::seconds(5),
                3,
                100,
                86400
            );

            Syscollector::instance().start();
        }
    };

    std::this_thread::sleep_for(std::chrono::seconds(2));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }

    // Reset factory after test
    SchemaValidator::SchemaValidatorFactory::getInstance().reset();

    // Verify that warning was logged for missing validator
    EXPECT_FALSE(loggedMessages->empty());

    bool foundMissingValidatorWarning = false;

    for (const auto& msg : *loggedMessages)
    {
        if (msg.find("No schema validator found for index: wazuh-states-inventory-hardware") != std::string::npos)
        {
            foundMissingValidatorWarning = true;
            break;
        }
    }

    EXPECT_TRUE(foundMissingValidatorWarning) << "Expected warning for missing validator not found";
}

// Test setDocumentLimits with invalid input (not a JSON object)
// This tests the input validation path: if (!limits.is_object()) return false;
TEST_F(SyscollectorImpTest, DocumentLimits_InvalidInput_NotAnObject)
{
    // Capture log messages
    // Use shared_ptr to prevent dangling references after test completes
    auto logCapture = std::make_shared<LogCapture>();

    // Create log function that captures messages
    std::function<void(const modules_log_level_t, const std::string&)> captureLogFunction =
        [logCapture](const modules_log_level_t level, const std::string & message)
    {
        logCapture->capture(level, message);
    };

    // Set up mock agentd query to return an array instead of an object
    auto mockQuery = [](const char*, char* output, size_t size) -> bool
    {
        // Return invalid JSON - an array instead of an object
        std::string response = R"([1, 2, 3])";
        std::strncpy(output, response.c_str(), size - 1);
        output[size - 1] = '\0';
        return true;
    };

    Syscollector::instance().setAgentdQueryFunction(mockQuery);

    // Set up minimal mock sysinfo (no scan data needed for this test)
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, packages(_)).WillRepeatedly(Return());
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, processes(_)).WillRepeatedly(Return());
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse("[]")));

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string&) {}
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string&, Operation_t, const std::string&, const std::string&, uint64_t) {}
    };

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist, &captureLogFunction]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          captureLogFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          5, false, true, false, false, false, false, false, false, false, false, false, false, false, false);

            Syscollector::instance().start();
        }
    };

    // Wait for syncLoop to attempt fetching and applying limits
    std::this_thread::sleep_for(std::chrono::seconds(2));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }

    // Verify that an error was logged about failing to apply document limits
    // When setDocumentLimits receives a non-object (an array in this case),
    // it should return false, causing the error message to be logged
    EXPECT_TRUE(logCapture->contains(LOG_ERROR, "Failed to apply document limits"))
            << "Expected error log about failing to apply document limits";
}

// Test setDocumentLimits with valid input - limit value of 0 (unlimited)
// This tests the path where limits are valid and set to 0 (no limit)
TEST_F(SyscollectorImpTest, DocumentLimits_ValidInput_UnlimitedPackages)
{
    // Capture log messages
    // Use shared_ptr to prevent dangling references after test completes
    auto logCapture = std::make_shared<LogCapture>();

    // Create log function that captures messages
    std::function<void(const modules_log_level_t, const std::string&)> captureLogFunction =
        [logCapture](const modules_log_level_t level, const std::string & message)
    {
        logCapture->capture(level, message);
    };

    // Set up mock agentd query to return valid limits with packages=0 (unlimited)
    auto mockQuery = [](const char*, char* output, size_t size) -> bool
    {
        // Return valid JSON object with packages limit set to 0 (unlimited)
        std::string response = R"({"packages": 0})";
        std::strncpy(output, response.c_str(), size - 1);
        output[size - 1] = '\0';
        return true;
    };

    Syscollector::instance().setAgentdQueryFunction(mockQuery);

    // Set up minimal mock sysinfo
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, packages(_)).WillRepeatedly(Return());
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, processes(_)).WillRepeatedly(Return());
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse("[]")));

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string&) {}
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string&, Operation_t, const std::string&, const std::string&, uint64_t) {}
    };

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist, &captureLogFunction]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          captureLogFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          5, false, true, false, false, false, false, false, false, false, false, false, false, false, false);

            Syscollector::instance().start();
        }
    };

    // Wait for syncLoop to fetch and apply limits
    std::this_thread::sleep_for(std::chrono::seconds(2));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }

    // Verify that document limits were successfully configured
    // When limit is 0 (unlimited), should log info about unlimited
    EXPECT_TRUE(logCapture->contains(LOG_INFO, "Document limits successfully configured from agentd"))
            << "Expected success message about document limits";

    EXPECT_TRUE(logCapture->contains(LOG_DEBUG, "Document limit set to unlimited for index 'wazuh-states-inventory-packages'"))
            << "Expected info log about unlimited packages";
}

// Test setDocumentLimits with invalid limit value (not a number)
// This tests the validation path for limit values: if (!limit.is_number_unsigned())
TEST_F(SyscollectorImpTest, DocumentLimits_InvalidLimitValue_NotANumber)
{
    // Capture log messages
    // Use shared_ptr to prevent dangling references after test completes
    auto logCapture = std::make_shared<LogCapture>();

    // Create log function that captures messages
    std::function<void(const modules_log_level_t, const std::string&)> captureLogFunction =
        [logCapture](const modules_log_level_t level, const std::string & message)
    {
        logCapture->capture(level, message);
    };

    // Set up mock agentd query to return invalid limit value (string instead of number)
    auto mockQuery = [](const char*, char* output, size_t size) -> bool
    {
        // Return JSON object with invalid limit value (string instead of unsigned number)
        std::string response = R"({"packages": "invalid"})";
        std::strncpy(output, response.c_str(), size - 1);
        output[size - 1] = '\0';
        return true;
    };

    Syscollector::instance().setAgentdQueryFunction(mockQuery);

    // Set up minimal mock sysinfo
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, packages(_)).WillRepeatedly(Return());
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, processes(_)).WillRepeatedly(Return());
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse("[]")));

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string&) {}
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string&, Operation_t, const std::string&, const std::string&, uint64_t) {}
    };

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist, &captureLogFunction]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          captureLogFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          5, false, true, false, false, false, false, false, false, false, false, false, false, false, false);

            Syscollector::instance().start();
        }
    };

    // Wait for syncLoop to fetch and attempt to apply limits
    std::this_thread::sleep_for(std::chrono::seconds(2));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }

    // Verify that appropriate error messages were logged
    // Should have error about invalid limit value
    EXPECT_TRUE(logCapture->contains(LOG_ERROR, "Invalid limit value for index: packages"))
            << "Expected error log about invalid limit value";

    // Should have error about failing to apply document limits
    EXPECT_TRUE(logCapture->contains(LOG_ERROR, "Failed to apply document limits"))
            << "Expected error log about failing to apply document limits";
}

// Test setDocumentLimits with unknown index name
// This tests the validation path for index names: AGENTD_TO_INDEX_MAP.find()
TEST_F(SyscollectorImpTest, DocumentLimits_UnknownIndexName)
{
    // Capture log messages
    // Use shared_ptr to prevent dangling references after test completes
    auto logCapture = std::make_shared<LogCapture>();

    // Create log function that captures messages
    std::function<void(const modules_log_level_t, const std::string&)> captureLogFunction =
        [logCapture](const modules_log_level_t level, const std::string & message)
    {
        logCapture->capture(level, message);
    };

    // Set up mock agentd query to return unknown index name
    auto mockQuery = [](const char*, char* output, size_t size) -> bool
    {
        // Return JSON object with unknown index name
        std::string response = R"({"unknown_index": 100})";
        std::strncpy(output, response.c_str(), size - 1);
        output[size - 1] = '\0';
        return true;
    };

    Syscollector::instance().setAgentdQueryFunction(mockQuery);

    // Set up minimal mock sysinfo
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, packages(_)).WillRepeatedly(Return());
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, processes(_)).WillRepeatedly(Return());
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse("[]")));

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string&) {}
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string&, Operation_t, const std::string&, const std::string&, uint64_t) {}
    };

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist, &captureLogFunction]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          captureLogFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          5, false, true, false, false, false, false, false, false, false, false, false, false, false, false);

            Syscollector::instance().start();
        }
    };

    // Wait for syncLoop to fetch and attempt to apply limits
    std::this_thread::sleep_for(std::chrono::seconds(2));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }

    // Verify that appropriate error messages were logged
    // Should have error about unknown index
    EXPECT_TRUE(logCapture->contains(LOG_ERROR, "Unknown index from agentd: unknown_index"))
            << "Expected error log about unknown index";

    // Should have error about failing to apply document limits
    EXPECT_TRUE(logCapture->contains(LOG_ERROR, "Failed to apply document limits"))
            << "Expected error log about failing to apply document limits";
}

// Test setDocumentLimits with valid numeric limit (newLimit >= currentCount case)
// This tests the path where limit is set and no data exceeds it
// Lines covered: validation, counting, accept limit
TEST_F(SyscollectorImpTest, DocumentLimits_ValidInput_NumericLimit)
{
    // Capture log messages
    // Use shared_ptr to prevent dangling references after test completes
    auto logCapture = std::make_shared<LogCapture>();

    // Create log function that captures messages
    std::function<void(const modules_log_level_t, const std::string&)> captureLogFunction =
        [logCapture](const modules_log_level_t level, const std::string & message)
    {
        logCapture->capture(level, message);
    };

    // Set up mock agentd query to return valid numeric limit
    auto mockQuery = [](const char*, char* output, size_t size) -> bool
    {
        // Return valid JSON object with packages limit set to 100
        std::string response = R"({"packages": 100})";
        std::strncpy(output, response.c_str(), size - 1);
        output[size - 1] = '\0';
        return true;
    };

    Syscollector::instance().setAgentdQueryFunction(mockQuery);

    // Set up minimal mock sysinfo
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, packages(_)).WillRepeatedly(Return());
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, processes(_)).WillRepeatedly(Return());
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse("[]")));

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string&) {}
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string&, Operation_t, const std::string&, const std::string&, uint64_t) {}
    };

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist, &captureLogFunction]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          captureLogFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          5, false, true, false, false, false, false, false, false, false, false, false, false, false, false);

            Syscollector::instance().start();
        }
    };

    // Wait for syncLoop to fetch and apply limits
    std::this_thread::sleep_for(std::chrono::seconds(2));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }

    // Verify that document limits were successfully configured
    EXPECT_TRUE(logCapture->contains(LOG_INFO, "Document limits successfully configured from agentd"))
            << "Expected success message about document limits";

    // When currentCount (0) < newLimit (100), it attempts to promote unsynced items
    // Since there are no unsynced items, it logs a DEBUG message
    EXPECT_TRUE(logCapture->contains(LOG_DEBUG_VERBOSE, "Document limit increased from 0 to 100: No unsynced items available to promote"))
            << "Expected debug log about no unsynced items to promote";
}

// Summary test to verify the DocumentLimits feature works end-to-end
// This test verifies that:
// 1. Document limits are fetched from agentd
// 2. Limits are applied successfully
// 3. The system respects the limits during operation
// Lines covered: Validates the overall document limits functionality
TEST_F(SyscollectorImpTest, DocumentLimits_EndToEnd_Summary)
{
    // Capture log messages
    auto logCapture = std::make_shared<LogCapture>();

    // Create log function that captures messages
    std::function<void(const modules_log_level_t, const std::string&)> captureLogFunction =
        [logCapture](const modules_log_level_t level, const std::string & message)
    {
        logCapture->capture(level, message);
    };

    // Set up mock agentd query to return multiple valid limits
    auto mockQuery = [](const char*, char* output, size_t size) -> bool
    {
        // Return JSON object with multiple index limits
        std::string response = R"({"packages": 50, "processes": 0, "hotfixes": 10})";
        std::strncpy(output, response.c_str(), size - 1);
        output[size - 1] = '\0';
        return true;
    };

    Syscollector::instance().setAgentdQueryFunction(mockQuery);

    // Set up minimal mock sysinfo
    const auto spInfoWrapper{std::make_shared<MockSysInfo>()};
    EXPECT_CALL(*spInfoWrapper, hardware()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_HARDWARE_JSON)));
    EXPECT_CALL(*spInfoWrapper, os()).WillRepeatedly(Return(nlohmann::json::parse(EXPECT_CALL_OS_JSON)));
    EXPECT_CALL(*spInfoWrapper, networks()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, ports()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, packages(_)).WillRepeatedly(Return());
    EXPECT_CALL(*spInfoWrapper, hotfixes()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, processes(_)).WillRepeatedly(Return());
    EXPECT_CALL(*spInfoWrapper, groups()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, users()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, services()).WillRepeatedly(Return(nlohmann::json::parse("[]")));
    EXPECT_CALL(*spInfoWrapper, browserExtensions()).WillRepeatedly(Return(nlohmann::json::parse("[]")));

    CallbackMock wrapperDelta;
    std::function<void(const std::string&)> callbackDataDelta
    {
        [&wrapperDelta](const std::string&) {}
    };

    CallbackMockPersist wrapperPersist;
    std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> callbackDataPersist
    {
        [&wrapperPersist](const std::string&, Operation_t, const std::string&, const std::string&, uint64_t) {}
    };

    std::thread t
    {
        [&spInfoWrapper, &callbackDataDelta, &callbackDataPersist, &captureLogFunction]()
        {
            Syscollector::instance().init(spInfoWrapper,
                                          callbackDataDelta,
                                          callbackDataPersist,
                                          captureLogFunction,
                                          SYSCOLLECTOR_DB_PATH,
                                          "",
                                          "",
                                          5, false, true, false, false, false, false, false, false, false, false, false, false, false, false);

            Syscollector::instance().start();
        }
    };

    // Wait for syncLoop to fetch and apply limits
    std::this_thread::sleep_for(std::chrono::seconds(2));
    Syscollector::instance().destroy();

    if (t.joinable())
    {
        t.join();
    }

    // Verify that document limits were successfully configured
    EXPECT_TRUE(logCapture->contains(LOG_INFO, "Document limits successfully configured from agentd"))
            << "Expected success message about document limits";

    // Verify that limits were set for each index
    EXPECT_TRUE(logCapture->contains(LOG_DEBUG_VERBOSE, "Document limit increased from 0 to 50"))
            << "Expected packages limit to be set to 50";

    EXPECT_TRUE(logCapture->contains(LOG_DEBUG, "Document limit set to unlimited for index 'wazuh-states-inventory-processes'"))
            << "Expected processes to be unlimited (0)";

    EXPECT_TRUE(logCapture->contains(LOG_DEBUG_VERBOSE, "Document limit increased from 0 to 10"))
            << "Expected hotfixes limit to be set to 10";
}
