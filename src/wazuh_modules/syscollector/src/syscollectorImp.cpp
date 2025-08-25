/*
 * Wazuh SysCollector
 * Copyright (C) 2015, Wazuh Inc.
 * October 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "syscollector.h"
#include "syscollector.hpp"
#include "json.hpp"
#include "stringHelper.h"
#include "hashHelper.h"
#include "timeHelper.h"
#include <iostream>
#include <stack>

#include "syscollectorTablesDef.hpp"

#define TRY_CATCH_TASK(task)                                            \
do                                                                      \
{                                                                       \
    try                                                                 \
    {                                                                   \
        if(!m_stopping)                                                 \
        {                                                               \
            task();                                                     \
        }                                                               \
    }                                                                   \
    catch(const std::exception& ex)                                     \
    {                                                                   \
        if(m_logFunction)                                               \
        {                                                               \
            m_logFunction(LOG_ERROR, std::string{ex.what()});           \
        }                                                               \
    }                                                                   \
}while(0)

constexpr auto EMPTY_VALUE {""};
constexpr auto UNKNOWN_VALUE {" "};

constexpr auto QUEUE_SIZE
{
    4096
};

static const std::map<ReturnTypeCallback, std::string> OPERATION_MAP
{
    // LCOV_EXCL_START
    {MODIFIED, "modified"},
    {DELETED, "deleted"},
    {INSERTED, "created"},
    {MAX_ROWS, "max_rows"},
    {DB_ERROR, "db_error"},
    {SELECTED, "selected"},
    // LCOV_EXCL_STOP
};

static void sanitizeJsonValue(nlohmann::json& input)
{
    if (input.is_object())
    {
        for (auto it = input.begin(); it != input.end(); ++it)
        {
            auto& value = it.value();

            sanitizeJsonValue(value);
        }
    }
    else if (input.is_array())
    {
        for (auto& item : input)
        {
            sanitizeJsonValue(item);
        }
    }
    else if (input.is_string())
    {
        const std::string& stringValue = input.get_ref<const std::string&>();

        if (stringValue != " ")
        {
            input = Utils::trim(stringValue);
        }
    }
}

static std::string getItemChecksum(const nlohmann::json& item)
{
    const auto content{item.dump()};
    Utils::HashData hash;
    hash.update(content.c_str(), content.size());
    return Utils::asciiToHex(hash.hash());
}

static std::string getItemId(const nlohmann::json& item, const std::vector<std::string>& idFields)
{
    Utils::HashData hash;

    for (const auto& field : idFields)
    {
        const auto& value{item.at(field)};

        if (value.is_string())
        {
            const auto& valueString{value.get<std::string>()};
            hash.update(valueString.c_str(), valueString.size());
        }
        else
        {
            const auto& valueNumber{value.get<unsigned long>()};
            const auto valueString{std::to_string(valueNumber)};
            hash.update(valueString.c_str(), valueString.size());
        }
    }

    return Utils::asciiToHex(hash.hash());
}

static bool isElementDuplicated(const nlohmann::json& input, const std::pair<std::string, std::string>& keyValue)
{
    const auto it
    {
        std::find_if (input.begin(), input.end(), [&keyValue](const auto & elem)
        {
            return elem.at(keyValue.first) == keyValue.second;
        })
    };
    return it != input.end();
}

void Syscollector::notifyChange(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table)
{
    if (DB_ERROR == result)
    {
        m_logFunction(LOG_ERROR, data.dump());
    }
    else if (!m_stopping)
    {
        if (data.is_array())
        {
            for (const auto& item : data)
            {
                processEvent(result, item, table);
            }
        }
        else
        {
            processEvent(result, data, table);
        }
    }
}

void Syscollector::processEvent(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table)
{
    nlohmann::json newData;

    newData = ecsData(result == MODIFIED ? data["new"] : data, table);

    const auto statefulToSend{newData.dump()};
    m_persistDiffFunction(statefulToSend);

    // Remove checksum from newData to avoid sending it in the diff
    if (newData.contains("checksum"))
    {
        newData.erase("checksum");
    }

    if (m_notify)
    {
        nlohmann::json stateless;
        nlohmann::json oldData;

        stateless["collector"] = table;
        stateless["module"] = "inventory";

        oldData = (result == MODIFIED) ? ecsData(data["old"], table, false) : nlohmann::json {};

        auto changedFields = addPreviousFields(newData, oldData);

        stateless["data"] = newData;
        stateless["data"]["event"]["changed_fields"] = changedFields;
        stateless["data"]["event"]["created"] = Utils::getCurrentISO8601();
        stateless["data"]["event"]["type"] = OPERATION_MAP.at(result);

        const auto statelessToSend{stateless.dump()};
        m_reportDiffFunction(statelessToSend);
        m_logFunction(LOG_DEBUG_VERBOSE, "Delta sent: " + statelessToSend);
    }
}

void Syscollector::updateChanges(const std::string& table,
                                 const nlohmann::json& values)
{
    const auto callback
    {
        [this, table](ReturnTypeCallback result, const nlohmann::json & data)
        {
            notifyChange(result, data, table);
        }
    };
    DBSyncTxn txn
    {
        m_spDBSync->handle(),
        nlohmann::json{table},
        0,
        QUEUE_SIZE,
        callback
    };
    nlohmann::json input;
    input["table"] = table;
    input["data"] = values;
    input["options"]["return_old_data"] = true;

    txn.syncTxnRow(input);
    txn.getDeletedRows(callback);
}

Syscollector::Syscollector()
    : m_intervalValue { 0 }
    , m_scanOnStart { false }
    , m_hardware { false }
    , m_os { false }
    , m_network { false }
    , m_packages { false }
    , m_ports { false }
    , m_portsAll { false }
    , m_processes { false }
    , m_hotfixes { false }
    , m_stopping { true }
    , m_notify { false }
    , m_groups { false }
    , m_users { false }
{}

std::string Syscollector::getCreateStatement() const
{
    std::string ret;

    ret += OS_SQL_STATEMENT;
    ret += HW_SQL_STATEMENT;
    ret += PACKAGES_SQL_STATEMENT;
    ret += HOTFIXES_SQL_STATEMENT;
    ret += PROCESSES_SQL_STATEMENT;
    ret += PORTS_SQL_STATEMENT;
    ret += NETIFACE_SQL_STATEMENT;
    ret += NETPROTO_SQL_STATEMENT;
    ret += NETADDR_SQL_STATEMENT;
    ret += GROUPS_SQL_STATEMENT;
    ret += USERS_SQL_STATEMENT;
    return ret;
}


void Syscollector::init(const std::shared_ptr<ISysInfo>& spInfo,
                        const std::function<void(const std::string&)> reportDiffFunction,
                        const std::function<void(const std::string&)> persistDiffFunction,
                        const std::function<void(const modules_log_level_t, const std::string&)> logFunction,
                        const std::string& dbPath,
                        const std::string& normalizerConfigPath,
                        const std::string& normalizerType,
                        const unsigned int interval,
                        const bool scanOnStart,
                        const bool hardware,
                        const bool os,
                        const bool network,
                        const bool packages,
                        const bool ports,
                        const bool portsAll,
                        const bool processes,
                        const bool hotfixes,
                        const bool groups,
                        const bool users,
                        const bool notifyOnFirstScan)
{
    m_spInfo = spInfo;
    m_reportDiffFunction = std::move(reportDiffFunction);
    m_persistDiffFunction = std::move(persistDiffFunction);
    m_logFunction = std::move(logFunction);
    m_intervalValue = interval;
    m_scanOnStart = scanOnStart;
    m_hardware = hardware;
    m_os = os;
    m_network = network;
    m_packages = packages;
    m_ports = ports;
    m_portsAll = portsAll;
    m_processes = processes;
    m_hotfixes = hotfixes;
    m_notify = notifyOnFirstScan;
    m_groups = groups;
    m_users = users;

    auto dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, dbPath, getCreateStatement(), DbManagement::PERSISTENT);
    auto normalizer = std::make_unique<SysNormalizer>(normalizerConfigPath, normalizerType);

    std::unique_lock<std::mutex> lock{m_mutex};
    m_stopping = false;

    m_spDBSync      = std::move(dbSync);
    m_spNormalizer  = std::move(normalizer);

    syncLoop(lock);
}

void Syscollector::destroy()
{
    std::unique_lock<std::mutex> lock{m_mutex};
    m_stopping = true;
    m_cv.notify_all();
    lock.unlock();
}

nlohmann::json Syscollector::ecsData(const nlohmann::json& data, const std::string& table, bool createFields)
{
    nlohmann::json ret;

    if (table == OS_TABLE)
    {
        ret = ecsSystemData(data, createFields);
    }
    else if (table == HW_TABLE)
    {
        ret = ecsHardwareData(data, createFields);
    }
    else if (table == HOTFIXES_TABLE)
    {
        ret = ecsHotfixesData(data, createFields);
    }
    else if (table == PACKAGES_TABLE)
    {
        ret = ecsPackageData(data, createFields);
    }
    else if (table == PROCESSES_TABLE)
    {
        ret = ecsProcessesData(data, createFields);
    }
    else if (table == PORTS_TABLE)
    {
        ret = ecsPortData(data, createFields);
    }
    else if (table == NET_IFACE_TABLE)
    {
        ret = ecsNetworkInterfaceData(data, createFields);
    }
    else if (table == NET_PROTOCOL_TABLE)
    {
        ret = ecsNetworkProtocolData(data, createFields);
    }
    else if (table == NET_ADDRESS_TABLE)
    {
        ret = ecsNetworkAddressData(data, createFields);
    }
    else if (table == USERS_TABLE)
    {
        ret = ecsUsersData(data, createFields);
    }
    else if (table == GROUPS_TABLE)
    {
        ret = ecsGroupsData(data, createFields);
    }

    if (createFields)
    {
        setJsonField(ret, data, "/checksum/hash/sha1", "checksum", std::nullopt, true);
    }

    return ret;
}

nlohmann::json Syscollector::ecsSystemData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/host/architecture", "architecture", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/hostname", "hostname", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/os/build", "os_build", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/os/codename", "os_codename", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/os/distribution/release", "os_distribution_release", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/os/full", "os_full", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/os/kernel/name", "os_kernel_name", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/os/kernel/release", "os_kernel_release", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/os/kernel/version", "os_kernel_version", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/os/major", "os_major", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/os/minor", "os_minor", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/os/name", "os_name", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/os/patch", "os_patch", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/os/platform", "os_platform", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/os/version", "os_version", std::nullopt, createFields);

    return ret;
}

nlohmann::json Syscollector::ecsHardwareData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/host/cpu/cores", "cpu_cores", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/cpu/name", "cpu_name", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/cpu/speed", "cpu_speed", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/memory/free", "memory_free", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/memory/total", "memory_total", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/memory/used", "memory_used", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/serial_number", "serial_number", std::nullopt, createFields);

    return ret;
}

nlohmann::json Syscollector::ecsHotfixesData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/package/hotfix/name", "hotfix_name", std::nullopt, createFields);

    return ret;
}

nlohmann::json Syscollector::ecsPackageData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/package/architecture", "architecture", std::nullopt, createFields);
    setJsonField(ret, originalData, "/package/category", "category", std::nullopt, createFields);
    setJsonField(ret, originalData, "/package/description", "description", std::nullopt, createFields);
    setJsonField(ret, originalData, "/package/installed", "installed", std::nullopt, createFields);
    setJsonField(ret, originalData, "/package/multiarch", "multiarch", std::nullopt, createFields);
    setJsonField(ret, originalData, "/package/name", "name", std::nullopt, createFields);
    setJsonField(ret, originalData, "/package/path", "path", std::nullopt, createFields);
    setJsonField(ret, originalData, "/package/priority", "priority", std::nullopt, createFields);
    setJsonField(ret, originalData, "/package/size", "size", std::nullopt, createFields);
    setJsonField(ret, originalData, "/package/source", "source", std::nullopt, createFields);
    setJsonField(ret, originalData, "/package/type", "type", std::nullopt, createFields);
    setJsonField(ret, originalData, "/package/vendor", "vendor", std::nullopt, createFields);
    setJsonField(ret, originalData, "/package/version", "version", std::nullopt, createFields);

    return ret;
}

nlohmann::json Syscollector::ecsProcessesData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonFieldArray(ret, originalData, "/process/args", "args", createFields);
    setJsonField(ret, originalData, "/process/args_count", "args_count", std::nullopt, createFields);
    setJsonField(ret, originalData, "/process/command_line", "command_line", std::nullopt, createFields);
    setJsonField(ret, originalData, "/process/name", "name", std::nullopt, createFields);
    setJsonField(ret, originalData, "/process/parent/pid", "parent_pid", std::nullopt, createFields);
    setJsonField(ret, originalData, "/process/pid", "pid", std::nullopt, createFields);
    setJsonField(ret, originalData, "/process/start", "start", std::nullopt, createFields);
    setJsonField(ret, originalData, "/process/state", "state", std::nullopt, createFields);
    setJsonField(ret, originalData, "/process/stime", "stime", std::nullopt, createFields);
    setJsonField(ret, originalData, "/process/utime", "utime", std::nullopt, createFields);

    return ret;
}

nlohmann::json Syscollector::ecsPortData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/destination/ip", "destination_ip", std::nullopt, createFields);
    setJsonField(ret, originalData, "/destination/port", "destination_port", std::nullopt, createFields);
    setJsonField(ret, originalData, "/file/inode", "file_inode", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/network/egress/queue", "host_network_egress_queue", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/network/ingress/queue", "host_network_ingress_queue", std::nullopt, createFields);
    setJsonField(ret, originalData, "/interface/state", "interface_state", std::nullopt, createFields);
    setJsonField(ret, originalData, "/network/transport", "network_transport", std::nullopt, createFields);
    setJsonField(ret, originalData, "/process/name", "process_name", std::nullopt, createFields);
    setJsonField(ret, originalData, "/process/pid", "process_pid", std::nullopt, createFields);
    setJsonField(ret, originalData, "/source/ip", "source_ip", std::nullopt, createFields);
    setJsonField(ret, originalData, "/source/port", "source_port", std::nullopt, createFields);

    return ret;
}

nlohmann::json Syscollector::ecsNetworkInterfaceData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonFieldArray(ret, originalData, "/host/mac", "host_mac", createFields);
    setJsonField(ret, originalData, "/host/network/ingress/bytes", "host_network_ingress_bytes", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/network/ingress/drops", "host_network_ingress_drops", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/network/ingress/errors", "host_network_ingress_errors", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/network/ingress/packets", "host_network_ingress_packages", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/network/egress/bytes", "host_network_egress_bytes", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/network/egress/drops", "host_network_egress_drops", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/network/egress/errors", "host_network_egress_errors", std::nullopt, createFields);
    setJsonField(ret, originalData, "/host/network/egress/packets", "host_network_egress_packages", std::nullopt, createFields);
    setJsonField(ret, originalData, "/interface/alias", "interface_alias", std::nullopt, createFields);
    setJsonField(ret, originalData, "/interface/mtu", "interface_mtu", std::nullopt, createFields);
    setJsonField(ret, originalData, "/interface/name", "interface_name", std::nullopt, createFields);
    setJsonField(ret, originalData, "/interface/state", "interface_state", std::nullopt, createFields);
    setJsonField(ret, originalData, "/interface/type", "interface_type", std::nullopt, createFields);

    return ret;
}

nlohmann::json Syscollector::ecsNetworkProtocolData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/interface/name", "interface_name", std::nullopt, createFields);
    setJsonField(ret, originalData, "/network/dhcp", "network_dhcp", std::nullopt, createFields);
    setJsonField(ret, originalData, "/network/gateway", "network_gateway", std::nullopt, createFields);
    setJsonField(ret, originalData, "/network/metric", "network_metric", std::nullopt, createFields);
    setJsonField(ret, originalData, "/network/type", "network_type", std::nullopt, createFields);

    return ret;
}

nlohmann::json Syscollector::ecsNetworkAddressData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/interface/name", "interface_name", std::nullopt, createFields);
    setJsonField(ret, originalData, "/network/broadcast", "network_broadcast", std::nullopt, createFields);
    setJsonField(ret, originalData, "/network/ip", "network_ip", std::nullopt, createFields);
    setJsonField(ret, originalData, "/network/netmask", "network_netmask", std::nullopt, createFields);
    setJsonField(ret, originalData, "/network/protocol", "network_protocol", std::nullopt, createFields);

    return ret;
}

nlohmann::json Syscollector::ecsUsersData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonFieldArray(ret, originalData, "/host/ip", "host_ip", createFields);
    setJsonField(ret, originalData, "/login/status", "login_status", std::nullopt, createFields);
    setJsonField(ret, originalData, "/login/tty", "login_tty", std::nullopt, createFields);
    setJsonField(ret, originalData, "/login/type", "login_type", std::nullopt, createFields);
    setJsonField(ret, originalData, "/process/pid", "process_pid", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/auth_failures/count", "user_auth_failed_count", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/auth_failures/timestamp", "user_auth_failed_timestamp", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/created", "user_created", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/full_name", "user_full_name", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/group/id", "user_group_id", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/group/id_signed", "user_group_id_signed", std::nullopt, createFields);
    setJsonFieldArray(ret, originalData, "/user/groups", "user_groups", createFields);
    setJsonField(ret, originalData, "/user/home", "user_home", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/id", "user_id", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/is_hidden", "user_is_hidden", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/is_remote", "user_is_remote", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/last_login", "user_last_login", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/name", "user_name", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/password/expiration_date", "user_password_expiration_date", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/password/hash_algorithm", "user_password_hash_algorithm", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/password/inactive_days", "user_password_inactive_days", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/password/last_change", "user_password_last_change", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/password/max_days_between_changes", "user_password_max_days_between_changes", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/password/min_days_between_changes", "user_password_min_days_between_changes", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/password/status", "user_password_status", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/password/warning_days_before_expiration", "user_password_warning_days_before_expiration", std::nullopt, createFields);
    setJsonFieldArray(ret, originalData, "/user/roles", "user_roles", createFields);
    setJsonField(ret, originalData, "/user/shell", "user_shell", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/type", "user_type", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/uid_signed", "user_uid_signed", std::nullopt, createFields);
    setJsonField(ret, originalData, "/user/uuid", "user_uuid", std::nullopt, createFields);

    return ret;
}

nlohmann::json Syscollector::ecsGroupsData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/group/description", "group_description", std::nullopt, createFields);
    setJsonField(ret, originalData, "/group/id", "group_id", std::nullopt, createFields);
    setJsonField(ret, originalData, "/group/id_signed", "group_id_signed", std::nullopt, createFields);
    setJsonField(ret, originalData, "/group/is_hidden", "group_is_hidden", std::nullopt, createFields);
    setJsonField(ret, originalData, "/group/name", "group_name", std::nullopt, createFields);
    setJsonFieldArray(ret, originalData, "/group/users", "group_users", createFields);
    setJsonField(ret, originalData, "/group/uuid", "group_uuid", std::nullopt, createFields);

    return ret;
}

nlohmann::json Syscollector::getHardwareData()
{
    nlohmann::json ret;
    ret[0] = m_spInfo->hardware();
    sanitizeJsonValue(ret[0]);
    ret[0]["checksum"] = getItemChecksum(ret[0]);
    return ret;
}

void Syscollector::scanHardware()
{
    if (m_hardware)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting hardware scan");
        const auto& hwData{getHardwareData()};
        updateChanges(HW_TABLE, hwData);
        m_logFunction(LOG_DEBUG_VERBOSE, "Ending hardware scan");
    }
}

nlohmann::json Syscollector::getOSData()
{
    nlohmann::json ret;
    ret[0] = m_spInfo->os();
    sanitizeJsonValue(ret[0]);
    ret[0]["checksum"] = getItemChecksum(ret[0]);
    return ret;
}

void Syscollector::scanOs()
{
    if (m_os)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting os scan");
        const auto& osData{getOSData()};
        updateChanges(OS_TABLE, osData);
        m_logFunction(LOG_DEBUG_VERBOSE, "Ending os scan");
    }
}

nlohmann::json Syscollector::getNetworkData()
{
    nlohmann::json ret;
    auto networks = m_spInfo->networks();
    nlohmann::json ifaceTableDataList {};
    nlohmann::json protoTableDataList {};
    nlohmann::json addressTableDataList {};
    constexpr auto IPV4 { 0 };
    constexpr auto IPV6 { 1 };
    static const std::map<int, std::string> IP_TYPE
    {
        { IPV4, "ipv4" },
        { IPV6, "ipv6" }
    };

    if (!networks.is_null())
    {
        sanitizeJsonValue(networks);
        const auto& itIface { networks.find("iface") };

        if (networks.end() != itIface)
        {
            for (const auto& item : itIface.value())
            {
                // Split the resulting networks data into the specific DB tables
                // "dbsync_network_iface" table data to update and notify
                nlohmann::json ifaceTableData {};
                ifaceTableData["interface_name"]                = item.at("interface_name");
                ifaceTableData["interface_alias"]               = item.at("interface_alias");
                ifaceTableData["interface_type"]                = item.at("interface_type");
                ifaceTableData["interface_state"]               = item.at("interface_state");
                ifaceTableData["interface_mtu"]                 = item.at("interface_mtu");
                ifaceTableData["host_mac"]                      = item.at("host_mac");
                ifaceTableData["host_network_egress_packages"]  = item.at("host_network_egress_packages");
                ifaceTableData["host_network_ingress_packages"] = item.at("host_network_ingress_packages");
                ifaceTableData["host_network_egress_errors"]    = item.at("host_network_egress_errors");
                ifaceTableData["host_network_ingress_errors"]   = item.at("host_network_ingress_errors");
                ifaceTableData["host_network_egress_bytes"]     = item.at("host_network_egress_bytes");
                ifaceTableData["host_network_ingress_bytes"]    = item.at("host_network_ingress_bytes");
                ifaceTableData["host_network_egress_drops"]     = item.at("host_network_egress_drops");
                ifaceTableData["host_network_ingress_drops"]    = item.at("host_network_ingress_drops");
                ifaceTableData["checksum"]                      = getItemChecksum(ifaceTableData);
                ifaceTableDataList.push_back(std::move(ifaceTableData));

                if (item.find("IPv4") != item.end())
                {
                    // "dbsync_network_protocol" table data to update and notify
                    nlohmann::json protoTableData {};
                    protoTableData["interface_name"]  = item.at("interface_name");
                    protoTableData["network_gateway"] = item.at("network_gateway");
                    protoTableData["network_type"]    = IP_TYPE.at(IPV4);
                    protoTableData["network_dhcp"]    = item.at("IPv4").begin()->at("network_dhcp");
                    protoTableData["network_metric"]  = item.at("IPv4").begin()->at("network_metric");
                    protoTableData["checksum"]        = getItemChecksum(protoTableData);
                    protoTableDataList.push_back(std::move(protoTableData));

                    for (auto addressTableData : item.at("IPv4"))
                    {
                        // "dbsync_network_address" table data to update and notify
                        addressTableData["interface_name"]   = item.at("interface_name");
                        addressTableData["network_protocol"] = IPV4;
                        addressTableData["checksum"]         = getItemChecksum(addressTableData);
                        // Remove unwanted fields for dbsync_network_address table
                        addressTableData.erase("network_dhcp");
                        addressTableData.erase("network_metric");

                        addressTableDataList.push_back(std::move(addressTableData));
                    }
                }

                if (item.find("IPv6") != item.end())
                {
                    // "dbsync_network_protocol" table data to update and notify
                    nlohmann::json protoTableData {};
                    protoTableData["interface_name"]  = item.at("interface_name");
                    protoTableData["network_gateway"] = item.at("network_gateway");
                    protoTableData["network_type"]    = IP_TYPE.at(IPV6);
                    protoTableData["network_dhcp"]    = item.at("IPv6").begin()->at("network_dhcp");
                    protoTableData["network_metric"]  = item.at("IPv6").begin()->at("network_metric");
                    protoTableData["checksum"]        = getItemChecksum(protoTableData);
                    protoTableDataList.push_back(std::move(protoTableData));

                    for (auto addressTableData : item.at("IPv6"))
                    {
                        // "dbsync_network_address" table data to update and notify
                        addressTableData["interface_name"]   = item.at("interface_name");
                        addressTableData["network_protocol"] = IPV6;
                        addressTableData["checksum"]         = getItemChecksum(addressTableData);
                        // Remove unwanted fields for dbsync_network_address table
                        addressTableData.erase("network_dhcp");
                        addressTableData.erase("network_metric");

                        addressTableDataList.push_back(std::move(addressTableData));
                    }
                }
            }

            ret[NET_IFACE_TABLE] = std::move(ifaceTableDataList);
            ret[NET_PROTOCOL_TABLE] = std::move(protoTableDataList);
            ret[NET_ADDRESS_TABLE] = std::move(addressTableDataList);
        }
    }

    return ret;
}

void Syscollector::scanNetwork()
{
    if (m_network)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting network scan");
        const auto networkData(getNetworkData());

        if (!networkData.is_null())
        {
            const auto itIface { networkData.find(NET_IFACE_TABLE) };

            if (itIface != networkData.end())
            {
                updateChanges(NET_IFACE_TABLE, itIface.value());
            }

            const auto itProtocol { networkData.find(NET_PROTOCOL_TABLE) };

            if (itProtocol != networkData.end())
            {
                updateChanges(NET_PROTOCOL_TABLE, itProtocol.value());
            }

            const auto itAddress { networkData.find(NET_ADDRESS_TABLE) };

            if (itAddress != networkData.end())
            {
                updateChanges(NET_ADDRESS_TABLE, itAddress.value());
            }
        }

        m_logFunction(LOG_DEBUG_VERBOSE, "Ending network scan");
    }
}

void Syscollector::scanPackages()
{
    if (m_packages)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting packages scan");
        const auto callback
        {
            [this](ReturnTypeCallback result, const nlohmann::json & data)
            {
                notifyChange(result, data, PACKAGES_TABLE);
            }
        };
        DBSyncTxn txn
        {
            m_spDBSync->handle(),
            nlohmann::json{PACKAGES_TABLE},
            0,
            QUEUE_SIZE,
            callback
        };
        m_spInfo->packages([this, &txn](nlohmann::json & rawData)
        {
            nlohmann::json input;

            sanitizeJsonValue(rawData);
            rawData["checksum"] = getItemChecksum(rawData);

            input["table"] = PACKAGES_TABLE;
            m_spNormalizer->normalize("packages", rawData);
            m_spNormalizer->removeExcluded("packages", rawData);

            if (!rawData.empty())
            {
                input["data"] = nlohmann::json::array( { rawData } );
                input["options"]["return_old_data"] = true;

                txn.syncTxnRow(input);
            }
        });
        txn.getDeletedRows(callback);

        m_logFunction(LOG_DEBUG_VERBOSE, "Ending packages scan");
    }
}

void Syscollector::scanHotfixes()
{
    if (m_hotfixes)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting hotfixes scan");
        auto hotfixes = m_spInfo->hotfixes();

        if (!hotfixes.is_null())
        {
            sanitizeJsonValue(hotfixes);

            for (auto& hotfix : hotfixes)
            {
                hotfix["checksum"] = getItemChecksum(hotfix);
            }

            updateChanges(HOTFIXES_TABLE, hotfixes);
        }

        m_logFunction(LOG_DEBUG_VERBOSE, "Ending hotfixes scan");
    }
}

nlohmann::json Syscollector::getPortsData()
{
    nlohmann::json ret;
    constexpr auto PORT_LISTENING_STATE { "listening" };
    constexpr auto TCP_PROTOCOL { "tcp" };
    constexpr auto UDP_PROTOCOL { "udp" };
    auto data(m_spInfo->ports());

    const std::vector<std::string> PORTS_ITEM_ID_FIELDS {"file_inode", "network_transport", "source_ip", "source_port"};

    if (!data.is_null())
    {
        sanitizeJsonValue(data);

        for (auto& item : data)
        {
            const auto protocol { item.at("network_transport").get_ref<const std::string&>() };

            if (Utils::startsWith(protocol, TCP_PROTOCOL))
            {
                // All ports.
                if (m_portsAll)
                {
                    const auto& itemId { getItemId(item, PORTS_ITEM_ID_FIELDS) };

                    if (!isElementDuplicated(ret, std::make_pair("item_id", itemId)))
                    {
                        item["checksum"] = getItemChecksum(item);
                        item["item_id"] = itemId;
                        ret.push_back(item);
                    }
                }
                else
                {
                    // Only listening ports.
                    const auto isListeningState { item.at("interface_state") == PORT_LISTENING_STATE };

                    if (isListeningState)
                    {
                        const auto& itemId { getItemId(item, PORTS_ITEM_ID_FIELDS) };

                        if (!isElementDuplicated(ret, std::make_pair("item_id", itemId)))
                        {
                            item["checksum"] = getItemChecksum(item);
                            item["item_id"] = itemId;
                            ret.push_back(item);
                        }
                    }
                }
            }
            else if (Utils::startsWith(protocol, UDP_PROTOCOL))
            {
                const auto& itemId { getItemId(item, PORTS_ITEM_ID_FIELDS) };

                if (!isElementDuplicated(ret, std::make_pair("item_id", itemId)))
                {
                    item["checksum"] = getItemChecksum(item);
                    item["item_id"] = itemId;
                    ret.push_back(item);
                }
            }
        }
    }

    return ret;
}

nlohmann::json Syscollector::getGroupsData()
{
    nlohmann::json ret;
    auto data = m_spInfo->groups();

    if (!data.is_null())
    {
        for (auto& item : data)
        {
            item["checksum"] = getItemChecksum(item);
            ret.push_back(item);
        }
    }

    return ret;
}

nlohmann::json Syscollector::getUsersData()
{
    auto allUsers = m_spInfo->users();

    for (auto& user : allUsers)
    {
        user["checksum"] = getItemChecksum(user);
    }

    return allUsers;
}

void Syscollector::scanPorts()
{
    if (m_ports)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting ports scan");
        const auto& portsData { getPortsData() };
        updateChanges(PORTS_TABLE, portsData);
        m_logFunction(LOG_DEBUG_VERBOSE, "Ending ports scan");
    }
}

void Syscollector::scanProcesses()
{
    if (m_processes)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting processes scan");
        const auto callback
        {
            [this](ReturnTypeCallback result, const nlohmann::json & data)
            {
                notifyChange(result, data, PROCESSES_TABLE);
            }
        };
        DBSyncTxn txn
        {
            m_spDBSync->handle(),
            nlohmann::json{PROCESSES_TABLE},
            0,
            QUEUE_SIZE,
            callback
        };
        m_spInfo->processes([&txn](nlohmann::json & rawData)
        {
            nlohmann::json input;

            sanitizeJsonValue(rawData);
            rawData["checksum"] = getItemChecksum(rawData);

            input["table"] = PROCESSES_TABLE;
            input["data"] = nlohmann::json::array( { rawData } );
            input["options"]["return_old_data"] = true;

            txn.syncTxnRow(input);
        });
        txn.getDeletedRows(callback);

        m_logFunction(LOG_DEBUG_VERBOSE, "Ending processes scan");
    }
}

void Syscollector::scanGroups()
{
    if (m_groups)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting groups scan");
        const auto& groupsData { getGroupsData() };
        updateChanges(GROUPS_TABLE, groupsData);
        m_logFunction(LOG_DEBUG_VERBOSE, "Ending groups scan");
    }
}

void Syscollector::scanUsers()
{
    if (m_users)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting users scan");
        const auto& usersData { getUsersData() };
        updateChanges(USERS_TABLE, usersData);
        m_logFunction(LOG_DEBUG_VERBOSE, "Ending users scan");
    }
}

void Syscollector::scan()
{
    m_logFunction(LOG_INFO, "Starting evaluation.");
    TRY_CATCH_TASK(scanHardware);
    TRY_CATCH_TASK(scanOs);
    TRY_CATCH_TASK(scanNetwork);
    TRY_CATCH_TASK(scanPackages);
    TRY_CATCH_TASK(scanHotfixes);
    TRY_CATCH_TASK(scanPorts);
    TRY_CATCH_TASK(scanProcesses);
    TRY_CATCH_TASK(scanGroups);
    TRY_CATCH_TASK(scanUsers);
    m_notify = true;
    m_logFunction(LOG_INFO, "Evaluation finished.");
}

void Syscollector::syncLoop(std::unique_lock<std::mutex>& lock)
{
    m_logFunction(LOG_INFO, "Module started.");

    if (m_scanOnStart)
    {
        scan();
    }

    while (!m_cv.wait_for(lock, std::chrono::seconds{m_intervalValue}, [&]()
{
    return m_stopping;
}))
    {
        scan();
    }
    m_spDBSync.reset(nullptr);
}

std::string Syscollector::getPrimaryKeys([[maybe_unused]] const nlohmann::json& data, const std::string& table)
{
    std::string ret;

    if (table == OS_TABLE)
    {
        ret = data["os_name"];
    }
    else if (table == HW_TABLE)
    {
        ret = data["serial_number"];
    }
    else if (table == HOTFIXES_TABLE)
    {
        ret = data["hotfix_name"];
    }
    else if (table == PACKAGES_TABLE)
    {
        ret = data["name"].get<std::string>() + ":" + data["version"].get<std::string>() + ":" +
              data["architecture"].get<std::string>() + ":" + data["type"].get<std::string>() + ":" +
              data["path"].get<std::string>();
    }
    else if (table == PROCESSES_TABLE)
    {
        ret = data["pid"];
    }
    else if (table == PORTS_TABLE)
    {
        ret = std::to_string(data["file_inode"].get<int>()) + ":" + data["network_transport"].get<std::string>() + ":" +
              data["source_ip"].get<std::string>() + ":" + std::to_string(data["source_port"].get<int>());
    }
    else if (table == NET_IFACE_TABLE)
    {
        ret = data["interface_name"].get<std::string>() + ":" + data["interface_alias"].get<std::string>() + ":" +
              data["interface_type"].get<std::string>();
    }
    else if (table == NET_PROTOCOL_TABLE)
    {
        ret = data["interface_name"].get<std::string>() + ":" + data["network_type"].get<std::string>();
    }
    else if (table == NET_ADDRESS_TABLE)
    {
        ret = data["interface_name"].get<std::string>() + ":" + std::to_string(data["network_protocol"].get<int>()) + ":" +
              data["network_ip"].get<std::string>();
    }
    else if (table == USERS_TABLE)
    {
        ret = data["user_name"];
    }
    else if (table == GROUPS_TABLE)
    {
        ret = data["group_name"];
    }

    return ret;
}

std::string Syscollector::calculateHashId(const nlohmann::json& data, const std::string& table)
{
    const std::string primaryKey = getPrimaryKeys(data, table);

    Utils::HashData hash(Utils::HashType::Sha1);
    hash.update(primaryKey.c_str(), primaryKey.size());

    return Utils::asciiToHex(hash.hash());
}

nlohmann::json Syscollector::addPreviousFields(nlohmann::json& current, const nlohmann::json& previous)
{
    using JsonPair = std::pair<nlohmann::json*, const nlohmann::json*>;
    using PathPair = std::pair<std::string, JsonPair>;

    std::stack<PathPair> stack;
    nlohmann::json modifiedKeys = nlohmann::json::array();

    stack.emplace("", JsonPair(&current, &previous));

    while (!stack.empty())
    {
        auto [path, pair] = stack.top();
        auto [curr, prev] = pair;
        stack.pop();

        for (auto& [key, value] : prev->items())
        {
            std::string currentPath = path;

            if (!path.empty())
            {
                currentPath.append(".").append(key);
            }
            else
            {
                currentPath = key;
            }

            if (curr->contains(key))
            {
                if ((*curr)[key].is_object() && value.is_object())
                {
                    stack.emplace(currentPath, JsonPair(&((*curr)[key]), &value));
                }
                else if ((*curr)[key] != value)
                {
                    modifiedKeys.push_back(currentPath);

                    size_t dotPos = currentPath.find('.');
                    std::string topLevelKey = (dotPos != std::string::npos) ? currentPath.substr(0, dotPos) : currentPath;

                    if (!current[topLevelKey].contains("previous"))
                    {
                        current[topLevelKey]["previous"] = nlohmann::json::object();
                    }

                    if (dotPos != std::string::npos)
                    {
                        std::string relativePath = currentPath.substr(dotPos + 1);
                        nlohmann::json::json_pointer pointer("/" + std::regex_replace(relativePath, std::regex("\\."), "/"));
                        current[topLevelKey]["previous"][pointer] = value;
                    }
                    else
                    {
                        current[topLevelKey]["previous"][key] = value;
                    }
                }
            }
        }
    }

    return modifiedKeys;
}

void Syscollector::setJsonField(nlohmann::json& target,
                                const nlohmann::json& source,
                                const std::string& keyPath,
                                const std::string& jsonKey,
                                const std::optional<std::string>& defaultValue,
                                bool createFields)
{
    if (createFields || source.contains(jsonKey))
    {
        const nlohmann::json::json_pointer pointer(keyPath);

        if (source.contains(jsonKey) && source[jsonKey] != EMPTY_VALUE && source[jsonKey] != UNKNOWN_VALUE)
        {
            target[pointer] = source[jsonKey];
        }
        else if (defaultValue.has_value())
        {
            target[pointer] = *defaultValue;
        }
        else
        {
            target[pointer] = nullptr;
        }
    }
}

void Syscollector::setJsonFieldArray(nlohmann::json& target,
                                     const nlohmann::json& source,
                                     const std::string& destPath,
                                     const std::string& sourceKey,
                                     bool createFields)
{
    if (createFields || source.contains(sourceKey))
    {
        const nlohmann::json::json_pointer destPointer(destPath);
        target[destPointer] = nullptr;

        if (source.contains(sourceKey) && !source[sourceKey].is_null() && source[sourceKey] != EMPTY_VALUE && source[sourceKey] != UNKNOWN_VALUE)
        {
            const auto& value = source[sourceKey];
            target[destPointer] = nlohmann::json::array();
            target[destPointer].push_back(value);
        }
    }
}
