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
#include <chrono>

#include "syscollectorTablesDef.hpp"
#include "agent_sync_protocol.hpp"
#include "logging_helper.h"
#include "../../module_query_errors.h"

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
    // LCOV_EXCL_STOP
};

static const std::map<ReturnTypeCallback, Operation_t> OPERATION_STATES_MAP
{
    // LCOV_EXCL_START
    {MODIFIED, OPERATION_MODIFY},
    {DELETED, OPERATION_DELETE},
    {INSERTED, OPERATION_CREATE},
    // LCOV_EXCL_STOP
};

static const std::map<std::string, std::string> INDEX_MAP
{
    // LCOV_EXCL_START
    {OS_TABLE, SYSCOLLECTOR_SYNC_INDEX_SYSTEM},
    {HW_TABLE, SYSCOLLECTOR_SYNC_INDEX_HARDWARE},
    {HOTFIXES_TABLE, SYSCOLLECTOR_SYNC_INDEX_HOTFIXES},
    {PACKAGES_TABLE, SYSCOLLECTOR_SYNC_INDEX_PACKAGES},
    {PROCESSES_TABLE, SYSCOLLECTOR_SYNC_INDEX_PROCESSES},
    {PORTS_TABLE, SYSCOLLECTOR_SYNC_INDEX_PORTS},
    {NET_IFACE_TABLE, SYSCOLLECTOR_SYNC_INDEX_INTERFACES},
    {NET_PROTOCOL_TABLE, SYSCOLLECTOR_SYNC_INDEX_PROTOCOLS},
    {NET_ADDRESS_TABLE, SYSCOLLECTOR_SYNC_INDEX_NETWORKS},
    {USERS_TABLE, SYSCOLLECTOR_SYNC_INDEX_USERS},
    {GROUPS_TABLE, SYSCOLLECTOR_SYNC_INDEX_GROUPS},
    {SERVICES_TABLE, SYSCOLLECTOR_SYNC_INDEX_SERVICES},
    {BROWSER_EXTENSIONS_TABLE, SYSCOLLECTOR_SYNC_INDEX_BROWSER_EXTENSIONS},
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
    nlohmann::json aux = result == MODIFIED && data.contains("new") ? data["new"] : data;

    auto [newData, version] = ecsData(aux, table);

    const auto statefulToSend{newData.dump()};
    auto indexIt = INDEX_MAP.find(table);

    if (indexIt != INDEX_MAP.end())
    {
        m_persistDiffFunction(calculateHashId(aux, table), OPERATION_STATES_MAP.at(result), indexIt->second, statefulToSend, version);
    }

    // Remove checksum and state from newData to avoid sending them in the diff
    if (newData.contains("checksum"))
    {
        newData.erase("checksum");
    }

    if (newData.contains("state"))
    {
        newData.erase("state");
    }

    if (m_notify)
    {
        nlohmann::json stateless;

        stateless["collector"] = table;
        stateless["module"] = "inventory";

        auto [oldData, oldVersion] = (result == MODIFIED) ? ecsData(data["old"], table, false) : std::make_pair(nlohmann::json{}, uint64_t(0));

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
            if (result == INSERTED || result == MODIFIED || result == DELETED)
            {
                notifyChange(result, data, table);
            }
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
    , m_initialized { false }
    , m_notify { false }
    , m_groups { false }
    , m_users { false }
    , m_services { false }
    , m_browserExtensions { false }
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
    ret += SERVICES_SQL_STATEMENT;
    ret += BROWSER_EXTENSIONS_SQL_STATEMENT;
    return ret;
}


void Syscollector::init(const std::shared_ptr<ISysInfo>& spInfo,
                        const std::function<void(const std::string&)> reportDiffFunction,
                        const std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> persistDiffFunction,
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
                        const bool services,
                        const bool browserExtensions,
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
    m_services = services;
    m_browserExtensions = browserExtensions;

    auto dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, dbPath, getCreateStatement(), DbManagement::PERSISTENT);
    auto normalizer = std::make_unique<SysNormalizer>(normalizerConfigPath, normalizerType);

    m_spDBSync      = std::move(dbSync);
    m_spNormalizer  = std::move(normalizer);
    m_initialized   = true;

}

void Syscollector::start()
{
    std::unique_lock<std::mutex> lock{m_mutex};

    // Don't start if initialization failed
    if (!m_initialized)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Cannot start Syscollector - module initialization failed");
        }

        return;
    }

    m_stopping = false;

    // Reset sync protocol stop flag to allow restarting operations
    if (m_spSyncProtocol)
    {
        m_spSyncProtocol->reset();
    }

    syncLoop(lock);
}

void Syscollector::destroy()
{
    std::unique_lock<std::mutex> lock{m_mutex};
    m_stopping = true;
    m_cv.notify_all();
    lock.unlock();

    // Signal sync protocol to stop any ongoing operations
    if (m_spSyncProtocol)
    {
        m_spSyncProtocol->stop();
    }

    // Explicitly release DBSync before static destructors run
    // This prevents use-after-free when Syscollector singleton destructs
    // after DBSyncImplementation singleton has already been destroyed
    m_spDBSync.reset();
}

std::pair<nlohmann::json, uint64_t> Syscollector::ecsData(const nlohmann::json& data, const std::string& table, bool createFields)
{
    nlohmann::json ret;
    uint64_t document_version = 0;

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
    else if (table == SERVICES_TABLE)
    {
        ret = ecsServicesData(data, createFields);
    }
    else if (table == BROWSER_EXTENSIONS_TABLE)
    {
        ret = ecsBrowserExtensionsData(data, createFields);
    }

    if (createFields)
    {
        setJsonField(ret, data, "/checksum/hash/sha1", "checksum", true);

        // Add state modified_at and version fields for stateful events only
        nlohmann::json state;
        state["modified_at"] = Utils::getCurrentISO8601();

        // Include document_version field in state for synchronization
        if (data.contains("version"))
        {
            document_version = data["version"].get<uint64_t>();
            state["document_version"] = document_version;
        }

        ret["state"] = state;
    }

    return {ret, document_version};
}

nlohmann::json Syscollector::ecsSystemData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/host/architecture", "architecture", createFields);
    setJsonField(ret, originalData, "/host/hostname", "hostname", createFields);
    setJsonField(ret, originalData, "/host/os/build", "os_build", createFields);
    setJsonField(ret, originalData, "/host/os/codename", "os_codename", createFields);
    setJsonField(ret, originalData, "/host/os/distribution/release", "os_distribution_release", createFields);
    setJsonField(ret, originalData, "/host/os/full", "os_full", createFields);
    setJsonField(ret, originalData, "/host/os/kernel/name", "os_kernel_name", createFields);
    setJsonField(ret, originalData, "/host/os/kernel/release", "os_kernel_release", createFields);
    setJsonField(ret, originalData, "/host/os/kernel/version", "os_kernel_version", createFields);
    setJsonField(ret, originalData, "/host/os/major", "os_major", createFields);
    setJsonField(ret, originalData, "/host/os/minor", "os_minor", createFields);
    setJsonField(ret, originalData, "/host/os/name", "os_name", createFields);
    setJsonField(ret, originalData, "/host/os/type", "os_type", createFields);
    setJsonField(ret, originalData, "/host/os/patch", "os_patch", createFields);
    setJsonField(ret, originalData, "/host/os/platform", "os_platform", createFields);
    setJsonField(ret, originalData, "/host/os/version", "os_version", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsHardwareData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/host/cpu/cores", "cpu_cores", createFields);
    setJsonField(ret, originalData, "/host/cpu/name", "cpu_name", createFields);
    setJsonField(ret, originalData, "/host/cpu/speed", "cpu_speed", createFields);
    setJsonField(ret, originalData, "/host/memory/free", "memory_free", createFields);
    setJsonField(ret, originalData, "/host/memory/total", "memory_total", createFields);
    setJsonField(ret, originalData, "/host/memory/used", "memory_used", createFields);
    setJsonField(ret, originalData, "/host/serial_number", "serial_number", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsHotfixesData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/package/hotfix/name", "hotfix_name", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsPackageData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/package/architecture", "architecture", createFields);
    setJsonField(ret, originalData, "/package/category", "category", createFields);
    setJsonField(ret, originalData, "/package/description", "description", createFields);
    setJsonField(ret, originalData, "/package/installed", "installed", createFields);
    setJsonField(ret, originalData, "/package/multiarch", "multiarch", createFields);
    setJsonField(ret, originalData, "/package/name", "name", createFields);
    setJsonField(ret, originalData, "/package/path", "path", createFields);
    setJsonField(ret, originalData, "/package/priority", "priority", createFields);
    setJsonField(ret, originalData, "/package/size", "size", createFields);
    setJsonField(ret, originalData, "/package/source", "source", createFields);
    setJsonField(ret, originalData, "/package/type", "type", createFields);
    setJsonField(ret, originalData, "/package/vendor", "vendor", createFields);
    setJsonField(ret, originalData, "/package/version", "version_", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsProcessesData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonFieldArray(ret, originalData, "/process/args", "args", createFields);
    setJsonField(ret, originalData, "/process/args_count", "args_count", createFields);
    setJsonField(ret, originalData, "/process/command_line", "command_line", createFields);
    setJsonField(ret, originalData, "/process/name", "name", createFields);
    setJsonField(ret, originalData, "/process/parent/pid", "parent_pid", createFields);
    setJsonField(ret, originalData, "/process/pid", "pid", createFields);
    setJsonField(ret, originalData, "/process/start", "start", createFields);
    setJsonField(ret, originalData, "/process/state", "state", createFields);
    setJsonField(ret, originalData, "/process/stime", "stime", createFields);
    setJsonField(ret, originalData, "/process/utime", "utime", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsPortData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/destination/ip", "destination_ip", createFields);
    setJsonField(ret, originalData, "/destination/port", "destination_port", createFields);
    setJsonField(ret, originalData, "/file/inode", "file_inode", createFields);
    setJsonField(ret, originalData, "/host/network/egress/queue", "host_network_egress_queue", createFields);
    setJsonField(ret, originalData, "/host/network/ingress/queue", "host_network_ingress_queue", createFields);
    setJsonField(ret, originalData, "/interface/state", "interface_state", createFields);
    setJsonField(ret, originalData, "/network/transport", "network_transport", createFields);
    setJsonField(ret, originalData, "/process/name", "process_name", createFields);
    setJsonField(ret, originalData, "/process/pid", "process_pid", createFields);
    setJsonField(ret, originalData, "/source/ip", "source_ip", createFields);
    setJsonField(ret, originalData, "/source/port", "source_port", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsNetworkInterfaceData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonFieldArray(ret, originalData, "/host/mac", "host_mac", createFields);
    setJsonField(ret, originalData, "/host/network/ingress/bytes", "host_network_ingress_bytes", createFields);
    setJsonField(ret, originalData, "/host/network/ingress/drops", "host_network_ingress_drops", createFields);
    setJsonField(ret, originalData, "/host/network/ingress/errors", "host_network_ingress_errors", createFields);
    setJsonField(ret, originalData, "/host/network/ingress/packets", "host_network_ingress_packages", createFields);
    setJsonField(ret, originalData, "/host/network/egress/bytes", "host_network_egress_bytes", createFields);
    setJsonField(ret, originalData, "/host/network/egress/drops", "host_network_egress_drops", createFields);
    setJsonField(ret, originalData, "/host/network/egress/errors", "host_network_egress_errors", createFields);
    setJsonField(ret, originalData, "/host/network/egress/packets", "host_network_egress_packages", createFields);
    setJsonField(ret, originalData, "/interface/alias", "interface_alias", createFields);
    setJsonField(ret, originalData, "/interface/mtu", "interface_mtu", createFields);
    setJsonField(ret, originalData, "/interface/name", "interface_name", createFields);
    setJsonField(ret, originalData, "/interface/state", "interface_state", createFields);
    setJsonField(ret, originalData, "/interface/type", "interface_type", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsNetworkProtocolData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/interface/name", "interface_name", createFields);
    setJsonField(ret, originalData, "/network/dhcp", "network_dhcp", createFields, true);
    setJsonField(ret, originalData, "/network/gateway", "network_gateway", createFields);
    setJsonField(ret, originalData, "/network/metric", "network_metric", createFields);
    setJsonField(ret, originalData, "/network/type", "network_type", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsNetworkAddressData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/interface/name", "interface_name", createFields);
    setJsonField(ret, originalData, "/network/broadcast", "network_broadcast", createFields);
    setJsonField(ret, originalData, "/network/ip", "network_ip", createFields);
    setJsonField(ret, originalData, "/network/netmask", "network_netmask", createFields);
    setJsonField(ret, originalData, "/network/type", "network_type", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsUsersData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonFieldArray(ret, originalData, "/host/ip", "host_ip", createFields);
    setJsonField(ret, originalData, "/login/status", "login_status", createFields, true);
    setJsonField(ret, originalData, "/login/tty", "login_tty", createFields);
    setJsonField(ret, originalData, "/login/type", "login_type", createFields);
    setJsonField(ret, originalData, "/process/pid", "process_pid", createFields);
    setJsonField(ret, originalData, "/user/auth_failures/count", "user_auth_failed_count", createFields);
    setJsonField(ret, originalData, "/user/auth_failures/timestamp", "user_auth_failed_timestamp", createFields);
    setJsonField(ret, originalData, "/user/created", "user_created", createFields);
    setJsonField(ret, originalData, "/user/full_name", "user_full_name", createFields);
    setJsonField(ret, originalData, "/user/group/id", "user_group_id", createFields);
    setJsonField(ret, originalData, "/user/group/id_signed", "user_group_id_signed", createFields);
    setJsonFieldArray(ret, originalData, "/user/groups", "user_groups", createFields);
    setJsonField(ret, originalData, "/user/home", "user_home", createFields);
    setJsonField(ret, originalData, "/user/id", "user_id", createFields);
    setJsonField(ret, originalData, "/user/is_hidden", "user_is_hidden", createFields, true);
    setJsonField(ret, originalData, "/user/is_remote", "user_is_remote", createFields, true);
    setJsonField(ret, originalData, "/user/last_login", "user_last_login", createFields);
    setJsonField(ret, originalData, "/user/name", "user_name", createFields);
    setJsonField(ret, originalData, "/user/password/expiration_date", "user_password_expiration_date", createFields);
    setJsonField(ret, originalData, "/user/password/hash_algorithm", "user_password_hash_algorithm", createFields);
    setJsonField(ret, originalData, "/user/password/inactive_days", "user_password_inactive_days", createFields);
    setJsonField(ret, originalData, "/user/password/last_change", "user_password_last_change", createFields);
    setJsonField(ret, originalData, "/user/password/max_days_between_changes", "user_password_max_days_between_changes", createFields);
    setJsonField(ret, originalData, "/user/password/min_days_between_changes", "user_password_min_days_between_changes", createFields);
    setJsonField(ret, originalData, "/user/password/status", "user_password_status", createFields);
    setJsonField(ret, originalData, "/user/password/warning_days_before_expiration", "user_password_warning_days_before_expiration", createFields);
    setJsonFieldArray(ret, originalData, "/user/roles", "user_roles", createFields);
    setJsonField(ret, originalData, "/user/shell", "user_shell", createFields);
    setJsonField(ret, originalData, "/user/type", "user_type", createFields);
    setJsonField(ret, originalData, "/user/uid_signed", "user_uid_signed", createFields);
    setJsonField(ret, originalData, "/user/uuid", "user_uuid", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsGroupsData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/group/description", "group_description", createFields);
    setJsonField(ret, originalData, "/group/id", "group_id", createFields);
    setJsonField(ret, originalData, "/group/id_signed", "group_id_signed", createFields);
    setJsonField(ret, originalData, "/group/is_hidden", "group_is_hidden", createFields, true);
    setJsonField(ret, originalData, "/group/name", "group_name", createFields);
    setJsonFieldArray(ret, originalData, "/group/users", "group_users", createFields);
    setJsonField(ret, originalData, "/group/uuid", "group_uuid", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsServicesData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/error/log/file/path", "error_log_file_path", createFields);
    setJsonField(ret, originalData, "/file/path", "file_path", createFields);
    setJsonField(ret, originalData, "/log/file/path", "log_file_path", createFields);
    setJsonFieldArray(ret, originalData, "/process/args", "process_args", createFields);
    setJsonField(ret, originalData, "/process/executable", "process_executable", createFields);
    setJsonField(ret, originalData, "/process/group/name", "process_group_name", createFields);
    setJsonField(ret, originalData, "/process/pid", "process_pid", createFields);
    setJsonField(ret, originalData, "/process/root_directory", "process_root_dir", createFields);
    setJsonField(ret, originalData, "/process/user/name", "process_user_name", createFields);
    setJsonField(ret, originalData, "/process/working_directory", "process_working_dir", createFields);
    setJsonField(ret, originalData, "/service/address", "service_address", createFields);
    setJsonField(ret, originalData, "/service/description", "service_description", createFields);
    setJsonField(ret, originalData, "/service/enabled", "service_enabled", createFields);
    setJsonField(ret, originalData, "/service/exit_code", "service_exit_code", createFields);
    setJsonField(ret, originalData, "/service/following", "service_following", createFields);
    setJsonField(ret, originalData, "/service/frequency", "service_frequency", createFields);
    setJsonField(ret, originalData, "/service/id", "service_id", createFields);
    setJsonField(ret, originalData, "/service/inetd_compatibility", "service_inetd_compatibility", createFields, true);
    setJsonField(ret, originalData, "/service/name", "service_name", createFields);
    setJsonField(ret, originalData, "/service/object_path", "service_object_path", createFields);
    setJsonField(ret, originalData, "/service/restart", "service_restart", createFields);
    setJsonField(ret, originalData, "/service/start_type", "service_start_type", createFields);
    setJsonField(ret, originalData, "/service/starts/on_mount", "service_starts_on_mount", createFields, true);
    setJsonFieldArray(ret, originalData, "/service/starts/on_not_empty_directory", "service_starts_on_not_empty_directory", createFields);
    setJsonFieldArray(ret, originalData, "/service/starts/on_path_modified", "service_starts_on_path_modified", createFields);
    setJsonField(ret, originalData, "/service/state", "service_state", createFields);
    setJsonField(ret, originalData, "/service/sub_state", "service_sub_state", createFields);
    setJsonField(ret, originalData, "/service/target/address", "service_target_address", createFields);
    setJsonField(ret, originalData, "/service/target/ephemeral_id", "service_target_ephemeral_id", createFields);
    setJsonField(ret, originalData, "/service/target/type", "service_target_type", createFields);
    setJsonField(ret, originalData, "/service/type", "service_type", createFields);
    setJsonField(ret, originalData, "/service/win32_exit_code", "service_win32_exit_code", createFields);

    return ret;
}

nlohmann::json Syscollector::ecsBrowserExtensionsData(const nlohmann::json& originalData, bool createFields)
{
    nlohmann::json ret;

    setJsonField(ret, originalData, "/browser/name", "browser_name", createFields);
    setJsonField(ret, originalData, "/browser/profile/name", "browser_profile_name", createFields);
    setJsonField(ret, originalData, "/browser/profile/path", "browser_profile_path", createFields);
    setJsonField(ret, originalData, "/browser/profile/referenced", "browser_profile_referenced", createFields, true);
    setJsonField(ret, originalData, "/file/hash/sha256", "file_hash_sha256", createFields);
    setJsonField(ret, originalData, "/package/autoupdate", "package_autoupdate", createFields, true);
    setJsonField(ret, originalData, "/package/build_version", "package_build_version", createFields);
    setJsonField(ret, originalData, "/package/description", "package_description", createFields);
    setJsonField(ret, originalData, "/package/enabled", "package_enabled", createFields, true);
    setJsonField(ret, originalData, "/package/from_webstore", "package_from_webstore", createFields, true);
    setJsonField(ret, originalData, "/package/id", "package_id", createFields);
    setJsonField(ret, originalData, "/package/installed", "package_installed", createFields);
    setJsonField(ret, originalData, "/package/name", "package_name", createFields);
    setJsonField(ret, originalData, "/package/path", "package_path", createFields);
    setJsonFieldArray(ret, originalData, "/package/permissions", "package_permissions", createFields);
    setJsonField(ret, originalData, "/package/persistent", "package_persistent", createFields, true);
    setJsonField(ret, originalData, "/package/reference", "package_reference", createFields);
    setJsonField(ret, originalData, "/package/type", "package_type", createFields);
    setJsonField(ret, originalData, "/package/vendor", "package_vendor", createFields);
    setJsonField(ret, originalData, "/package/version", "package_version_", createFields);
    setJsonField(ret, originalData, "/package/visible", "package_visible", createFields, true);
    setJsonField(ret, originalData, "/user/id", "user_id", createFields);

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
                        addressTableData["network_type"] = IPV4;
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
                        addressTableData["network_type"] = IPV6;
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

nlohmann::json Syscollector::getGroupsData()
{
    nlohmann::json ret;
    auto groups = m_spInfo->groups();

    if (!groups.is_null())
    {
        for (auto& group : groups)
        {
            sanitizeJsonValue(group);
            group["checksum"] = getItemChecksum(group);
            ret.push_back(std::move(group));
        }
    }

    return ret;
}

nlohmann::json Syscollector::getUsersData()
{
    nlohmann::json ret;
    auto users = m_spInfo->users();

    if (!users.is_null())
    {
        for (auto& user : users)
        {
            sanitizeJsonValue(user);
            user["checksum"] = getItemChecksum(user);
            ret.push_back(std::move(user));
        }
    }

    return ret;
}

nlohmann::json Syscollector::getServicesData()
{
    nlohmann::json ret;
    auto services = m_spInfo->services();

    if (!services.is_null())
    {
        for (auto& service : services)
        {
            sanitizeJsonValue(service);
            service["checksum"] = getItemChecksum(service);
            ret.push_back(std::move(service));
        }
    }

    return ret;
}

nlohmann::json Syscollector::getBrowserExtensionsData()
{
    nlohmann::json ret;
    auto extensions = m_spInfo->browserExtensions();

    if (!extensions.is_null())
    {
        for (auto& extension : extensions)
        {
            sanitizeJsonValue(extension);

            // Convert package_installed from string to integer for ECS compatibility
            if (extension.contains("package_installed") && extension["package_installed"].is_string())
            {
                try
                {
                    const auto& timestampStr = extension["package_installed"].get<std::string>();

                    if (!timestampStr.empty() && timestampStr != " " && timestampStr != "0")
                    {
                        int64_t timestamp = std::stoll(timestampStr);
                        extension["package_installed"] = timestamp;
                    }
                    else
                    {
                        extension["package_installed"] = nullptr;
                    }
                }
                catch (const std::exception&)
                {
                    extension["package_installed"] = nullptr;
                }
            }

            extension["checksum"] = getItemChecksum(extension);
            ret.push_back(std::move(extension));
        }
    }

    return ret;
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

void Syscollector::scanServices()
{
    if (m_services)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting services scan");
        const auto& servicesData { getServicesData() };
        updateChanges(SERVICES_TABLE, servicesData);
        m_logFunction(LOG_DEBUG_VERBOSE, "Ending services scan");
    }
}

void Syscollector::scanBrowserExtensions()
{
    if (m_browserExtensions)
    {
        m_logFunction(LOG_DEBUG_VERBOSE, "Starting browser extensions scan");
        const auto& extensionsData { getBrowserExtensionsData() };
        updateChanges(BROWSER_EXTENSIONS_TABLE, extensionsData);
        m_logFunction(LOG_DEBUG_VERBOSE, "Ending browser extensions scan");
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
    TRY_CATCH_TASK(scanServices);
    TRY_CATCH_TASK(scanBrowserExtensions);
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
        ret = data.contains("os_name") ? data["os_name"].get<std::string>() : "";
    }
    else if (table == HW_TABLE)
    {
        ret = data.contains("serial_number") ? data["serial_number"].get<std::string>() : "";
    }
    else if (table == HOTFIXES_TABLE)
    {
        ret = data.contains("hotfix_name") ? data["hotfix_name"].get<std::string>() : "";
    }
    else if (table == PACKAGES_TABLE)
    {
        std::string name = data.contains("name") ? data["name"].get<std::string>() : "";
        std::string version = data.contains("version_") ? data["version_"].get<std::string>() : "";
        std::string architecture = data.contains("architecture") ? data["architecture"].get<std::string>() : "";
        std::string type = data.contains("type") ? data["type"].get<std::string>() : "";
        std::string path = data.contains("path") ? data["path"].get<std::string>() : "";

        ret = name + ":" + version + ":" + architecture + ":" + type + ":" + path;
    }
    else if (table == PROCESSES_TABLE)
    {
        ret = data.contains("pid") ? data["pid"].get<std::string>() : "";
    }
    else if (table == PORTS_TABLE)
    {
        std::string file_inode = data.contains("file_inode") ? std::to_string(data["file_inode"].get<int>()) : "0";
        std::string transport = data.contains("network_transport") ? data["network_transport"].get<std::string>() : "";
        std::string source_ip = data.contains("source_ip") ? data["source_ip"].get<std::string>() : "";
        std::string source_port = data.contains("source_port") ? std::to_string(data["source_port"].get<int>()) : "0";

        ret = file_inode + ":" + transport + ":" + source_ip + ":" + source_port;
    }
    else if (table == NET_IFACE_TABLE)
    {
        std::string iface_name = data.contains("interface_name") ? data["interface_name"].get<std::string>() : "";
        std::string iface_alias = data.contains("interface_alias") ? data["interface_alias"].get<std::string>() : "";
        std::string iface_type = data.contains("interface_type") ? data["interface_type"].get<std::string>() : "";

        ret = iface_name + ":" + iface_alias + ":" + iface_type;
    }
    else if (table == NET_PROTOCOL_TABLE)
    {
        std::string iface_name = data.contains("interface_name") ? data["interface_name"].get<std::string>() : "";
        std::string net_type = data.contains("network_type") ? data["network_type"].get<std::string>() : "";

        ret = iface_name + ":" + net_type;
    }
    else if (table == NET_ADDRESS_TABLE)
    {
        std::string iface_name = data.contains("interface_name") ? data["interface_name"].get<std::string>() : "";
        std::string net_protocol = data.contains("network_type") ? std::to_string(data["network_type"].get<int>()) : "0";
        std::string net_ip = data.contains("network_ip") ? data["network_ip"].get<std::string>() : "";

        ret = iface_name + ":" + net_protocol + ":" + net_ip;
    }
    else if (table == USERS_TABLE)
    {
        ret = data.contains("user_name") ? data["user_name"].get<std::string>() : "";
    }
    else if (table == GROUPS_TABLE)
    {
        ret = data.contains("group_name") ? data["group_name"].get<std::string>() : "";
    }
    else if (table == SERVICES_TABLE)
    {
        std::string service_id = data.contains("service_id") ? data["service_id"].get<std::string>() : "";
        std::string file_path = data.contains("file_path") ? data["file_path"].get<std::string>() : "";

        ret = service_id + ":" + file_path;
    }
    else if (table == BROWSER_EXTENSIONS_TABLE)
    {
        std::string browser_name = data.contains("browser_name") ? data["browser_name"].get<std::string>() : "";
        std::string user_id = data.contains("user_id") ? data["user_id"].get<std::string>() : "";
        std::string browser_profile_path = data.contains("browser_profile_path") ? data["browser_profile_path"].get<std::string>() : "";
        std::string package_name = data.contains("package_name") ? data["package_name"].get<std::string>() : "";
        std::string package_version = data.contains("package_version_") ? data["package_version_"].get<std::string>() : "";

        ret = browser_name + ":" + user_id + ":" + browser_profile_path + ":" + package_name + ":" + package_version;
    }

    return ret;
}

std::string Syscollector::calculateHashId(const nlohmann::json& data, const std::string& table)
{
    const std::string primaryKey = table + ":" + getPrimaryKeys(data, table);

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
                                bool createFields,
                                bool is_boolean)
{
    if (createFields || source.contains(jsonKey))
    {
        const nlohmann::json::json_pointer pointer(keyPath);

        if (source.contains(jsonKey) && source[jsonKey] != EMPTY_VALUE && source[jsonKey] != UNKNOWN_VALUE)
        {
            if (is_boolean)
            {
                const auto& value = source[jsonKey];

                if (value.is_number())
                {
                    target[pointer] = (value.get<int>() != 0);
                }
                else if (value.is_string())
                {
                    const std::string strValue = value.get<std::string>();
                    target[pointer] = (strValue != "0");
                }
                else
                {
                    target[pointer] = value;
                }
            }
            else
            {
                target[pointer] = source[jsonKey];
            }
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

            // If the value is a string that contains commas, split it into multiple array elements
            if (value.is_string())
            {
                const auto valueStr = value.get<std::string>();
                const auto splitValues = Utils::split(valueStr, ',');

                for (const auto& splitValue : splitValues)
                {
                    const auto trimmedValue = Utils::trim(splitValue);

                    if (!trimmedValue.empty())
                    {
                        target[destPointer].push_back(trimmedValue);
                    }
                }
            }
            else
            {
                // For non-string values, add as single element
                target[destPointer].push_back(value);
            }
        }
    }
}

// Sync protocol methods implementation
void Syscollector::initSyncProtocol(const std::string& moduleName, const std::string& syncDbPath, MQ_Functions mqFuncs, std::chrono::seconds syncEndDelay, std::chrono::seconds timeout,
                                    unsigned int retries,
                                    size_t maxEps)
{
    auto logger_func = [this](modules_log_level_t level, const std::string & msg)
    {
        this->m_logFunction(level, msg);
    };

    try
    {
        m_spSyncProtocol = std::make_unique<AgentSyncProtocol>(moduleName, syncDbPath, mqFuncs, logger_func, syncEndDelay, timeout, retries, maxEps, nullptr);
        m_logFunction(LOG_INFO, "Syscollector sync protocol initialized successfully with database: " + syncDbPath);
    }
    catch (const std::exception& ex)
    {
        m_logFunction(LOG_ERROR, "Failed to initialize Syscollector sync protocol: " + std::string(ex.what()));
        // Re-throw to allow caller to handle
        throw;
    }
}

bool Syscollector::syncModule(Mode mode)
{
    if (m_spSyncProtocol)
    {
        return m_spSyncProtocol->synchronizeModule(mode);
    }

    return false;
}

void Syscollector::persistDifference(const std::string& id, Operation operation, const std::string& index, const std::string& data, uint64_t version)
{
    if (m_spSyncProtocol)
    {
        m_spSyncProtocol->persistDifference(id, operation, index, data, version);
    }
}

bool Syscollector::parseResponseBuffer(const uint8_t* data, size_t length)
{
    if (m_spSyncProtocol)
    {
        return m_spSyncProtocol->parseResponseBuffer(data, length);
    }

    return false;
}

bool Syscollector::notifyDataClean(const std::vector<std::string>& indices)
{
    if (m_spSyncProtocol)
    {
        return m_spSyncProtocol->notifyDataClean(indices);
    }

    return false;
}

void Syscollector::deleteDatabase()
{
    if (m_spSyncProtocol)
    {
        m_spSyncProtocol->deleteDatabase();
    }

    if (m_spDBSync)
    {
        m_spDBSync->closeAndDeleteDatabase();
    }
}

// LCOV_EXCL_START

// Excluded from code coverage as it is not the real implementation of the query method.
// This is just a placeholder to comply with the module interface requirements.
// The real implementation should be done in the future iterations.
std::string Syscollector::query(const std::string& jsonQuery)
{
    // Log the received query
    if (m_logFunction)
    {
        m_logFunction(LOG_DEBUG, "Received query: " + jsonQuery);
    }

    try
    {
        // Parse JSON command
        nlohmann::json query_json = nlohmann::json::parse(jsonQuery);

        if (!query_json.contains("command") || !query_json["command"].is_string())
        {
            nlohmann::json response;
            response["error"] = MQ_ERR_INVALID_PARAMS;
            response["message"] = MQ_MSG_INVALID_PARAMS;
            return response.dump();
        }

        std::string command = query_json["command"];
        nlohmann::json parameters = query_json.contains("parameters") ? query_json["parameters"] : nlohmann::json();

        // Log the command being executed
        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG, "Executing command: " + command);
        }

        nlohmann::json response;

        // Handle coordination commands with JSON responses
        if (command == "pause")
        {
            response["error"] = MQ_SUCCESS;
            response["message"] = "Syscollector module paused successfully";
            response["data"]["module"] = "syscollector";
            response["data"]["action"] = "pause";
        }
        else if (command == "flush")
        {
            response["error"] = MQ_SUCCESS;
            response["message"] = "Syscollector module flushed successfully";
            response["data"]["module"] = "syscollector";
            response["data"]["action"] = "flush";
        }
        else if (command == "get_version")
        {
            response["error"] = MQ_SUCCESS;
            response["message"] = "Syscollector version retrieved";
            response["data"]["version"] = 3;
        }
        else if (command == "set_version")
        {
            // Extract version from parameters
            int version = 0;

            if (parameters.is_object() && parameters.contains("version") && parameters["version"].is_number())
            {
                version = parameters["version"].get<int>();
            }

            response["error"] = MQ_SUCCESS;
            response["message"] = "Syscollector version set successfully";
            response["data"]["version"] = version;
        }
        else if (command == "resume")
        {
            response["error"] = MQ_SUCCESS;
            response["message"] = "Syscollector module resumed successfully";
            response["data"]["module"] = "syscollector";
            response["data"]["action"] = "resume";
        }
        else
        {
            response["error"] = MQ_ERR_UNKNOWN_COMMAND;
            response["message"] = "Unknown Syscollector command: " + command;
            response["data"]["command"] = command;
        }

        return response.dump();
    }
    catch (const std::exception& ex)
    {
        nlohmann::json response;
        response["error"] = MQ_ERR_INTERNAL;
        response["message"] = "Exception parsing JSON or executing command: " + std::string(ex.what());

        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Query error: " + std::string(ex.what()));
        }

        return response.dump();
    }
}
// LCOV_EXCL_STOP
