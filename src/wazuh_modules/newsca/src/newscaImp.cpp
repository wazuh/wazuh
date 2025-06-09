/*
 * Wazuh NewSca
 * Copyright (C) 2015, Wazuh Inc.
 * October 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "hashHelper.h"
#include "json.hpp"
#include "newsca.h"
#include "newsca.hpp"
#include "stringHelper.h"
#include "timeHelper.h"
#include <iostream>

#define TRY_CATCH_TASK(task)                                                                                           \
    do                                                                                                                 \
    {                                                                                                                  \
        try                                                                                                            \
        {                                                                                                              \
            if (!m_stopping)                                                                                           \
            {                                                                                                          \
                task();                                                                                                \
            }                                                                                                          \
        }                                                                                                              \
        catch (const std::exception& ex)                                                                               \
        {                                                                                                              \
            if (m_logFunction)                                                                                         \
            {                                                                                                          \
                m_logFunction(LOG_ERROR, std::string {ex.what()});                                                     \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

constexpr auto QUEUE_SIZE {4096};

static const std::map<ReturnTypeCallback, std::string> OPERATION_MAP {
    // LCOV_EXCL_START
    {MODIFIED, "MODIFIED"},
    {DELETED, "DELETED"},
    {INSERTED, "INSERTED"},
    {MAX_ROWS, "MAX_ROWS"},
    {DB_ERROR, "DB_ERROR"},
    {SELECTED, "SELECTED"},
    // LCOV_EXCL_STOP
};

static const std::vector<std::string> NETADDRESS_ITEM_ID_FIELDS {"iface", "proto", "address"};

constexpr auto NET_IFACE_TABLE {"dbsync_network_iface"};
constexpr auto NET_PROTOCOL_TABLE {"dbsync_network_protocol"};
constexpr auto NET_ADDRESS_TABLE {"dbsync_network_address"};
constexpr auto PACKAGES_TABLE {"dbsync_packages"};
constexpr auto HOTFIXES_TABLE {"dbsync_hotfixes"};
constexpr auto PORTS_TABLE {"dbsync_ports"};
constexpr auto PROCESSES_TABLE {"dbsync_processes"};
constexpr auto OS_TABLE {"dbsync_osinfo"};
constexpr auto HW_TABLE {"dbsync_hwinfo"};

static std::string getItemId(const nlohmann::json& item, const std::vector<std::string>& idFields)
{
    Utils::HashData hash;

    for (const auto& field : idFields)
    {
        const auto& value {item.at(field)};

        if (value.is_string())
        {
            const auto& valueString {value.get<std::string>()};
            hash.update(valueString.c_str(), valueString.size());
        }
        else
        {
            const auto& valueNumber {value.get<unsigned long>()};
            const auto valueString {std::to_string(valueNumber)};
            hash.update(valueString.c_str(), valueString.size());
        }
    }
    return Utils::asciiToHex(hash.hash());
}

static void removeKeysWithEmptyValue(nlohmann::json& input)
{
    for (auto& data : input)
    {
        for (auto it = data.begin(); it != data.end();)
        {
            if (it.value().type() == nlohmann::detail::value_t::string &&
                it.value().get_ref<const std::string&>().empty())
            {
                it = data.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }
}

static bool isElementDuplicated(const nlohmann::json& input, const std::pair<std::string, std::string>& keyValue)
{
    const auto it {std::find_if(input.begin(),
                                input.end(),
                                [&keyValue](const auto& elem) { return elem.at(keyValue.first) == keyValue.second; })};
    return it != input.end();
}

void NewSca::notifyChange(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table)
{
    if (DB_ERROR == result)
    {
        m_logFunction(LOG_ERROR, data.dump());
    }
}

void NewSca::updateChanges(const std::string& table, const nlohmann::json& values)
{
    const auto callback {[this, table](ReturnTypeCallback result, const nlohmann::json& data)
                         {
                             notifyChange(result, data, table);
                         }};
    DBSyncTxn txn {m_spDBSync->handle(), nlohmann::json {table}, 0, QUEUE_SIZE, callback};
    nlohmann::json input;
    input["table"] = table;
    input["data"] = values;
    txn.syncTxnRow(input);
    txn.getDeletedRows(callback);
}

NewSca::NewSca()
    : m_intervalValue {0}
    , m_stopping {true}
{
}

std::string NewSca::getCreateStatement() const
{
    std::string ret = "SOME SQL STATEMENT";

    return ret;
}

void NewSca::init(const std::shared_ptr<ISysInfo>& spInfo,
                  const std::function<void(const std::string&)> reportDiffFunction,
                  const std::function<void(const std::string&)> reportSyncFunction,
                  const std::function<void(const modules_log_level_t, const std::string&)> logFunction,
                  const std::string& dbPath,
                  const std::string& normalizerConfigPath,
                  const std::string& normalizerType,
                  const unsigned int interval)
{
    m_spInfo = spInfo;
    m_reportDiffFunction = reportDiffFunction;
    m_reportSyncFunction = reportSyncFunction;
    m_logFunction = logFunction;
    m_intervalValue = interval;

    std::unique_lock<std::mutex> lock {m_mutex};
    m_stopping = false;
    m_spDBSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, dbPath, getCreateStatement());
    m_spRsync = std::make_unique<RemoteSync>();
    syncLoop(lock);
}

void NewSca::destroy()
{
    std::unique_lock<std::mutex> lock {m_mutex};
    m_stopping = true;
    m_cv.notify_all();
    lock.unlock();
}

void NewSca::syncLoop(std::unique_lock<std::mutex>& lock)
{
    m_logFunction(LOG_INFO, "Test Module Loop started.");

    while (!m_cv.wait_for(lock, std::chrono::seconds {m_intervalValue}, [&]() { return m_stopping; }))
    {
        m_logFunction(LOG_INFO, "Test Module doing its job.");
    }
    m_spRsync.reset(nullptr);
    m_spDBSync.reset(nullptr);
}

void NewSca::push(const std::string& data)
{
    std::unique_lock<std::mutex> lock {m_mutex};

    if (!m_stopping)
    {
        auto rawData {data};
        Utils::replaceFirst(rawData, "dbsync ", "");
        const auto buff {reinterpret_cast<const uint8_t*>(rawData.c_str())};

        try
        {
            m_spRsync->pushMessage(std::vector<uint8_t> {buff, buff + rawData.size()});
        }
        // LCOV_EXCL_START
        catch (const std::exception& ex)
        {
            m_logFunction(LOG_ERROR, ex.what());
        }
    }

    // LCOV_EXCL_STOP
}
