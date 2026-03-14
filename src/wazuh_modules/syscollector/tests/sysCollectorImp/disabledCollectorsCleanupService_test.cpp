/*
 * Wazuh Syscollector
 * Copyright (C) 2015, Wazuh Inc.
 * March 12, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "disabledCollectorsCleanupService.hpp"

#include "dbsync.hpp"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "iagent_sync_protocol.hpp"
#include "syscollector.h"
#include "syscollectorTablesDef.hpp"

#include <cstdio>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using ::testing::_;
using ::testing::ElementsAre;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;

namespace
{
    constexpr auto TEST_DB_PATH_SUCCESS {"disabledCollectorsCleanupService_success.db"};
    constexpr auto TEST_DB_PATH_FAILURE {"disabledCollectorsCleanupService_failure.db"};

    struct LogEntry
    {
        modules_log_level_t level;
        std::string message;
    };

    class LogCapture
    {
        public:
            void capture(const modules_log_level_t level, const std::string& message)
            {
                m_logs.push_back({level, message});
            }

            bool contains(const modules_log_level_t level, const std::string& messageSubstring) const
            {
                for (const auto& log : m_logs)
                {
                    if (log.level == level && log.message.find(messageSubstring) != std::string::npos)
                    {
                        return true;
                    }
                }

                return false;
            }

            size_t count(const modules_log_level_t level, const std::string& messageSubstring) const
            {
                size_t matches = 0;

                for (const auto& log : m_logs)
                {
                    if (log.level == level && log.message.find(messageSubstring) != std::string::npos)
                    {
                        ++matches;
                    }
                }

                return matches;
            }

        private:
            std::vector<LogEntry> m_logs;
    };

    class MockDBSync : public IDBSync
    {
        public:
            MOCK_METHOD(void, addTableRelationship, (const nlohmann::json& jsInput), (override));
            MOCK_METHOD(void, insertData, (const nlohmann::json& jsInsert), (override));
            MOCK_METHOD(void, setTableMaxRow, (const std::string& table, const long long maxRows), (override));
            MOCK_METHOD(void, syncRow, (const nlohmann::json& jsInput, ResultCallbackData callbackData), (override));
            MOCK_METHOD(void, selectRows, (const nlohmann::json& jsInput, ResultCallbackData callbackData), (override));
            MOCK_METHOD(void, deleteRows, (const nlohmann::json& jsInput), (override));
            MOCK_METHOD(void, updateWithSnapshot, (const nlohmann::json& jsInput, nlohmann::json& jsResult), (override));
            MOCK_METHOD(void, updateWithSnapshot, (const nlohmann::json& jsInput, ResultCallbackData callbackData), (override));
            MOCK_METHOD(DBSYNC_HANDLE, handle, (), (override));
            MOCK_METHOD(void, closeAndDeleteDatabase, (), (override));
            MOCK_METHOD(std::string, getConcatenatedChecksums, (const std::string& tableName), (override));
            MOCK_METHOD(std::string,
                        getConcatenatedChecksums,
                        (const std::string& tableName, const std::string& rowFilter),
                        (override));
            MOCK_METHOD(std::string, calculateTableChecksum, (const std::string& tableName), (override));
            MOCK_METHOD(std::string,
                        calculateTableChecksum,
                        (const std::string& tableName, const std::string& rowFilter),
                        (override));
            MOCK_METHOD(void, increaseEachEntryVersion, (const std::string& tableName), (override));
    };

    class MockAgentSyncProtocol : public IAgentSyncProtocol
    {
        public:
            MOCK_METHOD(void,
                        persistDifference,
                        (const std::string& id,
                         Operation operation,
                         const std::string& index,
                         const std::string& data,
                         uint64_t version,
                         bool isDataContext),
                        (override));
            MOCK_METHOD(void,
                        persistDifferenceInMemory,
                        (const std::string& id,
                         Operation operation,
                         const std::string& index,
                         const std::string& data,
                         uint64_t version),
                        (override));
            MOCK_METHOD(bool, synchronizeModule, (Mode mode, Option option), (override));
            MOCK_METHOD(bool, requiresFullSync, (const std::string& index, const std::string& checksum), (override));
            MOCK_METHOD(void, clearInMemoryData, (), (override));
            MOCK_METHOD(bool,
                        synchronizeMetadataOrGroups,
                        (Mode mode, const std::vector<std::string>& indices, uint64_t globalVersion),
                        (override));
            MOCK_METHOD(bool, notifyDataClean, (const std::vector<std::string>& indices, Option option), (override));
            MOCK_METHOD(bool, sendDataContextMessages, (uint64_t session, const std::vector<PersistedData>& data), (override));
            MOCK_METHOD(std::vector<PersistedData>, fetchPendingItems, (bool onlyDataValues), (override));
            MOCK_METHOD(void, clearAllDataContext, (), (override));
            MOCK_METHOD(void, deleteDatabase, (), (override));
            MOCK_METHOD(void, stop, (), (override));
            MOCK_METHOD(void, reset, (), (override));
            MOCK_METHOD(bool, shouldStop, (), (const, override));
            MOCK_METHOD(bool, parseResponseBuffer, (const uint8_t* data, size_t length), (override));
    };

    class DisabledCollectorsCleanupServiceTest : public ::testing::Test
    {
        protected:
            void SetUp() override
            {
                std::remove(TEST_DB_PATH_SUCCESS);
                std::remove(TEST_DB_PATH_FAILURE);
                DBSync::initialize([](const std::string&) {});
            }

            void TearDown() override
            {
                std::remove(TEST_DB_PATH_SUCCESS);
                std::remove(TEST_DB_PATH_FAILURE);
            }

            static DisabledCollectorsCleanupService::CollectorSelection allCollectorsDisabled()
            {
                return DisabledCollectorsCleanupService::CollectorSelection
                {
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false
                };
            }

            static int countRows(IDBSync& dbSync, const std::string& tableName)
            {
                int count = -1;
                auto query = SelectQuery::builder().table(tableName).columnList({"COUNT(*) AS count"}).build();
                const auto callback = [&count](ReturnTypeCallback returnType, const nlohmann::json & resultData)
                {
                    if (returnType == SELECTED && resultData.contains("count"))
                    {
                        count = resultData["count"].get<int>();
                    }
                };

                dbSync.selectRows(query.query(), callback);
                return count;
            }

            static std::unique_ptr<DBSync> createDatabase(const std::string& path, const std::string& schema)
            {
                return std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, path, schema, DbManagement::PERSISTENT);
            }

            static std::function<void(const modules_log_level_t, const std::string&)> logFunction(LogCapture& capture)
            {
                return [&capture](const modules_log_level_t level, const std::string & message)
                {
                    capture.capture(level, message);
                };
            }
    };
}

TEST_F(DisabledCollectorsCleanupServiceTest, RefreshDisabledIndicesTracksAllMappedIndicesAndNotifiesOnce)
{
    LogCapture logs;
    DisabledCollectorsCleanupService service {logFunction(logs)};
    NiceMock<MockDBSync> dbSync;
    NiceMock<MockAgentSyncProtocol> syncProtocol;
    const std::set<std::string> tablesWithData
    {
        HW_TABLE,
        OS_TABLE,
        PACKAGES_TABLE,
        HOTFIXES_TABLE,
        PROCESSES_TABLE,
        PORTS_TABLE,
        USERS_TABLE,
        GROUPS_TABLE,
        SERVICES_TABLE,
        BROWSER_EXTENSIONS_TABLE,
        NET_IFACE_TABLE,
        NET_PROTOCOL_TABLE,
        NET_ADDRESS_TABLE
    };

    ON_CALL(dbSync, selectRows(_, _))
    .WillByDefault(Invoke([&tablesWithData](const nlohmann::json & jsInput, ResultCallbackData callbackData)
    {
        const auto tableName = jsInput.at("table").get<std::string>();

        if (tablesWithData.find(tableName) != tablesWithData.end())
        {
            callbackData(SELECTED, nlohmann::json {{"count", 1}});
        }
    }));

    EXPECT_CALL(syncProtocol,
                notifyDataClean(
                    ElementsAre(
                        SYSCOLLECTOR_SYNC_INDEX_HARDWARE,
                        SYSCOLLECTOR_SYNC_INDEX_SYSTEM,
                        SYSCOLLECTOR_SYNC_INDEX_VULNERABILITIES,
                        SYSCOLLECTOR_SYNC_INDEX_PACKAGES,
                        SYSCOLLECTOR_SYNC_INDEX_HOTFIXES,
                        SYSCOLLECTOR_SYNC_INDEX_PROCESSES,
                        SYSCOLLECTOR_SYNC_INDEX_PORTS,
                        SYSCOLLECTOR_SYNC_INDEX_USERS,
                        SYSCOLLECTOR_SYNC_INDEX_GROUPS,
                        SYSCOLLECTOR_SYNC_INDEX_SERVICES,
                        SYSCOLLECTOR_SYNC_INDEX_BROWSER_EXTENSIONS,
                        SYSCOLLECTOR_SYNC_INDEX_INTERFACES,
                        SYSCOLLECTOR_SYNC_INDEX_PROTOCOLS,
                        SYSCOLLECTOR_SYNC_INDEX_NETWORKS),
                    Option::SYNC))
    .WillOnce(Return(true));

    service.refreshDisabledIndices(allCollectorsDisabled(), &dbSync);

    EXPECT_TRUE(service.hasDisabledData());
    EXPECT_TRUE(service.notifyDataClean(&syncProtocol));
    EXPECT_TRUE(logs.contains(LOG_INFO, "Disabled collectors indices with data detected"));
    EXPECT_TRUE(logs.contains(LOG_DEBUG, "Notifying DataClean for disabled collectors indices"));
    EXPECT_EQ(1U, logs.count(LOG_INFO, SYSCOLLECTOR_SYNC_INDEX_VULNERABILITIES));
}

TEST_F(DisabledCollectorsCleanupServiceTest, RefreshDisabledIndicesIgnoresNullInvalidAndUnexpectedSelectResults)
{
    LogCapture logs;
    DisabledCollectorsCleanupService service {logFunction(logs)};
    NiceMock<MockDBSync> dbSync;

    service.refreshDisabledIndices(allCollectorsDisabled(), nullptr);
    EXPECT_FALSE(service.hasDisabledData());

    ON_CALL(dbSync, selectRows(_, _))
    .WillByDefault(Invoke([](const nlohmann::json & jsInput, ResultCallbackData callbackData)
    {
        const auto tableName = jsInput.at("table").get<std::string>();

        if (tableName == HW_TABLE)
        {
            callbackData(INSERTED, nlohmann::json {{"count", 1}});
        }
        else if (tableName == PACKAGES_TABLE)
        {
            callbackData(SELECTED, nlohmann::json {{"count", "invalid"}});
        }
        else if (tableName == PROCESSES_TABLE)
        {
            callbackData(SELECTED, nlohmann::json::object());
        }
    }));

    const DisabledCollectorsCleanupService::CollectorSelection collectors
    {
        false,
        true,
        true,
        false,
        true,
        false,
        true,
        true,
        true,
        true,
        true
    };

    service.refreshDisabledIndices(collectors, &dbSync);

    EXPECT_FALSE(service.hasDisabledData());
    EXPECT_FALSE(logs.contains(LOG_INFO, "Disabled collectors indices with data detected"));
}

TEST_F(DisabledCollectorsCleanupServiceTest, NotifyDataCleanHandlesEmptyStateMissingProtocolAndExplicitClear)
{
    LogCapture logs;
    DisabledCollectorsCleanupService service {logFunction(logs)};
    NiceMock<MockDBSync> dbSync;

    EXPECT_TRUE(service.notifyDataClean(nullptr));
    EXPECT_TRUE(logs.contains(LOG_DEBUG, "No disabled collectors indices with data to notify for cleanup"));

    ON_CALL(dbSync, selectRows(_, _))
    .WillByDefault(Invoke([](const nlohmann::json & jsInput, ResultCallbackData callbackData)
    {
        if (jsInput.at("table").get<std::string>() == PACKAGES_TABLE)
        {
            callbackData(SELECTED, nlohmann::json {{"count", 1}});
        }
    }));

    const DisabledCollectorsCleanupService::CollectorSelection collectors
    {
        true,
        true,
        true,
        false,
        true,
        true,
        true,
        true,
        true,
        true,
        true
    };

    service.refreshDisabledIndices(collectors, &dbSync);

    EXPECT_TRUE(service.hasDisabledData());
    EXPECT_FALSE(service.notifyDataClean(nullptr));
    EXPECT_TRUE(logs.contains(LOG_ERROR, "Sync protocol not initialized, cannot notify data clean"));

    service.clearTrackedIndices();
    EXPECT_FALSE(service.hasDisabledData());
}

TEST_F(DisabledCollectorsCleanupServiceTest, RefreshDisabledIndicesLogsErrorsWhenSelectRowsThrows)
{
#ifdef WIN32
    GTEST_SKIP() << "Skipping RefreshDisabledIndicesLogsErrorsWhenSelectRowsThrows on Windows due to exception handling issues in Wine environment";
#endif
    LogCapture logs;
    DisabledCollectorsCleanupService service {logFunction(logs)};
    NiceMock<MockDBSync> dbSync;

    ON_CALL(dbSync, selectRows(_, _))
    .WillByDefault(Invoke([](const nlohmann::json&, ResultCallbackData)
    {
        throw std::runtime_error {"boom"};
    }));

    const DisabledCollectorsCleanupService::CollectorSelection collectors
    {
        true,
        true,
        true,
        false,
        true,
        true,
        true,
        true,
        true,
        true,
        true
    };

    service.refreshDisabledIndices(collectors, &dbSync);

    EXPECT_FALSE(service.hasDisabledData());
    EXPECT_TRUE(logs.contains(LOG_ERROR, "Error checking data in table dbsync_packages: boom"));
}

TEST_F(DisabledCollectorsCleanupServiceTest, RefreshDisabledIndicesAddsVulnerabilityIndexForHotfixesOnly)
{
    LogCapture logs;
    DisabledCollectorsCleanupService service {logFunction(logs)};
    NiceMock<MockDBSync> dbSync;
    NiceMock<MockAgentSyncProtocol> syncProtocol;

    ON_CALL(dbSync, selectRows(_, _))
    .WillByDefault(Invoke([](const nlohmann::json & jsInput, ResultCallbackData callbackData)
    {
        if (jsInput.at("table").get<std::string>() == HOTFIXES_TABLE)
        {
            callbackData(SELECTED, nlohmann::json {{"count", 1}});
        }
    }));

    EXPECT_CALL(syncProtocol,
                notifyDataClean(ElementsAre(SYSCOLLECTOR_SYNC_INDEX_HOTFIXES, SYSCOLLECTOR_SYNC_INDEX_VULNERABILITIES),
                                Option::SYNC))
    .WillOnce(Return(true));

    const DisabledCollectorsCleanupService::CollectorSelection collectors
    {
        true,
        true,
        true,
        true,
        true,
        true,
        false,
        true,
        true,
        true,
        true
    };

    service.refreshDisabledIndices(collectors, &dbSync);

    EXPECT_TRUE(service.hasDisabledData());
    EXPECT_TRUE(service.notifyDataClean(&syncProtocol));
}

TEST_F(DisabledCollectorsCleanupServiceTest, DeleteDisabledDataHandlesEmptyNullDbSyncAndNullHandle)
{
    LogCapture logs;
    NiceMock<MockDBSync> trackerDbSync;
    NiceMock<MockDBSync> nullHandleDbSync;

    ON_CALL(trackerDbSync, selectRows(_, _))
    .WillByDefault(Invoke([](const nlohmann::json & jsInput, ResultCallbackData callbackData)
    {
        if (jsInput.at("table").get<std::string>() == PACKAGES_TABLE)
        {
            callbackData(SELECTED, nlohmann::json {{"count", 1}});
        }
    }));

    ON_CALL(nullHandleDbSync, handle()).WillByDefault(Return(nullptr));

    DisabledCollectorsCleanupService emptyService {logFunction(logs)};
    emptyService.deleteDisabledData(nullptr);
    EXPECT_TRUE(logs.contains(LOG_DEBUG, "No disabled collectors indices with data to delete"));

    DisabledCollectorsCleanupService noDbSyncService {logFunction(logs)};
    DisabledCollectorsCleanupService nullHandleService {logFunction(logs)};
    const DisabledCollectorsCleanupService::CollectorSelection packagesDisabled
    {
        true,
        true,
        true,
        false,
        true,
        true,
        true,
        true,
        true,
        true,
        true
    };

    noDbSyncService.refreshDisabledIndices(packagesDisabled, &trackerDbSync);
    noDbSyncService.deleteDisabledData(nullptr);
    EXPECT_FALSE(noDbSyncService.hasDisabledData());

    nullHandleService.refreshDisabledIndices(packagesDisabled, &trackerDbSync);
    nullHandleService.deleteDisabledData(&nullHandleDbSync);
    EXPECT_FALSE(nullHandleService.hasDisabledData());
    EXPECT_EQ(2U, logs.count(LOG_INFO, "Deleting data for disabled collectors indices"));
}

TEST_F(DisabledCollectorsCleanupServiceTest, DeleteDisabledDataClearsTrackedTablesFromDatabase)
{
    LogCapture logs;
    DisabledCollectorsCleanupService service {logFunction(logs)};
    auto dbSync = createDatabase(TEST_DB_PATH_SUCCESS,
                                 std::string {PACKAGES_SQL_STATEMENT}
                                 + NETIFACE_SQL_STATEMENT
                                 + NETPROTO_SQL_STATEMENT
                                 + NETADDR_SQL_STATEMENT
                                 + TABLE_METADATA_SQL_STATEMENT);

    ASSERT_NO_THROW(dbSync->insertData(nlohmann::json::parse(R"(
        {"table":"dbsync_packages","data":[
            {"name":"pkg1","version_":"1.0","architecture":"x64","type":"deb","path":"/tmp/pkg1","checksum":"sum1"}
        ]})")));
    ASSERT_NO_THROW(dbSync->insertData(nlohmann::json::parse(R"(
        {"table":"dbsync_network_iface","data":[
            {"interface_name":"eth0","interface_alias":"main","interface_type":"ethernet","checksum":"sum2"}
        ]})")));
    ASSERT_NO_THROW(dbSync->insertData(nlohmann::json::parse(R"(
        {"table":"dbsync_network_protocol","data":[
            {"interface_name":"eth0","network_type":"ipv4","checksum":"sum3"}
        ]})")));
    ASSERT_NO_THROW(dbSync->insertData(nlohmann::json::parse(R"(
        {"table":"dbsync_network_address","data":[
            {"interface_name":"eth0","network_type":0,"network_ip":"10.0.0.1","checksum":"sum4"}
        ]})")));

    const DisabledCollectorsCleanupService::CollectorSelection collectors
    {
        true,
        true,
        false,
        false,
        true,
        true,
        true,
        true,
        true,
        true,
        true
    };

    service.refreshDisabledIndices(collectors, dbSync.get());
    service.deleteDisabledData(dbSync.get());

    EXPECT_FALSE(service.hasDisabledData());
    EXPECT_EQ(0, countRows(*dbSync, PACKAGES_TABLE));
    EXPECT_EQ(0, countRows(*dbSync, NET_IFACE_TABLE));
    EXPECT_EQ(0, countRows(*dbSync, NET_PROTOCOL_TABLE));
    EXPECT_EQ(0, countRows(*dbSync, NET_ADDRESS_TABLE));
    EXPECT_TRUE(logs.contains(LOG_DEBUG, "Cleared table dbsync_packages"));
    EXPECT_TRUE(logs.contains(LOG_DEBUG, "Cleared table dbsync_network_iface"));
    EXPECT_TRUE(logs.contains(LOG_DEBUG, "Cleared table dbsync_network_protocol"));
    EXPECT_TRUE(logs.contains(LOG_DEBUG, "Cleared table dbsync_network_address"));
}

TEST_F(DisabledCollectorsCleanupServiceTest, DeleteDisabledDataLogsErrorsWhenTableCannotBeCleared)
{
#ifdef WIN32
    GTEST_SKIP() << "Skipping DeleteDisabledDataLogsErrorsWhenTableCannotBeCleared on Windows due to DBSync cleanup error handling issues in Wine environment";
#endif
    LogCapture logs;
    DisabledCollectorsCleanupService service {logFunction(logs)};
    NiceMock<MockDBSync> trackerDbSync;
    auto dbSync = createDatabase(TEST_DB_PATH_FAILURE, TABLE_METADATA_SQL_STATEMENT);

    ON_CALL(trackerDbSync, selectRows(_, _))
    .WillByDefault(Invoke([](const nlohmann::json & jsInput, ResultCallbackData callbackData)
    {
        if (jsInput.at("table").get<std::string>() == PACKAGES_TABLE)
        {
            callbackData(SELECTED, nlohmann::json {{"count", 1}});
        }
    }));

    const DisabledCollectorsCleanupService::CollectorSelection collectors
    {
        true,
        true,
        true,
        false,
        true,
        true,
        true,
        true,
        true,
        true,
        true
    };

    service.refreshDisabledIndices(collectors, &trackerDbSync);
    service.deleteDisabledData(dbSync.get());

    EXPECT_FALSE(service.hasDisabledData());
    EXPECT_TRUE(logs.contains(LOG_ERROR, "Error clearing table dbsync_packages"));
}
