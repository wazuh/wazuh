/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/**
 * @file syscollector_baseline_tests.cpp
 * @brief What a collector switched off and back on reports, on both paths that report it.
 *
 * Inventory: switching a collector off empties its table, so the scan after switching it back on
 * inserts every item again. Those inserts are the inventory being rebuilt, not changes, and are
 * reported only when notify_first_scan asks for first-scan events -- while every other table keeps
 * reporting its real changes in that same scan.
 *
 * Vulnerabilities: switching os, packages or (on Windows) hotfixes off removes the agent's
 * vulnerabilities from the manager. When the lane comes back, they are rebuilt by one first-scan
 * session carrying the whole VD inventory, which the manager indexes without an alert each.
 */

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include <algorithm>
#include <cstdio>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "json.hpp"
#include "syscollector.hpp"
#include "syscollector.h"
#include "syscollectorTablesDef.hpp"
#include "agent_sync_protocol.hpp"
#include <sqlite3.h>
#include <mock_sysinfo.hpp>

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;

namespace
{
    constexpr auto BASELINE_DB_PATH {"syscollector_baseline_test.db"};

    constexpr auto ROOT_USER_JSON
    {
        R"({"host_ip":"192.168.0.84","login_status":0,"login_tty":"pts/0","login_type":"user","process_pid":"129870","user_auth_failed_count":0,"user_auth_failed_timestamp":0,"user_created":0,"user_full_name":"root","user_group_id":0,"user_group_id_signed":0,"user_groups":"root,adm,sudo","user_home":"/root","user_id":0,"user_is_hidden":0,"user_is_remote":1,"user_last_login":"1749605216","user_name":"root","user_password_expiration_date":-1,"user_password_hash_algorithm":"y","user_password_inactive_days":-1,"user_password_last_change":1745971200.0,"user_password_max_days_between_changes":99999,"user_password_min_days_between_changes":0,"user_password_status":"active","user_password_warning_days_before_expiration":7,"user_roles":"sudo","user_shell":"/bin/bash","user_type":null,"user_uid_signed":0,"user_uuid":null})"
    };

    constexpr auto SERVICE_JSON
    {
        R"({"service_id":"wazuh-agent","service_name":"Wazuh Agent","service_description":"Monitors system activity","service_state":"running","service_sub_state":"subState","service_start_type":"auto","service_type":"type","process_pid":1234,"service_exit_code":0,"service_win32_exit_code":0,"process_executable":"/usr/bin/wazuh-agent","service_address":"/lib/systemd/system/wazuh-agent.service","user_name":"root","service_enabled":"enabled","service_following":"following","service_object_path":"objectPath","service_target_ephemeral_id":0,"service_target_type":"jobType","service_target_address":"jobPath","file_path":"sourcePath"})"
    };

    /// @brief One user, or two when @p withNewUser: the second is the real change a scan reports.
    nlohmann::json usersData(bool withNewUser)
    {
        auto users = nlohmann::json::array({nlohmann::json::parse(ROOT_USER_JSON)});

        if (withNewUser)
        {
            auto alice = nlohmann::json::parse(ROOT_USER_JSON);
            alice["user_name"] = "alice";
            alice["user_full_name"] = "alice";
            alice["user_id"] = 1001;
            alice["user_home"] = "/home/alice";
            users.push_back(alice);
        }

        return users;
    }

    nlohmann::json servicesData()
    {
        return nlohmann::json::array({nlohmann::json::parse(SERVICE_JSON)});
    }

    class MockAgentSyncProtocol : public IAgentSyncProtocol
    {
        public:
            MOCK_METHOD(void, persistDifference,
                        (const std::string& id, Operation operation, const std::string& index,
                         const std::string& data, uint64_t version, bool isDataContext), (override));
            MOCK_METHOD(SyncModuleResult, synchronizeModule, (Mode mode, Option option), (override));
            MOCK_METHOD(IntegrityCheckResult, requiresFullSync, (const std::string& index, const std::string& checksum), (override));
            MOCK_METHOD(void, clearIntegrityProgress, (const std::string& index), (override));
            MOCK_METHOD(SyncModuleResult, synchronizeMetadataOrGroups,
                        (Mode mode, const std::vector<std::string>& indices, uint64_t globalVersion), (override));
            MOCK_METHOD(SyncModuleResult, notifyDataClean, (const std::vector<std::string>& indices, Option option, bool trackConsecutiveFailures), (override));
            MOCK_METHOD(bool, parseResponseBuffer, (const uint8_t* data, size_t length), (override));
            MOCK_METHOD(std::vector<PersistedData>, fetchPendingItems, (bool onlyDataValues), (override));
            MOCK_METHOD(void, clearAllDataContext, (), (override));
            MOCK_METHOD(void, deleteDatabase, (), (override));
            MOCK_METHOD(void, stop, (), (override));
            MOCK_METHOD(void, reset, (), (override));
            MOCK_METHOD(bool, shouldStop, (), (const, override));
    };

    SyncModuleResult okResult()
    {
        SyncModuleResult result;
        result.success = true;
        return result;
    }

    /// @brief A session that reached the manager: what the VD first-sync marker is gated on.
    SyncModuleResult sentResult()
    {
        SyncModuleResult result;
        result.success = true;
        result.sentAnything = true;
        return result;
    }
}

class SyscollectorBaselineTest : public ::testing::Test
{
    protected:
        /// @brief Collectors a case switches on. users and services are the two the inventory
        /// cases need: one that keeps reporting, one that is switched off and back on.
        struct Collectors
        {
            bool users {false};
            bool services {false};
            bool browserExtensions {false};
            bool os {false};
            bool packages {false};
        };

        void SetUp() override
        {
            std::remove(BASELINE_DB_PATH);
            s_reports.clear();
            s_persisted.clear();
        }

        void TearDown() override
        {
            Syscollector::instance().destroy();
            std::remove(BASELINE_DB_PATH);
        }

        static void initModule(const Collectors& collectors, const std::shared_ptr<MockSysInfo>& spInfo,
                               bool notifyOnFirstScan = false)
        {
            EXPECT_CALL(*spInfo, releaseThreadResources()).Times(::testing::AnyNumber());

            Syscollector::instance().init(spInfo,
                                          [](const std::string & report)
            {
                std::lock_guard<std::mutex> lock(s_mutex);
                s_reports.push_back(nlohmann::json::parse(report));
            },
            [](const std::string&, Operation_t, const std::string & index, const std::string&, uint64_t)
            {
                std::lock_guard<std::mutex> lock(s_mutex);
                ++s_persisted[index];
            },
            [](const modules_log_level_t, const std::string&) {},
            BASELINE_DB_PATH,
            "",
            "",
            3600,
            false,                          // scanOnStart
            false,                          // hardware
            collectors.os,                  // os
            false,                          // network
            collectors.packages,            // packages
            false,                          // ports
            false,                          // portsAll
            false,                          // processes
            false,                          // hotfixes
            false,                          // groups
            collectors.users,               // users
            collectors.services,            // services
            collectors.browserExtensions,   // browserExtensions
            notifyOnFirstScan);

            // The singleton outlives each case, and start(), which computes this, never runs here.
            Syscollector::instance().m_vdSyncEnabled = false;
        }

        /// @brief A host with one service, no browser extensions, and root -- plus alice when
        /// @p withNewUser.
        static std::shared_ptr<NiceMock<MockSysInfo>> makeSysInfo(bool withNewUser)
        {
            const auto spInfo {std::make_shared<NiceMock<MockSysInfo>>()};
            ON_CALL(*spInfo, users()).WillByDefault(Return(usersData(withNewUser)));
            ON_CALL(*spInfo, services()).WillByDefault(Return(servicesData()));
            ON_CALL(*spInfo, browserExtensions()).WillByDefault(Return(nlohmann::json::array()));
            return spInfo;
        }

        /// @brief Brings the module up with the given collectors and scans once.
        static void scanOnce(const Collectors& collectors, bool withNewUser, bool notifyOnFirstScan = false)
        {
            initModule(collectors, makeSysInfo(withNewUser), notifyOnFirstScan);
            Syscollector::instance().scan();
        }

        /// @brief The stateless reports of @p table, by event type.
        static std::map<std::string, int> reportsOf(const std::string& table)
        {
            std::lock_guard<std::mutex> lock(s_mutex);
            std::map<std::string, int> byType;

            for (const auto& report : s_reports)
            {
                if (report.at("collector") == table)
                {
                    ++byType[report.at("data").at("event").at("type").get<std::string>()];
                }
            }

            return byType;
        }

        static int persistedTo(const std::string& index)
        {
            std::lock_guard<std::mutex> lock(s_mutex);
            return s_persisted[index];
        }

        static void clearCaptures()
        {
            std::lock_guard<std::mutex> lock(s_mutex);
            s_reports.clear();
            s_persisted.clear();
        }

        static int64_t metadata(const std::string& key)
        {
            int64_t value = -1;
            EXPECT_TRUE(Syscollector::instance().getMetadataValue(key, value));
            return value;
        }

        static int64_t baseline(const std::string& table)
        {
            return metadata("scan_baseline:" + table);
        }

        /// @brief Runs a statement against the database while the module is down: DBSync keeps it
        /// open while the module is initialized, and refuses writes from outside with SQLITE_BUSY.
        static void execSql(const std::string& statement)
        {
            sqlite3* db = nullptr;
            ASSERT_EQ(sqlite3_open_v2(BASELINE_DB_PATH, &db, SQLITE_OPEN_READWRITE, nullptr), SQLITE_OK);

            char* errMsg = nullptr;
            ASSERT_EQ(sqlite3_exec(db, statement.c_str(), nullptr, nullptr, &errMsg), SQLITE_OK)
                    << (errMsg ? errMsg : "");

            if (errMsg)
            {
                sqlite3_free(errMsg);
            }

            sqlite3_close(db);
        }

        static void seedMetadata(const std::string& key, int64_t value)
        {
            execSql("INSERT OR REPLACE INTO table_metadata (table_name, last_sync_time) VALUES ('" + key + "', " +
                    std::to_string(value) + ");");
        }

        /// @brief Brings the VD collectors up with one OS row and the given metadata, without
        /// scanning, and with the VD lane in the state start() would compute for them.
        static void initVDModule(bool laneEnabled, const std::map<std::string, int64_t>& seeded)
        {
            const Collectors collectors {.os = true, .packages = true};

            initModule(collectors, std::make_shared<NiceMock<MockSysInfo>>());
            Syscollector::instance().destroy();

            execSql("INSERT OR REPLACE INTO dbsync_osinfo (hostname, architecture, os_name, os_version, "
                    "os_codename, os_major, os_minor, os_patch, os_platform, os_type, os_kernel_name, "
                    "os_kernel_release, os_kernel_version, sync, checksum, version) VALUES "
                    "('test-host', 'x86_64', 'Ubuntu', '22.04.2 LTS', 'jammy', '22', '04', '2', 'ubuntu', "
                    "'linux', 'Linux', '5.15.0-69-generic', '#76-Ubuntu', 1, 'seedchecksum', 1);");

            for (const auto& [key, value] : seeded)
            {
                seedMetadata(key, value);
            }

            initModule(collectors, std::make_shared<NiceMock<MockSysInfo>>());

            // start() computes it from the collectors; these cases do not run start(). os and
            // packages are on, so a disabled lane here stands for one with hotfixes off on Windows.
            Syscollector::instance().m_vdSyncEnabled = laneEnabled;
        }

        static std::mutex s_mutex;
        static std::vector<nlohmann::json> s_reports;
        static std::map<std::string, int> s_persisted;
};

std::mutex SyscollectorBaselineTest::s_mutex;
std::vector<nlohmann::json> SyscollectorBaselineTest::s_reports;
std::map<std::string, int> SyscollectorBaselineTest::s_persisted;

/// Declares plainProtocol / vdProtocol and publishes the mocks into the module. A macro because
/// FRIEND_TEST grants access to the test body, not to fixture members.
#define INJECT_MOCK_PROTOCOLS()                                                            \
    auto plainOwned = std::make_unique<NiceMock<MockAgentSyncProtocol>>();                 \
    auto vdOwned = std::make_unique<NiceMock<MockAgentSyncProtocol>>();                    \
    auto* plainProtocol = plainOwned.get();                                                \
    auto* vdProtocol = vdOwned.get();                                                      \
    Syscollector::instance().m_spSyncProtocol = std::move(plainOwned);                     \
    Syscollector::instance().m_spSyncProtocolVD = std::move(vdOwned);                      \
    (void)plainProtocol;                                                                   \
    (void)vdProtocol

// The reported case: services switched off, then back on. Its refill is not reported, while the
// users table, scanned in the same pass, still reports a user that really was added.
TEST_F(SyscollectorBaselineTest, ReenabledCollectorRefillsItsTableWithoutReporting)
{
    scanOnce({.users = true, .services = true}, false);
    Syscollector::instance().destroy();

    // Switched off: the start-up cleanup empties the table.
    scanOnce({.users = true, .services = false}, false);
    Syscollector::instance().deleteDisableCollectorsData();
    Syscollector::instance().destroy();
    clearCaptures();

    // Switched back on, while a user is added.
    scanOnce({.users = true, .services = true}, true);

    EXPECT_TRUE(reportsOf(SERVICES_TABLE).empty());
    EXPECT_EQ(reportsOf(USERS_TABLE)["created"], 1);

    // The refill still reaches the inventory: only the alert path is quiet.
    EXPECT_EQ(persistedTo(SYSCOLLECTOR_SYNC_INDEX_SERVICES), 1);
    EXPECT_GT(baseline(SERVICES_TABLE), 0);
}

// notify_first_scan asks for first-scan events, and a refill is one.
TEST_F(SyscollectorBaselineTest, ReenabledCollectorReportsWhenFirstScanEventsAreRequested)
{
    scanOnce({.users = true, .services = true}, false, true);
    Syscollector::instance().destroy();

    scanOnce({.users = true, .services = false}, false, true);
    Syscollector::instance().deleteDisableCollectorsData();
    Syscollector::instance().destroy();
    clearCaptures();

    scanOnce({.users = true, .services = true}, false, true);

    EXPECT_EQ(reportsOf(SERVICES_TABLE)["created"], 1);
    // users keeps its baseline, so nothing in it is reported as created. (The fixture's user
    // carries strings in integer columns, so DBSync reports that row as modified on every scan.)
    EXPECT_EQ(reportsOf(USERS_TABLE)["created"], 0);
}

// The same flood without any cleanup: a collector that was never on has an empty table, while the
// global first-scan marker says the device was scanned long ago.
TEST_F(SyscollectorBaselineTest, CollectorDisabledSinceInstallIsNotReportedWhenEnabled)
{
    scanOnce({.users = true, .services = false}, false);
    EXPECT_EQ(baseline(SERVICES_TABLE), 0);
    Syscollector::instance().destroy();
    clearCaptures();

    scanOnce({.users = true, .services = true}, true);

    EXPECT_TRUE(reportsOf(SERVICES_TABLE).empty());
    EXPECT_EQ(reportsOf(USERS_TABLE)["created"], 1);
    EXPECT_EQ(persistedTo(SYSCOLLECTOR_SYNC_INDEX_SERVICES), 1);
}

TEST_F(SyscollectorBaselineTest, CleanupClearsTheBaselineOfTheTablesItEmpties)
{
    scanOnce({.users = true, .services = true}, false);
    ASSERT_GT(baseline(SERVICES_TABLE), 0);
    const auto usersBaseline = baseline(USERS_TABLE);
    ASSERT_GT(usersBaseline, 0);
    Syscollector::instance().destroy();

    initModule({.users = true, .services = false}, std::make_shared<NiceMock<MockSysInfo>>());
    Syscollector::instance().deleteDisableCollectorsData();

    EXPECT_FALSE(Syscollector::instance().hasDataInTable(SERVICES_TABLE));
    EXPECT_EQ(baseline(SERVICES_TABLE), 0);
    EXPECT_EQ(baseline(USERS_TABLE), usersBaseline);
}

// A stop skips the tasks still to run. Their tables were not scanned, so they get no baseline.
TEST_F(SyscollectorBaselineTest, TaskSkippedByAStopLeavesItsTableWithoutBaseline)
{
    const auto spInfo {std::make_shared<NiceMock<MockSysInfo>>()};
    ON_CALL(*spInfo, users()).WillByDefault([]()
    {
        // users runs right before services.
        Syscollector::instance().m_stopping = true;
        return usersData(false);
    });
    EXPECT_CALL(*spInfo, services()).Times(0);

    initModule({.users = true, .services = true}, spInfo);
    Syscollector::instance().scan();
    Syscollector::instance().m_stopping = false;

    // users ran to the end: the collector does not watch the stop flag.
    EXPECT_GT(baseline(USERS_TABLE), 0);
    EXPECT_EQ(baseline(SERVICES_TABLE), 0);
}

TEST_F(SyscollectorBaselineTest, TaskThatThrowsLeavesItsTableWithoutBaseline)
{
#ifdef WIN32
    GTEST_SKIP() << "Skipping TaskThatThrowsLeavesItsTableWithoutBaseline test on Windows due to exception handling issues in Wine environment";
#endif
    const auto spInfo {std::make_shared<NiceMock<MockSysInfo>>()};
    ON_CALL(*spInfo, users()).WillByDefault(Return(usersData(false)));
    ON_CALL(*spInfo, services()).WillByDefault([]() -> nlohmann::json
    {
        throw std::runtime_error {"services collector failed"};
    });

    initModule({.users = true, .services = true}, spInfo);
    Syscollector::instance().scan();

    EXPECT_GT(baseline(USERS_TABLE), 0);
    EXPECT_EQ(baseline(SERVICES_TABLE), 0);
}

// The scan thread records baselines while the sync thread records its markers. Each write rewrites
// the whole table from its own snapshot, so without serialization one drops the other's key.
TEST_F(SyscollectorBaselineTest, ConcurrentMetadataWritesKeepEveryKey)
{
    initModule({.users = true}, std::make_shared<NiceMock<MockSysInfo>>());

    constexpr int WRITES {200};
    const auto writer = [](const std::string & key)
    {
        for (int i = 1; i <= WRITES; ++i)
        {
            Syscollector::instance().updateMetadataValue(key, i);
        }
    };

    std::thread scanThread {writer, "concurrent_scan_key"};
    std::thread syncThread {writer, "concurrent_sync_key"};
    scanThread.join();
    syncThread.join();

    EXPECT_EQ(metadata("concurrent_scan_key"), WRITES);
    EXPECT_EQ(metadata("concurrent_sync_key"), WRITES);
}

// With the lane disabled the VD tables go out as plain SYNC sessions, which build no
// vulnerabilities. Recording one would make the session after re-enabling go out as VDSYNC.
TEST_F(SyscollectorBaselineTest, SyncSessionDoesNotArmTheVDMarker)
{
    initVDModule(false, {});
    INJECT_MOCK_PROTOCOLS();
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, Option::SYNC)).WillOnce(Return(sentResult()));

    EXPECT_TRUE(Syscollector::instance().synchronizeVDTables(Mode::DELTA).success);
    EXPECT_FALSE(Syscollector::instance().isVDFirstSyncDone());
}

TEST_F(SyscollectorBaselineTest, FirstScanSessionArmsTheVDMarker)
{
    initVDModule(true, {});
    INJECT_MOCK_PROTOCOLS();
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, Option::VDFIRST)).WillOnce(Return(sentResult()));

    EXPECT_TRUE(Syscollector::instance().synchronizeVDTables(Mode::DELTA).success);
    EXPECT_TRUE(Syscollector::instance().isVDFirstSyncDone());
}

// Any start with the lane disabled -- the cleanup of the vulnerabilities, or an agent whose marker
// an earlier SYNC session armed -- leaves the lane to be resent as a first scan.
TEST_F(SyscollectorBaselineTest, DisabledLaneAtStartClearsTheVDMarkerAndHoldsTheLane)
{
    initVDModule(false, {{"vd_first_sync_completed", 1787900000}});

    Syscollector::instance().holdVDLaneForRearm();
    EXPECT_FALSE(Syscollector::instance().isVDFirstSyncDone());
    EXPECT_EQ(Syscollector::instance().vdLaneRearmState(), 1);

    // Every start with the lane still off finds it already held.
    Syscollector::instance().holdVDLaneForRearm();
    EXPECT_EQ(Syscollector::instance().vdLaneRearmState(), 1);
}

// Back on, before the inventory is requeued: the queue holds only what changed, so nothing is sent.
TEST_F(SyscollectorBaselineTest, PendingRearmHoldsTheVDSession)
{
    initVDModule(true, {{"vd_lane_rearm", 1}});
    INJECT_MOCK_PROTOCOLS();
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, _)).Times(0);

    const auto result = Syscollector::instance().synchronizeVDTables(Mode::DELTA);

    EXPECT_TRUE(result.success);
    EXPECT_TRUE(result.sessionSkipped);
    EXPECT_FALSE(Syscollector::instance().isVDFirstSyncDone());
}

// The scan after re-enabling refills what the cleanup removed; resent before it, the packages
// table would still be empty.
TEST_F(SyscollectorBaselineTest, RearmWaitsForACompleteScan)
{
    initVDModule(true, {{"vd_lane_rearm", 1}});
    INJECT_MOCK_PROTOCOLS();
    EXPECT_CALL(*vdProtocol, notifyDataClean(_, _, _)).Times(0);
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, _)).Times(0);
    EXPECT_CALL(*plainProtocol, synchronizeModule(_, _)).Times(0);

    Syscollector::instance().rearmVDLaneIfPending();

    EXPECT_EQ(Syscollector::instance().vdLaneRearmState(), 1);
}

// The marker is still armed here, as a stop between the two writes of holdVDLaneForRearm() leaves
// it: the re-arm clears it again, so the single session carrying the inventory is a first scan.
TEST_F(SyscollectorBaselineTest, RearmResendsTheVDInventoryAsOneFirstScan)
{
    initVDModule(true, {{"vd_lane_rearm", 1}, {"vd_first_sync_completed", 1787900000}});
    Syscollector::instance().m_vdLaneScanCompleted = true;
    INJECT_MOCK_PROTOCOLS();

    EXPECT_CALL(*vdProtocol, notifyDataClean(std::vector<std::string> {SYSCOLLECTOR_SYNC_INDEX_SYSTEM}, _, _))
    .WillOnce(Return(okResult()));
    EXPECT_CALL(*vdProtocol, notifyDataClean(std::vector<std::string> {SYSCOLLECTOR_SYNC_INDEX_PACKAGES}, _, _))
    .WillOnce(Return(okResult()));
    EXPECT_CALL(*vdProtocol, persistDifference(_, _, SYSCOLLECTOR_SYNC_INDEX_SYSTEM, _, _, _)).Times(1);
    EXPECT_CALL(*plainProtocol, synchronizeModule(_, _)).WillRepeatedly(Return(okResult()));
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, Option::VDSYNC)).Times(0);
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, Option::VDFIRST)).WillOnce(Return(sentResult()));

    Syscollector::instance().rearmVDLaneIfPending();

    EXPECT_TRUE(Syscollector::instance().isVDFirstSyncDone());
    EXPECT_EQ(Syscollector::instance().vdLaneRearmState(), 0);
}

// A table that could not be requeued keeps the lane held: the tables that were would otherwise
// leave without it.
TEST_F(SyscollectorBaselineTest, FailedRequeueKeepsTheRearmPending)
{
    initVDModule(true, {{"vd_lane_rearm", 1}});
    Syscollector::instance().m_vdLaneScanCompleted = true;
    INJECT_MOCK_PROTOCOLS();

    EXPECT_CALL(*vdProtocol, notifyDataClean(_, _, _)).WillRepeatedly(Return(SyncModuleResult {}));
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, _)).Times(0);

    Syscollector::instance().rearmVDLaneIfPending();

    EXPECT_EQ(Syscollector::instance().vdLaneRearmState(), 1);
    EXPECT_TRUE(Syscollector::instance().synchronizeVDTables(Mode::DELTA).sessionSkipped);
}

// A stop mid-requeue: nothing is sent and the next start requeues the lane from the beginning.
TEST_F(SyscollectorBaselineTest, StopDuringTheRearmKeepsItPending)
{
    initVDModule(true, {{"vd_lane_rearm", 1}});
    Syscollector::instance().m_vdLaneScanCompleted = true;
    INJECT_MOCK_PROTOCOLS();

    EXPECT_CALL(*vdProtocol, notifyDataClean(_, _, _)).WillOnce([](const std::vector<std::string>&, Option, bool)
    {
        Syscollector::instance().m_stopping = true;
        SyncModuleResult result;
        result.stopped = true;
        return result;
    });
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, _)).Times(0);
    EXPECT_CALL(*plainProtocol, synchronizeModule(_, _)).Times(0);

    Syscollector::instance().rearmVDLaneIfPending();
    Syscollector::instance().m_stopping = false;

    EXPECT_EQ(Syscollector::instance().vdLaneRearmState(), 1);
}

// The first session after the requeue did not land. The lane stays released for the rest of the
// run, so the next cycle sends the queued inventory as a first scan without requeueing it, and the
// re-arm is done once that session landed.
TEST_F(SyscollectorBaselineTest, RequeuedLaneIsReleasedUntilTheFirstScanLands)
{
    initVDModule(true, {{"vd_lane_rearm", 1}});
    Syscollector::instance().m_vdLaneScanCompleted = true;
    INJECT_MOCK_PROTOCOLS();

    EXPECT_CALL(*vdProtocol, notifyDataClean(_, _, _)).Times(2).WillRepeatedly(Return(okResult()));
    EXPECT_CALL(*plainProtocol, synchronizeModule(_, _)).WillRepeatedly(Return(okResult()));
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, Option::VDSYNC)).Times(0);
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, Option::VDFIRST))
    .WillOnce(Return(SyncModuleResult {}))
    .WillOnce(Return(sentResult()));

    Syscollector::instance().rearmVDLaneIfPending();
    EXPECT_FALSE(Syscollector::instance().isVDFirstSyncDone());
    EXPECT_EQ(Syscollector::instance().vdLaneRearmState(), 1);

    // The next cycle: not held, and nothing is cleared or requeued again.
    EXPECT_TRUE(Syscollector::instance().synchronizeVDTables(Mode::DELTA).success);
    Syscollector::instance().rearmVDLaneIfPending();

    EXPECT_TRUE(Syscollector::instance().isVDFirstSyncDone());
    EXPECT_EQ(Syscollector::instance().vdLaneRearmState(), 0);
}

// A run that ended after the requeue but before the first scan landed: the rows may not have
// reached the persistent queue's storage, so the next run holds the lane and requeues it again
// instead of sending what was persisted.
TEST_F(SyscollectorBaselineTest, NextRunRequeuesALaneWhoseFirstScanNeverLanded)
{
    initVDModule(true, {{"vd_lane_rearm", 1}});
    Syscollector::instance().m_vdLaneScanCompleted = true;
    {
        INJECT_MOCK_PROTOCOLS();
        EXPECT_CALL(*vdProtocol, notifyDataClean(_, _, _)).WillRepeatedly(Return(okResult()));
        EXPECT_CALL(*plainProtocol, synchronizeModule(_, _)).WillRepeatedly(Return(okResult()));
        EXPECT_CALL(*vdProtocol, synchronizeModule(_, Option::VDFIRST)).WillOnce(Return(SyncModuleResult {}));
        Syscollector::instance().rearmVDLaneIfPending();
    }
    Syscollector::instance().destroy();

    // Restart: same database, fresh run.
    initModule({.os = true, .packages = true}, std::make_shared<NiceMock<MockSysInfo>>());
    Syscollector::instance().m_vdSyncEnabled = true;
    INJECT_MOCK_PROTOCOLS();
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, _)).Times(0);

    EXPECT_EQ(Syscollector::instance().vdLaneRearmState(), 1);
    EXPECT_TRUE(Syscollector::instance().synchronizeVDTables(Mode::DELTA).sessionSkipped);

    // Until a scan completes in this run, it is not requeued either.
    EXPECT_CALL(*vdProtocol, notifyDataClean(_, _, _)).Times(0);
    Syscollector::instance().rearmVDLaneIfPending();
}

// A row DBSync could not write leaves its table incomplete, so the task gives it no baseline.
TEST_F(SyscollectorBaselineTest, TaskWithAFailedRowWriteLeavesItsTableWithoutBaseline)
{
    const auto spInfo {std::make_shared<NiceMock<MockSysInfo>>()};
    ON_CALL(*spInfo, users()).WillByDefault(Return(usersData(false)));
    ON_CALL(*spInfo, services()).WillByDefault([]()
    {
        // What DBSync's pipeline reports for a row whose write threw.
        Syscollector::instance().notifyChange(DB_ERROR, nlohmann::json {{"exception", "disk I/O error"}}, SERVICES_TABLE);
        return servicesData();
    });

    initModule({.users = true, .services = true}, spInfo);
    Syscollector::instance().scan();

    EXPECT_GT(baseline(USERS_TABLE), 0);
    EXPECT_EQ(baseline(SERVICES_TABLE), 0);
}

// A pending re-arm held back by a scan that ran and did not complete the VD tables says so.
TEST_F(SyscollectorBaselineTest, RearmHeldByAnIncompleteScanIsWarned)
{
    // packages fails by reporting a row DBSync could not write, not by throwing: an exception thrown
    // through the scan is not reliable under Wine, and this case should run on every target. os is
    // off so that its task completes without data; the lane is forced on below, as start() would
    // compute it on an agent with both collectors enabled.
    const Collectors collectors {.packages = true};
    initModule(collectors, std::make_shared<NiceMock<MockSysInfo>>());
    Syscollector::instance().destroy();
    seedMetadata("vd_lane_rearm", 1);

    const auto spInfo {std::make_shared<NiceMock<MockSysInfo>>()};
    ON_CALL(*spInfo, packages(_)).WillByDefault([](const std::function<void(nlohmann::json&)>&)
    {
        Syscollector::instance().notifyChange(DB_ERROR, nlohmann::json {{"exception", "disk I/O error"}}, PACKAGES_TABLE);
    });
    initModule(collectors, spInfo);
    Syscollector::instance().m_vdSyncEnabled = true;

    std::vector<std::string> warnings;
    Syscollector::instance().m_logFunction = [&warnings](const modules_log_level_t level, const std::string & msg)
    {
        if (level == LOG_WARNING)
        {
            warnings.push_back(msg);
        }
    };

    Syscollector::instance().scan();

    EXPECT_FALSE(Syscollector::instance().m_vdLaneScanCompleted.load());
    EXPECT_EQ(std::count_if(warnings.begin(), warnings.end(), [](const std::string & msg)
    {
        return msg.find("cannot be resent yet") != std::string::npos;
    }), 1);
}
