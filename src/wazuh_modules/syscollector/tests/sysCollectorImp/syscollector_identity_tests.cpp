/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/**
 * @file syscollector_identity_tests.cpp
 * @brief Decision procedure for #38601's identity resync, and the lane it resends on.
 *
 * The routing is the part worth pinning down: a recovered VD index has to be cleared and
 * re-sent on the VD protocol, because the manager routes a VD session through the scan lane
 * that feeds the vulnerability scanner. Sending it on the plain protocol repopulates
 * wazuh-states-inventory-* and leaves the scanner with nothing -- measured as 1 package
 * scanned instead of 679 before the fix, and invisible to every assertion that only checks
 * that a resync happened at all.
 *
 * Driving any of this needs a manager to answer notifyDataClean(), so the protocols are mocked
 * and reach Syscollector's members through the friend declarations in syscollector_defs.hpp.
 */

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "json.hpp"
#include "syscollector.hpp"
#include "syscollector.h"
#include "syscollectorTablesDef.hpp"
#include "agent_sync_protocol.hpp"
#include "metadata_provider.h"
#include <sqlite3.h>
#include <mock_sysinfo.hpp>

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;

namespace
{
    constexpr auto IDENTITY_DB_PATH {"syscollector_identity_test.db"};
    constexpr auto WORK_DIR {"syscollector_identity_test_workdir"};
    constexpr auto SYNCED_AGENT_ID_KEY {"synced_agent_id"};

    class MockAgentSyncProtocol : public IAgentSyncProtocol
    {
        public:
            MOCK_METHOD(void, persistDifference,
                        (const std::string& id, Operation operation, const std::string& index,
                         const std::string& data, uint64_t version, bool isDataContext), (override));
            MOCK_METHOD(SyncModuleResult, synchronizeModule, (Mode mode, Option option), (override));
            MOCK_METHOD(bool, requiresFullSync, (const std::string& index, const std::string& checksum), (override));
            MOCK_METHOD(SyncModuleResult, synchronizeMetadataOrGroups,
                        (Mode mode, const std::vector<std::string>& indices, uint64_t globalVersion), (override));
            MOCK_METHOD(bool, notifyDataClean, (const std::vector<std::string>& indices, Option option), (override));
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
}

class SyscollectorIdentityTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            // Own directory: the metadata provider is a file at a path relative to the working
            // directory, and every other test binary in this tree writes the same one. Without
            // this, a parallel ctest decides which agent id these cases observe.
            std::filesystem::create_directories(std::string(WORK_DIR) + "/var/run");
            std::filesystem::current_path(WORK_DIR);

            std::remove(IDENTITY_DB_PATH);
            metadata_provider_reset();
        }

        void TearDown() override
        {
            Syscollector::instance().destroy();
            metadata_provider_reset();
            std::remove(IDENTITY_DB_PATH);
            std::filesystem::current_path("..");
        }

        /// @brief Publishes an agent id, the way agentd does after enrolling.
        static void publishAgentId(const std::string& agentId)
        {
            agent_metadata_t metadata {};
            strncpy(metadata.agent_id, agentId.c_str(), sizeof(metadata.agent_id) - 1);
            strncpy(metadata.agent_name, "test-agent", sizeof(metadata.agent_name) - 1);
            strncpy(metadata.agent_version, "5.0.0", sizeof(metadata.agent_version) - 1);
            strncpy(metadata.architecture, "x86_64", sizeof(metadata.architecture) - 1);
            strncpy(metadata.hostname, "test-host", sizeof(metadata.hostname) - 1);
            strncpy(metadata.os_name, "Linux", sizeof(metadata.os_name) - 1);
            strncpy(metadata.os_type, "linux", sizeof(metadata.os_type) - 1);
            strncpy(metadata.os_platform, "ubuntu", sizeof(metadata.os_platform) - 1);
            strncpy(metadata.os_version, "24.04", sizeof(metadata.os_version) - 1);
            metadata_provider_update(&metadata);
        }

        /// @brief init() with only the collectors a case needs. packages and os ride the VD
        /// lane, users the plain one, which is what makes the routing observable with two mocks.
        static void initModule(bool packages, bool users, bool os = false)
        {
            const auto spInfoWrapper {std::make_shared<MockSysInfo>()};
            EXPECT_CALL(*spInfoWrapper, releaseThreadResources()).Times(::testing::AnyNumber());

            Syscollector::instance().init(spInfoWrapper,
            [](const std::string&) {},
            [](const std::string&, Operation_t, const std::string&,
               const std::string&, uint64_t) {},
            [](const modules_log_level_t, const std::string&) {},
            IDENTITY_DB_PATH,
            "",
            "",
            3600,
            false,      // scanOnStart
            false,      // hardware
            os,         // os        -> VD lane
            false,      // network
            packages,   // packages  -> VD lane
            false,      // ports
            false,      // portsAll
            false,      // processes
            false,      // hotfixes
            false,      // groups
            users,      // users     -> plain lane
            false,      // services
            false,      // browserExtensions
            false);     // notifyOnFirstScan

            // start() computes this, and these cases do not call it -- they inject protocols
            // instead of letting the module build real ones. Set here so that no case can model
            // a lane a real agent could not have: with a VD collector switched off there is no
            // VD lane at all, and checkAgentIdentity() routes os and packages through the plain
            // one. (Windows also requires hotfixes; these cases stand in for the enabled lane.)
            Syscollector::instance().m_vdSyncEnabled = packages && os;
        }

        /// @brief Creates the schema, seeds the marker, and reopens: DBSync holds the database
        /// open for as long as the module is initialized, so a write from outside it is refused
        /// with SQLITE_BUSY while it is up.
        static void initWithMarker(bool packages, bool users, int64_t marker, bool os = false)
        {
            initModule(packages, users, os);
            Syscollector::instance().destroy();
            seedMarker(marker);
            initModule(packages, users, os);
        }

        /// @brief Writes any metadata row, for the markers other than synced_agent_id.
        static void seedMetadata(const std::string& key, int64_t value)
        {
            sqlite3* db = nullptr;
            ASSERT_EQ(sqlite3_open_v2(IDENTITY_DB_PATH, &db, SQLITE_OPEN_READWRITE, nullptr), SQLITE_OK);

            const std::string statement =
                "INSERT OR REPLACE INTO table_metadata (table_name, last_sync_time) VALUES ('" +
                key + "', " + std::to_string(value) + ");";

            ASSERT_EQ(sqlite3_exec(db, statement.c_str(), nullptr, nullptr, nullptr), SQLITE_OK);
            sqlite3_close(db);
        }

        /// @brief Writes a row straight into table_metadata, which is where the marker lives.
        static void seedMarker(int64_t agentId)
        {
            sqlite3* db = nullptr;
            ASSERT_EQ(sqlite3_open_v2(IDENTITY_DB_PATH, &db, SQLITE_OPEN_READWRITE, nullptr), SQLITE_OK);

            const std::string statement =
                "INSERT OR REPLACE INTO table_metadata (table_name, last_sync_time) VALUES ('" +
                std::string(SYNCED_AGENT_ID_KEY) + "', " + std::to_string(agentId) + ");";

            char* errMsg = nullptr;
            ASSERT_EQ(sqlite3_exec(db, statement.c_str(), nullptr, nullptr, &errMsg), SQLITE_OK)
                    << (errMsg ? errMsg : "");

            if (errMsg)
            {
                sqlite3_free(errMsg);
            }

            sqlite3_close(db);
        }

        static int64_t readMarker()
        {
            const auto response = Syscollector::instance().query(R"({"command":"get_synced_agent_id"})");
            return nlohmann::json::parse(response)["data"]["synced_agent_id"].get<int64_t>();
        }
};

/// Declares plainProtocol / vdProtocol and publishes the mocks into the module. Written as a
/// macro because gtest's FRIEND_TEST grants access to the test body, not to fixture members.
#define INJECT_MOCK_PROTOCOLS()                                                            \
    auto plainOwned = std::make_unique<NiceMock<MockAgentSyncProtocol>>();                 \
    auto vdOwned = std::make_unique<NiceMock<MockAgentSyncProtocol>>();                    \
    auto* plainProtocol = plainOwned.get();                                                \
    auto* vdProtocol = vdOwned.get();                                                      \
    Syscollector::instance().m_spSyncProtocol = std::move(plainOwned);                     \
    Syscollector::instance().m_spSyncProtocolVD = std::move(vdOwned)

// An in-place upgrade must not make the whole fleet resend at once: a database that never
// recorded the marker adopts the current id and sends nothing.
TEST_F(SyscollectorIdentityTest, AbsentMarkerIsAdoptedWithoutResync)
{
    initModule(true, true);
    publishAgentId("7");
    INJECT_MOCK_PROTOCOLS();

    EXPECT_CALL(*plainProtocol, notifyDataClean(_, _)).Times(0);
    EXPECT_CALL(*vdProtocol, notifyDataClean(_, _)).Times(0);

    Syscollector::instance().checkAgentIdentity();

    EXPECT_EQ(readMarker(), 7);
}

// The common re-enrollment keeps the same id (a key rotation, an authd password change, any
// 401 that is not a deletion). Treating that as a change would resend the fleet on every
// credential refresh.
TEST_F(SyscollectorIdentityTest, UnchangedIdIsANoOp)
{
    initWithMarker(true, true, 5);
    publishAgentId("5");
    INJECT_MOCK_PROTOCOLS();

    EXPECT_CALL(*plainProtocol, notifyDataClean(_, _)).Times(0);
    EXPECT_CALL(*vdProtocol, notifyDataClean(_, _)).Times(0);

    Syscollector::instance().checkAgentIdentity();

    EXPECT_EQ(readMarker(), 5);
}

// Nothing published yet: an unavailable provider, or one still holding the previous id, must
// read as unknown and never as a new identity.
TEST_F(SyscollectorIdentityTest, UnknownIdIsANoOp)
{
    initWithMarker(true, true, 5);
    metadata_provider_reset();
    INJECT_MOCK_PROTOCOLS();

    EXPECT_CALL(*plainProtocol, notifyDataClean(_, _)).Times(0);
    EXPECT_CALL(*vdProtocol, notifyDataClean(_, _)).Times(0);

    Syscollector::instance().checkAgentIdentity();

    EXPECT_EQ(readMarker(), 5);
}

// A failed read is not an answer. Folding it into "nothing recorded" would let one transient
// database failure, in the window right after a re-enrollment, record the new id as already
// synchronized and suppress the resync permanently.
TEST_F(SyscollectorIdentityTest, FailedMarkerReadAdoptsNothing)
{
    initWithMarker(true, true, 5);
    publishAgentId("9");
    INJECT_MOCK_PROTOCOLS();

    EXPECT_CALL(*plainProtocol, notifyDataClean(_, _)).Times(0);
    EXPECT_CALL(*vdProtocol, notifyDataClean(_, _)).Times(0);

    // A read that fails rather than one that answers "nothing recorded": getMetadataValue()
    // reports false when it has no database, which is the same "not an answer" a busy or
    // unreadable one produces. Dropping table_metadata instead reproduces it too, but leaves the
    // schema broken -- portable enough to pass here and fatal to the process under wine.
    auto dbsync = std::move(Syscollector::instance().m_spDBSync);
    Syscollector::instance().checkAgentIdentity();
    Syscollector::instance().m_spDBSync = std::move(dbsync);

    // The distinguishing observation, and the reason this case exists: an absent marker is
    // adopted, a failed read must not be. Adopting 9 here would record an id nothing was ever
    // sent under and suppress the resync permanently.
    EXPECT_EQ(readMarker(), 5);
}

// The headline behaviour: every enabled table is resent, each on the protocol its data rides.
TEST_F(SyscollectorIdentityTest, ChangedIdResendsEachTableOnItsOwnLane)
{
    initWithMarker(true, true, 1);
    publishAgentId("2");
    INJECT_MOCK_PROTOCOLS();

    EXPECT_CALL(*vdProtocol,
                notifyDataClean(std::vector<std::string> {SYSCOLLECTOR_SYNC_INDEX_PACKAGES}, _))
    .Times(1)
    .WillOnce(Return(true));
    EXPECT_CALL(*plainProtocol,
                notifyDataClean(std::vector<std::string> {SYSCOLLECTOR_SYNC_INDEX_USERS}, _))
    .Times(1)
    .WillOnce(Return(true));

    EXPECT_CALL(*plainProtocol, synchronizeModule(_, _)).WillRepeatedly(Return(okResult()));
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, _)).WillRepeatedly(Return(okResult()));

    Syscollector::instance().checkAgentIdentity();

    EXPECT_EQ(readMarker(), 2);
}

// A disabled collector holds no data worth resending, and its index must not be cleared.
TEST_F(SyscollectorIdentityTest, ChangedIdSkipsDisabledCollectors)
{
    initWithMarker(true, false, 1);
    publishAgentId("2");
    INJECT_MOCK_PROTOCOLS();

    EXPECT_CALL(*vdProtocol, notifyDataClean(_, _)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*plainProtocol, notifyDataClean(_, _)).Times(0);
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, _)).WillRepeatedly(Return(okResult()));
    EXPECT_CALL(*plainProtocol, synchronizeModule(_, _)).WillRepeatedly(Return(okResult()));

    Syscollector::instance().checkAgentIdentity();

    EXPECT_EQ(readMarker(), 2);
}

// To the manager a re-enrolled agent is a new agent, and a new agent's first scan is the one
// that indexes its vulnerabilities without alerting on each -- the chain the manager picks for
// Option::VDFIRST. The agent only asks for it while vd_first_sync_completed is unset, so the
// identity resync clears that marker and sends the whole VD inventory in one session.
TEST_F(SyscollectorIdentityTest, ChangedIdSendsTheVDInventoryAsAFirstSync)
{
    // os as well as packages: m_vdSyncEnabled is m_packages && m_os, and without it the module
    // sends the VD tables with Option::SYNC and the first-scan question never arises.
    initModule(true, true, /* os */ true);
    Syscollector::instance().destroy();
    seedMarker(1);
    // Armed, as it is on any agent that has synchronized before: without this the plain lane's
    // own session would already ask for VDFIRST and the reset below would prove nothing.
    seedMetadata("vd_first_sync_completed", 1787900000);
    initModule(true, true, /* os */ true);
    publishAgentId("2");
    INJECT_MOCK_PROTOCOLS();

    EXPECT_CALL(*vdProtocol, notifyDataClean(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*plainProtocol, notifyDataClean(_, _)).WillRepeatedly(Return(true));

    // The whole point: exactly one session carries the VD inventory, and it asks for the
    // first-scan chain. The plain lane's own sessions also reach this protocol -- syncModule()
    // drains both -- but they run before any VD row is queued, so they find nothing to send and
    // ask under the marker that is still armed. Those are allowed; a second VDFIRST is not,
    // since each one opens by deleting what the previous indexed.
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, Option::VDSYNC))
    .Times(::testing::AnyNumber())
    .WillRepeatedly(Return(okResult()));
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, Option::VDFIRST))
    .Times(1)
    .WillOnce(Return(okResult()));
    EXPECT_CALL(*plainProtocol, synchronizeModule(_, _)).WillRepeatedly(Return(okResult()));

    Syscollector::instance().checkAgentIdentity();

    EXPECT_EQ(readMarker(), 2);
}

// A refused DataClean means the manager never took that table. The pass keeps going, so the
// tables that can be resent are, and the marker stays put so the next cycle retries.
TEST_F(SyscollectorIdentityTest, RefusedDataCleanWithholdsTheMarkerAndKeepsGoing)
{
    initWithMarker(true, true, 1);
    publishAgentId("2");
    INJECT_MOCK_PROTOCOLS();

    EXPECT_CALL(*vdProtocol, notifyDataClean(_, _)).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*plainProtocol, notifyDataClean(_, _)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*plainProtocol, synchronizeModule(_, _)).WillRepeatedly(Return(okResult()));
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, _)).WillRepeatedly(Return(okResult()));

    Syscollector::instance().checkAgentIdentity();

    EXPECT_EQ(readMarker(), 1);
}

// The combined marker waits for both lanes, so a plain table that keeps failing leaves the pass
// unfinished cycle after cycle. The VD lane must not be redone on the strength of that: every
// redo clears the vulnerability index and resends it as a first scan, which suppresses alerts,
// so a CVE appearing between two cycles would never raise one.
TEST_F(SyscollectorIdentityTest, PlainLaneFailureDoesNotRedoTheVDLaneNextCycle)
{
    initWithMarker(true, true, 1, /* os */ true);
    publishAgentId("2");
    INJECT_MOCK_PROTOCOLS();

    // The VD lane lands once across both cycles: one call per VD table -- packages and os --
    // in the first cycle, and none in the second.
    EXPECT_CALL(*vdProtocol, notifyDataClean(_, _)).Times(2).WillRepeatedly(Return(true));
    // The plain lane never does, and is retried on the second cycle.
    EXPECT_CALL(*plainProtocol, notifyDataClean(_, _)).Times(2).WillRepeatedly(Return(false));
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, _)).WillRepeatedly(Return(okResult()));
    EXPECT_CALL(*plainProtocol, synchronizeModule(_, _)).WillRepeatedly(Return(okResult()));

    Syscollector::instance().checkAgentIdentity();
    Syscollector::instance().checkAgentIdentity();

    // The identity is still not fully synchronized, so the combined marker stays where it was.
    EXPECT_EQ(readMarker(), 1);
}

// Each resent table stamps the integrity clock, so the checksum loop running right behind this
// one in the same pass does not clear and re-upload what was just replaced. Both lanes stamp,
// from different places: the plain one as each session returns, the VD one only once its single
// deferred session lands, so this case enables a table on each.
TEST_F(SyscollectorIdentityTest, ResyncStampsTheIntegrityClockPerTable)
{
    initWithMarker(true, true, 1, /* os */ true);
    publishAgentId("2");
    INJECT_MOCK_PROTOCOLS();

    EXPECT_CALL(*vdProtocol, notifyDataClean(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*plainProtocol, notifyDataClean(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, _)).WillRepeatedly(Return(okResult()));
    EXPECT_CALL(*plainProtocol, synchronizeModule(_, _)).WillRepeatedly(Return(okResult()));

    Syscollector::instance().checkAgentIdentity();

    int64_t stamped = 0;
    EXPECT_TRUE(Syscollector::instance().getMetadataValue(PACKAGES_TABLE, stamped));
    EXPECT_GT(stamped, 0);

    stamped = 0;
    EXPECT_TRUE(Syscollector::instance().getMetadataValue(USERS_TABLE, stamped));
    EXPECT_GT(stamped, 0);
}

// vd_synced_agent_id skips the VD lane for an identity it says is already covered, so only a run
// that actually had that lane may write it. With a VD collector switched off there is none:
// m_vdSyncEnabled is false, synchronizeVDTables() sends Option::SYNC, and os and packages go out
// on the plain lane like any other table. Recording the marker there would let a later run --
// packages switched back on -- honour it, skip the whole VD inventory, and leave it to go out as
// VDSYNC: an alert for every finding the manager has never seen under this identity.
TEST_F(SyscollectorIdentityTest, DisabledVDLaneDoesNotClaimTheVDMarker)
{
    // os off, so there is no VD lane while packages still has rows to resend.
    initWithMarker(true, true, 1);
    publishAgentId("2");
    INJECT_MOCK_PROTOCOLS();

    // packages is resent on both cycles: no marker exists to skip it, and the plain lane keeps
    // failing so the combined marker never advances either. Its data still rides the VD
    // protocol -- that routing is by index and is not what the lane decides.
    EXPECT_CALL(*vdProtocol, notifyDataClean(_, _)).Times(2).WillRepeatedly(Return(true));
    EXPECT_CALL(*plainProtocol, notifyDataClean(_, _)).Times(2).WillRepeatedly(Return(false));
    EXPECT_CALL(*vdProtocol, synchronizeModule(_, _)).WillRepeatedly(Return(okResult()));
    EXPECT_CALL(*plainProtocol, synchronizeModule(_, _)).WillRepeatedly(Return(okResult()));

    Syscollector::instance().checkAgentIdentity();
    Syscollector::instance().checkAgentIdentity();

    // Read cleanly, and unset: an absent row reads as 0, which is what the resync compares
    // against the current id and finds different.
    int64_t vdMarker = -1;
    EXPECT_TRUE(Syscollector::instance().getMetadataValue("vd_synced_agent_id", vdMarker));
    EXPECT_EQ(vdMarker, 0);
    EXPECT_EQ(readMarker(), 1);
}
