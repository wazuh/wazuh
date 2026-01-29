#include <gtest/gtest.h>

#include <dbsync.hpp>
#include <sca_sync_manager.hpp>

#include "logging_helper.hpp"

#include <chrono>
#include <filesystem>
#include <string>

namespace
{
    std::string makeTempPath()
    {
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto path = std::filesystem::temp_directory_path() /
                          ("sca_sync_manager_test_" + std::to_string(now));
        return path.string();
    }

    const std::string kCreateStatement =
        "CREATE TABLE IF NOT EXISTS sca_check ("
        "id TEXT PRIMARY KEY,"
        "policy_id TEXT,"
        "version INTEGER NOT NULL DEFAULT 1,"
        "sync INTEGER NOT NULL DEFAULT 0);";

    void insertCheck(const std::shared_ptr<IDBSync>& dbSync, const std::string& id, int syncValue = 0)
    {
        nlohmann::json data;
        data["id"] = id;
        data["policy_id"] = "policy";
        data["version"] = 1;
        data["sync"] = syncValue;

        auto query = SyncRowQuery::builder().table("sca_check").data(data).build();
        const auto callback = [](ReturnTypeCallback, const nlohmann::json&) {};
        dbSync->syncRow(query.query(), callback);
    }

    void deleteCheck(const std::shared_ptr<IDBSync>& dbSync, const std::string& id)
    {
        nlohmann::json data;
        data["id"] = id;

        auto query = DeleteQuery::builder().table("sca_check").data(data).build();
        dbSync->deleteRows(query.query());
    }

    int getSyncFlag(const std::shared_ptr<IDBSync>& dbSync, const std::string& id)
    {
        int syncFlag = -1;
        auto query = SelectQuery::builder()
                     .table("sca_check")
                     .columnList({"sync"})
                     .rowFilter("WHERE id = '" + id + "'")
                     .build();

        const auto callback = [&syncFlag](ReturnTypeCallback returnTypeCallback, const nlohmann::json & resultData)
        {
            if (returnTypeCallback == SELECTED && resultData.contains("sync"))
            {
                syncFlag = resultData["sync"].get<int>();
            }
        };

        dbSync->selectRows(query.query(), callback);
        return syncFlag;
    }

    nlohmann::json makeCheckData(const std::string& id, int version = 1, int syncValue = 0)
    {
        return {{"id", id}, {"version", version}, {"sync", syncValue}};
    }
}

class SCASyncManagerTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            LoggingHelper::setLogCallback(
            [](const modules_log_level_t /* level */, const std::string& /* log */) {});

            m_dbPath = makeTempPath();
            m_dbSync = std::make_shared<DBSync>(
                           HostType::AGENT, DbEngineType::SQLITE3, m_dbPath, kCreateStatement, DbManagement::PERSISTENT);
        }

        void TearDown() override
        {
            if (m_dbSync)
            {
                m_dbSync->closeAndDeleteDatabase();
            }

            m_dbSync.reset();
        }

        std::string m_dbPath;
        std::shared_ptr<IDBSync> m_dbSync;
};

TEST_F(SCASyncManagerTest, InitializeEnforcesLimitAndInsert)
{
    insertCheck(m_dbSync, "check-1");
    insertCheck(m_dbSync, "check-2");
    insertCheck(m_dbSync, "check-3");

    SCASyncManager manager(m_dbSync);
    manager.updateHandshake(2, "cluster-a");
    manager.initialize();

    EXPECT_EQ(getSyncFlag(m_dbSync, "check-1"), 1);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-2"), 1);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-3"), 0);
    EXPECT_TRUE(manager.shouldSyncModify(makeCheckData("check-1", 1, 1)));
    EXPECT_FALSE(manager.shouldSyncModify(makeCheckData("check-3", 1, 0)));

    insertCheck(m_dbSync, "check-4");
    nlohmann::json insertedCheck = {{"id", "check-4"}, {"version", 1}, {"sync", 0}};
    EXPECT_FALSE(manager.shouldSyncInsert(insertedCheck));
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-4"), 0);
}

TEST_F(SCASyncManagerTest, DeletePromotesOldestUnsynced)
{
    insertCheck(m_dbSync, "check-1");
    insertCheck(m_dbSync, "check-2");
    insertCheck(m_dbSync, "check-3");

    SCASyncManager manager(m_dbSync);
    manager.updateHandshake(2, "cluster-a");
    manager.initialize();

    deleteCheck(m_dbSync, "check-1");

    nlohmann::json deletedCheck = {{"id", "check-1"}, {"version", 1}};
    const auto result = manager.handleDelete(deletedCheck);

    EXPECT_TRUE(result.wasSynced);
    ASSERT_EQ(result.promotedIds.size(), 1U);
    EXPECT_EQ(result.promotedIds[0], "check-3");
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-3"), 1);
}

TEST_F(SCASyncManagerTest, UnlimitedModeSyncsAllChecks)
{
    insertCheck(m_dbSync, "check-1");
    insertCheck(m_dbSync, "check-2");

    SCASyncManager manager(m_dbSync);
    manager.updateHandshake(0, "cluster-a");
    manager.initialize();

    EXPECT_EQ(getSyncFlag(m_dbSync, "check-1"), 1);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-2"), 1);
    EXPECT_TRUE(manager.shouldSyncModify(makeCheckData("check-1", 1, 1)));
    EXPECT_TRUE(manager.shouldSyncModify(makeCheckData("missing-check", 1, 0)));

    insertCheck(m_dbSync, "check-3");
    EXPECT_TRUE(manager.shouldSyncInsert(makeCheckData("check-3", 1, 0)));
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-3"), 1);
}

TEST_F(SCASyncManagerTest, ModifyRespectsSyncedSet)
{
    insertCheck(m_dbSync, "check-1");
    insertCheck(m_dbSync, "check-2");

    SCASyncManager manager(m_dbSync);
    manager.updateHandshake(1, "cluster-a");
    manager.initialize();

    EXPECT_EQ(getSyncFlag(m_dbSync, "check-1"), 1);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-2"), 0);
    EXPECT_TRUE(manager.shouldSyncModify(makeCheckData("check-1", 1, 1)));
    EXPECT_FALSE(manager.shouldSyncModify(makeCheckData("check-2", 1, 0)));
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-1"), 1);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-2"), 0);
}

TEST_F(SCASyncManagerTest, ModifyPromotesWhenSpaceAvailable)
{
    insertCheck(m_dbSync, "check-1");

    SCASyncManager manager(m_dbSync);
    manager.updateHandshake(2, "cluster-a");
    manager.initialize();

    EXPECT_EQ(getSyncFlag(m_dbSync, "check-1"), 1);

    // Insert a new check after initialization to simulate an unsynced entry not yet tracked by the manager.
    insertCheck(m_dbSync, "check-2", 0);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-2"), 0);

    EXPECT_TRUE(manager.shouldSyncModify(makeCheckData("check-2", 1, 0)));
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-2"), 1);
}

TEST_F(SCASyncManagerTest, UpdateHandshakeReappliesLimit)
{
    insertCheck(m_dbSync, "check-1");
    insertCheck(m_dbSync, "check-2");
    insertCheck(m_dbSync, "check-3");
    insertCheck(m_dbSync, "check-4");

    SCASyncManager manager(m_dbSync);
    manager.updateHandshake(3, "cluster-a");
    manager.initialize();

    EXPECT_EQ(getSyncFlag(m_dbSync, "check-1"), 1);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-2"), 1);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-3"), 1);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-4"), 0);

    manager.updateHandshake(1, "cluster-a");

    EXPECT_EQ(getSyncFlag(m_dbSync, "check-1"), 1);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-2"), 0);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-3"), 0);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-4"), 0);

    manager.updateHandshake(3, "cluster-a");

    EXPECT_EQ(getSyncFlag(m_dbSync, "check-1"), 1);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-2"), 1);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-3"), 1);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-4"), 0);

    manager.updateHandshake(0, "cluster-a");

    EXPECT_EQ(getSyncFlag(m_dbSync, "check-1"), 1);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-2"), 1);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-3"), 1);
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-4"), 1);
}

TEST_F(SCASyncManagerTest, DeleteUnsyncedCheckDoesNotPromote)
{
    insertCheck(m_dbSync, "check-1");
    insertCheck(m_dbSync, "check-2");

    SCASyncManager manager(m_dbSync);
    manager.updateHandshake(1, "cluster-a");
    manager.initialize();

    deleteCheck(m_dbSync, "check-2");

    const auto result = manager.handleDelete(makeCheckData("check-2", 1, 0));

    EXPECT_FALSE(result.wasSynced);
    EXPECT_TRUE(result.promotedIds.empty());
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-1"), 1);
}

TEST_F(SCASyncManagerTest, DeleteAllChecksStopsPromotion)
{
    insertCheck(m_dbSync, "check-1");
    insertCheck(m_dbSync, "check-2");

    SCASyncManager manager(m_dbSync);
    manager.updateHandshake(1, "cluster-a");
    manager.initialize();

    deleteCheck(m_dbSync, "check-1");
    const auto firstDelete = manager.handleDelete(makeCheckData("check-1", 1, 0));

    ASSERT_TRUE(firstDelete.wasSynced);
    ASSERT_EQ(firstDelete.promotedIds.size(), 1U);
    EXPECT_EQ(firstDelete.promotedIds[0], "check-2");
    EXPECT_EQ(getSyncFlag(m_dbSync, "check-2"), 1);

    deleteCheck(m_dbSync, "check-2");
    const auto secondDelete = manager.handleDelete(makeCheckData("check-2", 1, 0));

    EXPECT_TRUE(secondDelete.wasSynced);
    EXPECT_TRUE(secondDelete.promotedIds.empty());
}

TEST_F(SCASyncManagerTest, EmptyDatabaseDoesNotPromote)
{
    SCASyncManager manager(m_dbSync);
    manager.updateHandshake(2, "cluster-a");
    manager.initialize();

    EXPECT_FALSE(manager.shouldSyncModify(makeCheckData("missing-check", 1, 0)));

    const auto result = manager.handleDelete(makeCheckData("missing-check", 1, 0));

    EXPECT_FALSE(result.wasSynced);
    EXPECT_TRUE(result.promotedIds.empty());
}
