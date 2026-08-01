#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/json.hpp>
#include <base/syncStatus.hpp>
#include <iockvdb/helpers.hpp>
#include <iockvdb/mockManager.hpp>
#include <store/mockStore.hpp>
#include <wiconnector/mockswindexerconnector.hpp>

#include <iocsync/iocsync.hpp>

using namespace ioc::sync;
using namespace ::testing;

namespace
{

constexpr std::size_t DEFAULT_RETRIES = 1;
constexpr std::size_t DEFAULT_WAIT = 0;
constexpr std::size_t DEFAULT_BATCH = 100;

class IocSyncStatusTest : public ::testing::Test
{
protected:
    std::shared_ptr<StrictMock<wiconnector::mocks::MockWIndexerConnector>> indexer {
        std::make_shared<StrictMock<wiconnector::mocks::MockWIndexerConnector>>()};
    std::shared_ptr<StrictMock<ioc::kvdb::MockKVDBManager>> kvdb {
        std::make_shared<StrictMock<ioc::kvdb::MockKVDBManager>>()};
    std::shared_ptr<StrictMock<store::mocks::MockStore>> store {
        std::make_shared<StrictMock<store::mocks::MockStore>>()};

    /// Create IocSync with no persisted state (first setup)
    std::unique_ptr<IocSync> createFirstSetup()
    {
        const auto numTypes = ioc::kvdb::details::getSupportedIocTypes().size();

        EXPECT_CALL(*store, existsDoc(_)).WillOnce(Return(false));
        // 6 from addIOCTypeToSync + 1 explicit saveStateToStore in constructor
        EXPECT_CALL(*store, upsertDoc(_, _)).Times(numTypes + 1).WillRepeatedly(Return(store::mocks::storeOk()));

        return std::make_unique<IocSync>(indexer, kvdb, store, DEFAULT_RETRIES, DEFAULT_WAIT, DEFAULT_BATCH);
    }
};

} // namespace

TEST_F(IocSyncStatusTest, InitialStatusAllReady)
{
    // On first setup the hash is empty for every type, so updateIocStatusSnapshot() skips
    // kvdb->exists() and reports available = false.
    auto sync = createFirstSetup();

    auto status = sync->getIocStatus();
    ASSERT_EQ(status.size(), ioc::kvdb::details::getSupportedIocTypes().size());

    for (const auto& s : status)
    {
        EXPECT_EQ(s.status, base::SyncStatus::READY);
        EXPECT_FALSE(s.available);
        EXPECT_TRUE(s.hash.empty());
        EXPECT_EQ(s.lastSuccessfulUpdate, 0U);
    }
}

TEST_F(IocSyncStatusTest, InitialStatusContainsAllIocTypes)
{
    auto sync = createFirstSetup();

    auto status = sync->getIocStatus();
    auto supportedTypes = ioc::kvdb::details::getSupportedIocTypes();

    ASSERT_EQ(status.size(), supportedTypes.size());

    for (std::size_t i = 0; i < supportedTypes.size(); ++i)
    {
        EXPECT_EQ(status[i].type, supportedTypes[i]);
    }
}

// A sync cycle that cannot reach/use the indexer must report FAILED for types without a usable
// version (e.g. first start with no indexer connector), not leave them at the seeded READY.
TEST_F(IocSyncStatusTest, FailedSyncMarksUnsyncedTypesFailed)
{
    auto sync = createFirstSetup(); // 6 types seeded READY, empty hash, unavailable

    // Indexer consumer not ready (e.g. no indexer connector) → the sync cycle aborts in pre-flight.
    EXPECT_CALL(*indexer, isConsumerReadyForSync(_)).WillOnce(Return(false));

    sync->synchronize();

    auto status = sync->getIocStatus();
    ASSERT_EQ(status.size(), ioc::kvdb::details::getSupportedIocTypes().size());
    for (const auto& s : status)
    {
        EXPECT_EQ(s.status, base::SyncStatus::FAILED);
        EXPECT_FALSE(s.available);
    }
}

// last_successful_update persisted in the store must be restored on load (survives restart).
TEST_F(IocSyncStatusTest, RestoresLastSuccessfulUpdateFromStore)
{
    json::Json state;
    state.setArray();
    json::Json entry;
    entry.setString("hash_md5", "/ioc_type");
    entry.setString("deadbeef", "/last_data_hash");
    entry.setInt64(1700000000, "/last_successful_update");
    state.appendJson(entry);

    EXPECT_CALL(*store, existsDoc(_)).WillOnce(Return(true));
    EXPECT_CALL(*store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(state)));
    // Hash is non-empty, so availability is checked against the KVDB.
    EXPECT_CALL(*kvdb, exists(_)).WillRepeatedly(Return(true));

    IocSync sync(indexer, kvdb, store, DEFAULT_RETRIES, DEFAULT_WAIT, DEFAULT_BATCH);

    auto status = sync.getIocStatus();
    ASSERT_EQ(status.size(), 1U);
    EXPECT_EQ(status[0].type, "hash_md5");
    EXPECT_TRUE(status[0].available);
    EXPECT_EQ(status[0].hash, "deadbeef");
    EXPECT_EQ(status[0].lastSuccessfulUpdate, 1700000000U);
}
