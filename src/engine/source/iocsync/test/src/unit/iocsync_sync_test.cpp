#include <chrono>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/json.hpp>
#include <base/logging.hpp>
#include <base/syncStatus.hpp>
#include <cmcontent/fakeContentTopic.hpp>
#include <cmcontent/registration.hpp>
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

nlohmann::json indexerConnection()
{
    return nlohmann::json {{"hosts", nlohmann::json::array({"http://127.0.0.1:9200"})}};
}

cmcontent::Options contentOptions()
{
    cmcontent::Options options;
    options.pageSize = 100;
    return options;
}

/// The persisted state document for a set of types, each at the given hash.
json::Json stateDoc(const std::vector<std::pair<std::string, std::string>>& types)
{
    json::Json doc {};
    doc.setArray();
    for (const auto& [type, hash] : types)
    {
        json::Json entry {};
        entry.setString(type, "/ioc_type");
        entry.setString(hash, "/last_data_hash");
        entry.setInt64(0, "/last_successful_update");
        doc.appendJson(entry);
    }
    return doc;
}

content_manager::CycleOutcome outcomeOf(content_manager::CycleStatus status)
{
    content_manager::CycleOutcome outcome;
    outcome.status = status;
    return outcome;
}

/**
 * @brief Drives IocSync's orchestration through a scripted topic registry.
 *
 * This is the coverage the design document called the single biggest gap: everything below the
 * download — which outcome marks a type FAILED, when a physically missing database forces a full
 * reload, what a token committed by an out-of-band cycle does to the persisted state — had no test
 * at all, because IocSync owned a concrete ContentRegister that opens real connections.
 */
class IocSyncOrchestrationTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit();

        // Only the two types under test, so the assertions name what they mean instead of counting
        // whatever the supported-type table happens to hold today.
        persisted = {{"url_domain", "hash-url"}, {"hash_md5", "hash-md5"}};
    }

    /// Build the service from the persisted state, with every topic scripted through `topics`.
    std::unique_ptr<IocSync> build()
    {
        EXPECT_CALL(*store, existsDoc(_)).WillOnce(Return(true));
        EXPECT_CALL(*store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(stateDoc(persisted))));

        return std::make_unique<IocSync>(indexer,
                                         kvdb,
                                         store,
                                         indexerConnection(),
                                         DEFAULT_RETRIES,
                                         DEFAULT_WAIT,
                                         contentOptions(),
                                         topics.factory());
    }

    /// Let the pre-flight through: the consumer is ready and the remote index exists.
    void expectPreflightPasses()
    {
        EXPECT_CALL(*indexer, isConsumerReadyForSync(_)).WillRepeatedly(Return(true));
        EXPECT_CALL(*indexer, existsIocDataIndex()).WillRepeatedly(Return(true));
    }

    /// Report every target database as present, so nothing forces a reload on that account.
    void expectDatabasesPresent()
    {
        EXPECT_CALL(*kvdb, exists(_)).WillRepeatedly(Return(true));
    }

    static std::string topicOf(const std::string& type) { return cmcontent::iocTopic(type); }

    static IocTypeStatus statusOf(const std::vector<IocTypeStatus>& all, const std::string& type)
    {
        for (const auto& entry : all)
        {
            if (entry.type == type)
            {
                return entry;
            }
        }
        ADD_FAILURE() << "no status reported for IOC type '" << type << "'";
        return {};
    }

    std::shared_ptr<NiceMock<wiconnector::mocks::MockWIndexerConnector>> indexer {
        std::make_shared<NiceMock<wiconnector::mocks::MockWIndexerConnector>>()};
    std::shared_ptr<NiceMock<ioc::kvdb::MockKVDBManager>> kvdb {
        std::make_shared<NiceMock<ioc::kvdb::MockKVDBManager>>()};
    std::shared_ptr<NiceMock<store::mocks::MockStore>> store {
        std::make_shared<NiceMock<store::mocks::MockStore>>()};

    cmcontent::mocks::FakeTopicRegistry topics;
    std::vector<std::pair<std::string, std::string>> persisted;
};

} // namespace

TEST_F(IocSyncOrchestrationTest, RegistersOneTopicPerPersistedType)
{
    auto sync = build();

    EXPECT_THAT(topics.registered(),
                UnorderedElementsAre(topicOf("url_domain"), topicOf("hash_md5")));
}

TEST_F(IocSyncOrchestrationTest, EachTopicStartsFromItsPersistedHash)
{
    auto sync = build();

    // The seed matters: a registration that started at "" would treat a perfectly current database
    // as never synced and re-download every IOC on the first cycle after a restart.
    EXPECT_EQ(topics.tokenStoreOf(topicOf("url_domain"))->load(topicOf("url_domain")), "hash-url");
    EXPECT_EQ(topics.tokenStoreOf(topicOf("hash_md5"))->load(topicOf("hash_md5")), "hash-md5");
}

TEST_F(IocSyncOrchestrationTest, APhysicallyMissingDatabaseForcesAFullReload)
{
    expectPreflightPasses();

    const auto missing = ioc::kvdb::details::getDbNameFromType("url_domain");
    EXPECT_CALL(*kvdb, exists(_))
        .WillRepeatedly(Invoke([missing](std::string_view name) { return std::string {name} != missing; }));

    topics.scriptStatus(topicOf("url_domain"), content_manager::CycleStatus::Updated);
    topics.scriptStatus(topicOf("hash_md5"), content_manager::CycleStatus::Unchanged);

    auto sync = build();
    sync->synchronize();

    // A matching hash says the *content* has not moved; it says nothing about whether the database
    // holding it still exists. Only a forced reload can rebuild one that was deleted, because a
    // no-change cycle delivers no documents to swap in.
    bool forcedForMissing = false;
    bool forcedForPresent = false;
    for (const auto& call : topics.calls())
    {
        if (call.topic == topicOf("url_domain") && call.request.forceFullReload)
        {
            forcedForMissing = true;
        }
        if (call.topic == topicOf("hash_md5") && call.request.forceFullReload)
        {
            forcedForPresent = true;
        }
    }

    EXPECT_TRUE(forcedForMissing) << "a deleted database must be rebuilt, not skipped as unchanged";
    EXPECT_FALSE(forcedForPresent) << "a present database must not pay for a full reload";
}

TEST_F(IocSyncOrchestrationTest, ACommittedHashReachesThePersistedState)
{
    expectPreflightPasses();
    expectDatabasesPresent();

    cmcontent::mocks::FakeTopicRegistry::Script updated;
    updated.outcome = outcomeOf(content_manager::CycleStatus::Updated);
    updated.tokenToStore = "hash-url-v2";
    topics.script(topicOf("url_domain"), {updated});
    topics.scriptStatus(topicOf("hash_md5"), content_manager::CycleStatus::Unchanged);

    json::Json written;
    EXPECT_CALL(*store, upsertDoc(_, _))
        .WillRepeatedly(Invoke(
            [&written](const base::Name&, const json::Json& doc)
            {
                written = doc;
                return store::mocks::storeOk();
            }));

    auto sync = build();
    sync->synchronize();

    // The cycle writes its token into the registration's cell; this is the reconciliation that
    // carries it into the document. Without it the hash would be lost on restart and the whole
    // type re-downloaded.
    EXPECT_EQ(statusOf(sync->getIocStatus(), "url_domain").hash, "hash-url-v2");

    const auto entries = written.getArray();
    ASSERT_TRUE(entries.has_value());
    bool found = false;
    for (const auto& entry : *entries)
    {
        std::string type;
        std::string hash;
        if (entry.getString(type, "/ioc_type") == json::RetGet::Success && type == "url_domain" &&
            entry.getString(hash, "/last_data_hash") == json::RetGet::Success)
        {
            found = true;
            EXPECT_EQ(hash, "hash-url-v2");
        }
    }
    EXPECT_TRUE(found) << "the new hash was never persisted";
}

TEST_F(IocSyncOrchestrationTest, AnUpdateAlreadyRunningLeavesTheTypeAlone)
{
    expectPreflightPasses();
    expectDatabasesPresent();

    cmcontent::mocks::FakeTopicRegistry::Script busy;
    busy.outcome = outcomeOf(content_manager::CycleStatus::SkippedAlreadyRunning);
    // The on-demand cycle that is holding the slot commits while this one is being refused.
    busy.tokenToStore = "hash-url-from-ondemand";
    topics.script(topicOf("url_domain"), {busy});
    topics.scriptStatus(topicOf("hash_md5"), content_manager::CycleStatus::Unchanged);

    auto sync = build();
    sync->synchronize();

    // Nothing was observed here, so nothing is concluded here: marking the type FAILED because the
    // API had been used a moment earlier would be a lie. But whatever that cycle committed still
    // has to reach the persisted state.
    const auto status = statusOf(sync->getIocStatus(), "url_domain");
    EXPECT_EQ(status.status, base::SyncStatus::READY);
    EXPECT_EQ(status.hash, "hash-url-from-ondemand");
}

TEST_F(IocSyncOrchestrationTest, AFailedCycleKeepsTheExistingVersionAndReportsReady)
{
    expectPreflightPasses();
    expectDatabasesPresent();

    cmcontent::mocks::FakeTopicRegistry::Script failing;
    failing.outcome = outcomeOf(content_manager::CycleStatus::FailedTransport);
    failing.outcome.retryAfter = std::chrono::seconds {30};
    topics.script(topicOf("url_domain"), {failing});
    topics.scriptStatus(topicOf("hash_md5"), content_manager::CycleStatus::Unchanged);

    auto sync = build();
    sync->synchronize();

    // A type that already has usable data on disk keeps it: the old IOCs are still valid, and the
    // failure is about refreshing them, not about them.
    const auto status = statusOf(sync->getIocStatus(), "url_domain");
    EXPECT_EQ(status.hash, "hash-url");
    EXPECT_EQ(status.status, base::SyncStatus::READY);
}

TEST_F(IocSyncOrchestrationTest, ARetryableOutcomeIsRetriedUpToTheConfiguredAttempts)
{
    expectPreflightPasses();
    expectDatabasesPresent();

    cmcontent::mocks::FakeTopicRegistry::Script deferred;
    deferred.outcome = outcomeOf(content_manager::CycleStatus::SkippedConsumerNotReady);
    // A non-zero retryAfter is what the Engine's rethrow adapter keys on, since runOnce reports by
    // status and executeWithRetry retries on a thrown exception.
    deferred.outcome.retryAfter = std::chrono::seconds {60};
    topics.script(topicOf("url_domain"), {deferred});
    topics.scriptStatus(topicOf("hash_md5"), content_manager::CycleStatus::Unchanged);

    EXPECT_CALL(*store, existsDoc(_)).WillOnce(Return(true));
    EXPECT_CALL(*store, readDoc(_)).WillOnce(Return(store::mocks::storeReadDocResp(stateDoc(persisted))));

    constexpr std::size_t ATTEMPTS = 3;
    auto sync = std::make_unique<IocSync>(
        indexer, kvdb, store, indexerConnection(), ATTEMPTS, 0, contentOptions(), topics.factory());
    sync->synchronize();

    EXPECT_EQ(topics.callCount(topicOf("url_domain")), ATTEMPTS);
    // A terminal outcome is not retried; only one of the two types should have been re-run.
    EXPECT_EQ(topics.callCount(topicOf("hash_md5")), 1U);
}

TEST_F(IocSyncOrchestrationTest, ShutdownStopsEveryTopicAndHaltsTheIteration)
{
    auto sync = build();

    sync->requestShutdown();

    EXPECT_EQ(topics.stopCount(topicOf("url_domain")), 1U);
    EXPECT_EQ(topics.stopCount(topicOf("hash_md5")), 1U);

    // Already shutting down: the cycle must not start at all.
    sync->synchronize();
    EXPECT_TRUE(topics.calls().empty());
}

TEST_F(IocSyncOrchestrationTest, ANotReadyConsumerSkipsEveryTypeWithoutRunningACycle)
{
    EXPECT_CALL(*indexer, isConsumerReadyForSync(_)).WillRepeatedly(Return(false));

    auto sync = build();
    sync->synchronize();

    // One cheap query short-circuits every registration at once; paying for a PIT per type only to
    // be told the same thing is the cost this gate exists to avoid.
    EXPECT_TRUE(topics.calls().empty());
}
