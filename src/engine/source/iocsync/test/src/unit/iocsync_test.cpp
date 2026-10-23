// SPDX-License-Identifier: AGPL-3.0-or-later
#include <memory>
#include <optional>
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

#include <iocsync/iocsync.hpp>

/*
 * IocSync's own behaviour: one topic per supported type, the forced reload of a missing database,
 * how an outcome becomes the status the API serves, and the persisted hash that is each topic's
 * token. The download is the content manager's, the database swap the sink's (cmcontent_utest).
 */

using namespace ioc::sync;
using namespace ::testing;

namespace
{

const base::Name STORE_NAME_IOCSYNC {"iocsync/status/0"};
const std::string URL_DOMAIN {"url_domain"};
const std::string HASH_MD5 {"hash_md5"};

std::string topicOf(const std::string& type)
{
    return cmcontent::iocTopic(type);
}

/// A persisted state for two types, each at its own hash.
json::Json stateDoc()
{
    json::Json doc {};
    doc.setArray();
    for (const auto& [type, hash] :
         std::vector<std::pair<std::string, std::string>> {{URL_DOMAIN, "hash-url"}, {HASH_MD5, "hash-md5"}})
    {
        json::Json entry {};
        entry.setString(type, "/ioc_type");
        entry.setString(hash, "/last_data_hash");
        entry.setInt64(1700000000, "/last_successful_update");
        doc.appendJson(entry);
    }
    return doc;
}

IocTypeStatus statusOf(const std::vector<IocTypeStatus>& all, const std::string& type)
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

class IocSyncTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit();
        ON_CALL(*store, existsDoc(STORE_NAME_IOCSYNC)).WillByDefault(Return(false));
        ON_CALL(*store, upsertDoc(STORE_NAME_IOCSYNC, _)).WillByDefault(Return(store::mocks::storeOk()));
        ON_CALL(*kvdb, exists(_)).WillByDefault(Return(true));
        // Every type other than the one a test scripts finds nothing new.
        for (const auto& type : ioc::kvdb::details::getSupportedIocTypes())
        {
            topics.scriptStatus(topicOf(std::string {type}), content_manager::CycleStatus::Unchanged);
        }
    }

    std::unique_ptr<IocSync> build(std::size_t attempts = 1)
    {
        return std::make_unique<IocSync>(
            kvdb, store, topics.factory(), cmcontent::Options {}, cmcontent::RetryPolicy {attempts, 0});
    }

    void withStoredState()
    {
        ON_CALL(*store, existsDoc(STORE_NAME_IOCSYNC)).WillByDefault(Return(true));
        ON_CALL(*store, readDoc(STORE_NAME_IOCSYNC)).WillByDefault(Return(store::mocks::storeReadDocResp(stateDoc())));
    }

    std::shared_ptr<NiceMock<ioc::kvdb::MockKVDBManager>> kvdb {
        std::make_shared<NiceMock<ioc::kvdb::MockKVDBManager>>()};
    std::shared_ptr<NiceMock<store::mocks::MockStore>> store {std::make_shared<NiceMock<store::mocks::MockStore>>()};
    cmcontent::mocks::FakeTopicRegistry topics;
};

} // namespace

TEST_F(IocSyncTest, RegistersOneTopicPerSupportedType)
{
    const auto sync = build();

    const auto supported = ioc::kvdb::details::getSupportedIocTypes();
    EXPECT_EQ(topics.registered().size(), supported.size());
    EXPECT_EQ(sync->getIocStatus().size(), supported.size());
    for (const auto& type : supported)
    {
        const auto spec = topics.specOf(topicOf(std::string {type}));
        ASSERT_TRUE(spec.readiness.has_value()) << type;
        EXPECT_EQ(spec.readiness->consumerId, cmcontent::IOC_CONSUMER_ID);
    }
}

TEST_F(IocSyncTest, EachTopicStartsFromItsPersistedHash)
{
    withStoredState();
    const auto sync = build();

    // A topic that started at "" would re-download every IOC on the first cycle after a restart.
    EXPECT_EQ(topics.tokenStoreOf(topicOf(URL_DOMAIN))->load(topicOf(URL_DOMAIN)), "hash-url");
    EXPECT_EQ(topics.tokenStoreOf(topicOf(HASH_MD5))->load(topicOf(HASH_MD5)), "hash-md5");

    const auto status = statusOf(sync->getIocStatus(), URL_DOMAIN);
    EXPECT_EQ(status.lastSuccessfulUpdate, 1700000000U);
    EXPECT_TRUE(status.available);
}

TEST_F(IocSyncTest, AcceptsTheStateUnderADatabasesKey)
{
    json::Json wrapped {};
    wrapped.setArray("/databases");
    const auto entries = stateDoc().getArray();
    ASSERT_TRUE(entries.has_value());
    for (const auto& entry : *entries)
    {
        wrapped.appendJson(entry, "/databases");
    }
    ON_CALL(*store, existsDoc(STORE_NAME_IOCSYNC)).WillByDefault(Return(true));
    ON_CALL(*store, readDoc(STORE_NAME_IOCSYNC)).WillByDefault(Return(store::mocks::storeReadDocResp(wrapped)));

    const auto sync = build();
    EXPECT_EQ(statusOf(sync->getIocStatus(), URL_DOMAIN).hash, "hash-url");
}

TEST_F(IocSyncTest, RejectsAnUnreadableState)
{
    json::Json invalid {};
    invalid.setString("nonsense", "/whatever");
    ON_CALL(*store, existsDoc(STORE_NAME_IOCSYNC)).WillByDefault(Return(true));
    ON_CALL(*store, readDoc(STORE_NAME_IOCSYNC)).WillByDefault(Return(store::mocks::storeReadDocResp(invalid)));

    EXPECT_THROW(build(), std::runtime_error);
}

TEST_F(IocSyncTest, AMissingDatabaseForcesAFullReload)
{
    withStoredState();
    const auto missing = std::string {ioc::kvdb::details::getDbNameFromType(URL_DOMAIN)};
    ON_CALL(*kvdb, exists(_)).WillByDefault(Invoke([missing](std::string_view name) { return name != missing; }));

    const auto sync = build();
    sync->synchronize();

    // A matching hash says the content has not moved, not that its database still exists.
    for (const auto& call : topics.calls())
    {
        EXPECT_EQ(call.request.forceFullReload, call.topic == topicOf(URL_DOMAIN)) << call.topic;
    }
}

TEST_F(IocSyncTest, ACommittedHashIsReportedAndPersisted)
{
    withStoredState();
    cmcontent::mocks::FakeTopicRegistry::Script updated;
    updated.outcome.status = content_manager::CycleStatus::Updated;
    updated.tokenToStore = "hash-url-v2";
    topics.script(topicOf(URL_DOMAIN), {updated});

    std::optional<json::Json> written;
    EXPECT_CALL(*store, upsertDoc(STORE_NAME_IOCSYNC, _))
        .WillOnce(
            [&written](const base::Name&, const json::Json& doc)
            {
                written.emplace(doc);
                return store::mocks::storeOk();
            });

    const auto sync = build();
    sync->synchronize();

    const auto status = statusOf(sync->getIocStatus(), URL_DOMAIN);
    EXPECT_EQ(status.hash, "hash-url-v2");
    EXPECT_EQ(status.status, base::SyncStatus::READY);
    EXPECT_GT(status.lastSuccessfulUpdate, 1700000000U);

    ASSERT_TRUE(written.has_value());
    const auto entries = written->getArray();
    ASSERT_TRUE(entries.has_value());
    bool found = false;
    for (const auto& entry : *entries)
    {
        std::string type;
        std::string hash;
        if (entry.getString(type, "/ioc_type") == json::RetGet::Success && type == URL_DOMAIN
            && entry.getString(hash, "/last_data_hash") == json::RetGet::Success)
        {
            found = true;
            EXPECT_EQ(hash, "hash-url-v2");
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(IocSyncTest, NothingChangedWritesNothing)
{
    withStoredState();
    EXPECT_CALL(*store, upsertDoc(_, _)).Times(0);

    const auto sync = build();
    sync->synchronize();
}

TEST_F(IocSyncTest, AFailedCycleIsReportedAndKeepsTheExistingVersion)
{
    withStoredState();
    topics.scriptStatus(topicOf(URL_DOMAIN), content_manager::CycleStatus::FailedTransport);

    const auto sync = build(/*attempts=*/2);
    sync->synchronize();

    EXPECT_EQ(topics.callCount(topicOf(URL_DOMAIN)), 2U) << "a failure is retried";
    const auto status = statusOf(sync->getIocStatus(), URL_DOMAIN);
    EXPECT_EQ(status.status, base::SyncStatus::FAILED);
    // The IOCs already on disk are still valid and still served.
    EXPECT_EQ(status.hash, "hash-url");
    EXPECT_TRUE(status.available);
}

TEST_F(IocSyncTest, ADeferralIsNotRetriedNorAFailure)
{
    topics.scriptStatus(topicOf(URL_DOMAIN), content_manager::CycleStatus::SkippedConsumerNotReady);

    const auto sync = build(/*attempts=*/3);
    sync->synchronize();

    EXPECT_EQ(topics.callCount(topicOf(URL_DOMAIN)), 1U);
    EXPECT_EQ(statusOf(sync->getIocStatus(), URL_DOMAIN).status, base::SyncStatus::READY);
}

TEST_F(IocSyncTest, ACycleThatDidNotRunLeavesTheStatusAlone)
{
    cmcontent::mocks::FakeTopicRegistry::Script failing;
    failing.outcome.status = content_manager::CycleStatus::FailedSink;
    cmcontent::mocks::FakeTopicRegistry::Script busy;
    busy.outcome.status = content_manager::CycleStatus::SkippedAlreadyRunning;
    topics.script(topicOf(URL_DOMAIN), {failing, busy});

    const auto sync = build();
    sync->synchronize();
    ASSERT_EQ(statusOf(sync->getIocStatus(), URL_DOMAIN).status, base::SyncStatus::FAILED);

    sync->synchronize();
    EXPECT_EQ(statusOf(sync->getIocStatus(), URL_DOMAIN).status, base::SyncStatus::FAILED);
}

TEST_F(IocSyncTest, ATypeWithNoDataIsNotAvailable)
{
    const auto sync = build();
    EXPECT_FALSE(statusOf(sync->getIocStatus(), URL_DOMAIN).available);
}

TEST_F(IocSyncTest, ShutdownStopsEveryTopicAndTheNextRun)
{
    const auto sync = build();

    sync->requestShutdown();

    EXPECT_EQ(topics.stopCount(topicOf(URL_DOMAIN)), 1U);
    EXPECT_EQ(topics.stopCount(topicOf(HASH_MD5)), 1U);

    sync->synchronize();
    EXPECT_TRUE(topics.calls().empty());
}

TEST_F(IocSyncTest, RefusesAMissingTopicFactory)
{
    EXPECT_THROW(IocSync(kvdb, store, {}, cmcontent::Options {}, cmcontent::RetryPolicy {}), std::invalid_argument);
}
