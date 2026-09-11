#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/json.hpp>
#include <base/syncStatus.hpp>
#include <cmcontent/registration.hpp>
#include <cmcrud/mockcmcrud.hpp>
#include <cmsync/cmsync.hpp>
#include <router/mockRouter.hpp>
#include <store/mockStore.hpp>
#include <wiconnector/mockswindexerconnector.hpp>

/*
 * What is covered here, and what moved.
 *
 * The download itself — the PIT, the pagination, the consumer check, the per-space hash comparison —
 * is no longer part of this class; it is one content registration per space over the shared content
 * manager. The cases that used to live here as expectations on a deleted query surface now live
 * where the logic does: `cmcontent_utest` covers the sink that assembles a namespace and swaps it
 * into the router, and `content_manager_utest`/`content_manager_ctest` cover the cycle itself,
 * including consumer readiness and the token rules.
 *
 * What remains this class's own behaviour, and is covered below: which spaces are tracked, how
 * their state document is written and read back, and how the status the API serves is derived.
 */

namespace
{

constexpr std::string_view STORE_ORIGIN_STANDARD = "standard";
constexpr std::string_view STORE_ORIGIN_CUSTOM = "custom";
const base::Name STORE_NAME_CMSYNC {"cmsync/status/0"};
constexpr size_t DEFAULT_ATTEMPTS = 3U;
constexpr size_t DEFAULT_WAIT_SECONDS = 5U;

constexpr std::string_view STANDARD_CONSUMER_ID = "cti:catalog:consumer:ruleset";

/// Minimal-but-valid indexer settings. The content registrations build a session from these; a
/// session validates its configuration, but an UNREACHABLE host is not an error, so these tests do
/// not need an indexer to be running.
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

json::Json createStoredState()
{
    json::Json state {};
    state.setArray();

    json::Json standard {};
    standard.setString(std::string(STORE_ORIGIN_STANDARD), "/origin_space");
    standard.setString("stored_standard_ns", "/namespace_id");
    standard.setString(std::string(STANDARD_CONSUMER_ID), "/consumer_id");
    standard.setInt64(1700000000, "/last_successful_update");
    standard.setBool(true, "/enabled");
    state.appendJson(standard);

    json::Json custom {};
    custom.setString(std::string(STORE_ORIGIN_CUSTOM), "/origin_space");
    custom.setString("stored_custom_ns", "/namespace_id");
    state.appendJson(custom);

    return state;
}

void expectStateDocHasSpaces(const store::Doc& doc, const std::vector<std::string>& expectedSpaces)
{
    const auto config = doc.getArray();
    ASSERT_TRUE(config.has_value());
    ASSERT_EQ(config->size(), expectedSpaces.size());

    for (size_t i = 0; i < expectedSpaces.size(); ++i)
    {
        std::string origin;
        std::string nsId;
        ASSERT_EQ(json::RetGet::Success, config->at(i).getString(origin, "/origin_space"));
        ASSERT_EQ(json::RetGet::Success, config->at(i).getString(nsId, "/namespace_id"));
        EXPECT_EQ(origin, expectedSpaces.at(i));
        EXPECT_FALSE(nsId.empty());
    }
}

router::prod::Entry makeRouterEntry(const std::string& name,
                                    const std::string& nsId,
                                    std::size_t priority,
                                    router::env::State state,
                                    const std::string& hash)
{
    router::prod::EntryPost post(name, cm::store::NamespaceId(nsId), priority);
    router::prod::Entry entry(post);
    entry.status(state);
    entry.hash(hash);
    return entry;
}

class CMSyncTest : public ::testing::Test
{
protected:
    std::shared_ptr<::testing::NiceMock<wiconnector::mocks::MockWIndexerConnector>> indexer {
        std::make_shared<::testing::NiceMock<wiconnector::mocks::MockWIndexerConnector>>()};
    std::shared_ptr<::testing::NiceMock<cm::crud::MockCrudService>> crud {
        std::make_shared<::testing::NiceMock<cm::crud::MockCrudService>>()};
    std::shared_ptr<::testing::StrictMock<store::mocks::MockStore>> store {
        std::make_shared<::testing::StrictMock<store::mocks::MockStore>>()};
    std::shared_ptr<::testing::NiceMock<router::mocks::MockRouterAPI>> router {
        std::make_shared<::testing::NiceMock<router::mocks::MockRouterAPI>>()};

    void SetUp() override { logging::testInit(); }

    std::unique_ptr<cm::sync::CMSync> create()
    {
        return std::make_unique<cm::sync::CMSync>(
            indexer, crud, store, router, indexerConnection(), DEFAULT_ATTEMPTS, DEFAULT_WAIT_SECONDS, contentOptions());
    }
};

} // namespace

TEST_F(CMSyncTest, InitializesDefaultSpacesOnFirstSetup)
{
    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(false));
    EXPECT_CALL(*store, upsertDoc(STORE_NAME_CMSYNC, ::testing::_))
        .WillOnce(::testing::Invoke(
            [](const base::Name&, const store::Doc& doc)
            {
                expectStateDocHasSpaces(doc, {std::string(STORE_ORIGIN_STANDARD), std::string(STORE_ORIGIN_CUSTOM)});
                return store::mocks::storeOk();
            }));

    const auto sync = create();

    const auto status = sync->getSpacesStatus();
    ASSERT_EQ(status.size(), 2U);
    EXPECT_EQ(status[0].name, STORE_ORIGIN_STANDARD);
    EXPECT_EQ(status[1].name, STORE_ORIGIN_CUSTOM);
    // Nothing has been deployed yet, so nothing is available and nothing has failed.
    EXPECT_FALSE(status[0].available);
    EXPECT_EQ(status[0].status, base::SyncStatus::READY);
}

TEST_F(CMSyncTest, LoadsPersistedSpacesWithoutRewritingTheDocument)
{
    const auto state = createStoredState();

    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(true));
    EXPECT_CALL(*store, readDoc(STORE_NAME_CMSYNC))
        .WillOnce(::testing::Return(store::mocks::storeReadDocResp(state)));
    // No upsertDoc: loading is not a state change, and StrictMock would fail if one happened.
    ON_CALL(*router, existsEntry(::testing::_)).WillByDefault(::testing::Return(false));

    const auto sync = create();

    const auto status = sync->getSpacesStatus();
    ASSERT_EQ(status.size(), 2U);
    EXPECT_EQ(status[0].name, STORE_ORIGIN_STANDARD);
    EXPECT_EQ(status[0].lastSuccessfulUpdate, 1700000000U);
    // `enabled` is persisted; `available`/`hash` are live router state re-derived on the next sync.
    EXPECT_TRUE(status[0].enabled);
    EXPECT_FALSE(status[0].available);
}

TEST_F(CMSyncTest, ReconcilesRouteStateFromTheRouterOnStartup)
{
    const auto state = createStoredState();

    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(true));
    EXPECT_CALL(*store, readDoc(STORE_NAME_CMSYNC))
        .WillOnce(::testing::Return(store::mocks::storeReadDocResp(state)));

    ON_CALL(*router, existsEntry(std::string {"cmsync_standard"})).WillByDefault(::testing::Return(true));
    ON_CALL(*router, existsEntry(std::string {"cmsync_custom"})).WillByDefault(::testing::Return(false));
    ON_CALL(*router, getEntry(std::string {"cmsync_standard"}))
        .WillByDefault(::testing::Return(makeRouterEntry(
            "cmsync_standard", "stored_standard_ns", 1, router::env::State::ENABLED, "deployed-hash")));

    const auto sync = create();

    const auto status = sync->getSpacesStatus();
    ASSERT_EQ(status.size(), 2U);
    // A route that exists is reported as available with the hash actually deployed, so a restart
    // does not claim the ruleset is missing until the next sync proves otherwise.
    EXPECT_TRUE(status[0].available);
    EXPECT_EQ(status[0].hash, "deployed-hash");
    EXPECT_FALSE(status[1].available);
}

TEST_F(CMSyncTest, RejectsAMalformedStateDocument)
{
    json::Json notAnArray {};
    notAnArray.setString("nonsense", "/whatever");

    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(true));
    EXPECT_CALL(*store, readDoc(STORE_NAME_CMSYNC))
        .WillOnce(::testing::Return(store::mocks::storeReadDocResp(notAnArray)));

    EXPECT_THROW(create(), std::runtime_error);
}

TEST_F(CMSyncTest, RequestShutdownIsSafeBeforeAnySync)
{
    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(false));
    EXPECT_CALL(*store, upsertDoc(STORE_NAME_CMSYNC, ::testing::_))
        .WillOnce(::testing::Return(store::mocks::storeOk()));

    const auto sync = create();
    EXPECT_NO_THROW(sync->requestShutdown());
}

TEST_F(CMSyncTest, SynchronizeSkipsSpacesThatDoNotExistRemotely)
{
    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(false));
    EXPECT_CALL(*store, upsertDoc(STORE_NAME_CMSYNC, ::testing::_))
        .WillOnce(::testing::Return(store::mocks::storeOk()));

    const auto sync = create();

    // A space with no policy in the indexer has nothing to sync, and saying so costs one cheap
    // query instead of a PIT per space.
    ON_CALL(*indexer, existsPolicy(::testing::_)).WillByDefault(::testing::Return(false));

    EXPECT_NO_THROW(sync->synchronize());

    const auto status = sync->getSpacesStatus();
    ASSERT_EQ(status.size(), 2U);
    for (const auto& entry : status)
    {
        EXPECT_EQ(entry.status, base::SyncStatus::READY);
        EXPECT_FALSE(entry.available);
    }
}

TEST_F(CMSyncTest, SynchronizeSkipsWhenTheConsumerIsNotReady)
{
    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(false));
    EXPECT_CALL(*store, upsertDoc(STORE_NAME_CMSYNC, ::testing::_))
        .WillOnce(::testing::Return(store::mocks::storeOk()));

    const auto sync = create();

    ON_CALL(*indexer, existsPolicy(::testing::_)).WillByDefault(::testing::Return(true));
    ON_CALL(*indexer, isConsumerReadyForSync(::testing::_)).WillByDefault(::testing::Return(false));

    // The standard space has a consumer id, so this short-circuits it before any lease is taken.
    EXPECT_NO_THROW(sync->synchronize());
}
