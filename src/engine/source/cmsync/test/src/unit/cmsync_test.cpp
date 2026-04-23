#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/json.hpp>
#include <cmcrud/mockcmcrud.hpp>
#include <cmsync/cmsync.hpp>
#include <router/mockRouter.hpp>
#include <store/mockStore.hpp>
#include <wiconnector/mockswindexerconnector.hpp>

namespace
{

constexpr std::string_view STORE_ORIGIN_STANDARD = "standard";
constexpr std::string_view STORE_ORIGIN_CUSTOM = "custom";
const base::Name STORE_NAME_CMSYNC {"cmsync/status/0"};
constexpr size_t DEFAULT_ATTEMPTS = 3U;
constexpr size_t DEFAULT_WAIT_SECONDS = 5U;

json::Json createStoredState()
{
    json::Json state {};
    state.setArray();

    json::Json standard {};
    standard.setString(std::string(STORE_ORIGIN_STANDARD), "/origin_space");
    standard.setString("stored_standard_ns", "/namespace_id");
    state.appendJson(standard);

    json::Json custom {};
    custom.setString(std::string(STORE_ORIGIN_CUSTOM), "/origin_space");
    custom.setString("stored_custom_ns", "/namespace_id");
    state.appendJson(custom);

    return state;
}

json::Json createStoredStateWithNs(const std::string& space, const std::string& nsId)
{
    json::Json state {};
    state.setArray();

    json::Json entry {};
    entry.setString(space, "/origin_space");
    entry.setString(nsId, "/namespace_id");
    state.appendJson(entry);

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

class CMSyncConstructorTest : public ::testing::Test
{
protected:
    std::shared_ptr<::testing::StrictMock<wiconnector::mocks::MockWIndexerConnector>> indexer {
        std::make_shared<::testing::StrictMock<wiconnector::mocks::MockWIndexerConnector>>()};
    std::shared_ptr<::testing::StrictMock<cm::crud::MockCrudService>> crud {
        std::make_shared<::testing::StrictMock<cm::crud::MockCrudService>>()};
    std::shared_ptr<::testing::StrictMock<store::mocks::MockStore>> store {
        std::make_shared<::testing::StrictMock<store::mocks::MockStore>>()};
    std::shared_ptr<::testing::StrictMock<router::mocks::MockRouterAPI>> router {
        std::make_shared<::testing::StrictMock<router::mocks::MockRouterAPI>>()};
};

class CMSyncSynchronizeTest : public ::testing::Test
{
protected:
    std::shared_ptr<::testing::StrictMock<wiconnector::mocks::MockWIndexerConnector>> indexer {
        std::make_shared<::testing::StrictMock<wiconnector::mocks::MockWIndexerConnector>>()};
    std::shared_ptr<::testing::StrictMock<cm::crud::MockCrudService>> crud {
        std::make_shared<::testing::StrictMock<cm::crud::MockCrudService>>()};
    std::shared_ptr<::testing::StrictMock<store::mocks::MockStore>> store {
        std::make_shared<::testing::StrictMock<store::mocks::MockStore>>()};
    std::shared_ptr<::testing::StrictMock<router::mocks::MockRouterAPI>> router {
        std::make_shared<::testing::StrictMock<router::mocks::MockRouterAPI>>()};

    std::unique_ptr<cm::sync::CMSync> createSyncWithState(const json::Json& state)
    {
        EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(true));
        EXPECT_CALL(*store, readDoc(STORE_NAME_CMSYNC))
            .WillOnce(::testing::Return(store::mocks::storeReadDocResp(state)));

        return std::make_unique<cm::sync::CMSync>(indexer, crud, store, router, DEFAULT_ATTEMPTS, DEFAULT_WAIT_SECONDS);
    }
};

} // namespace

// ==================== Constructor Tests ====================

TEST_F(CMSyncConstructorTest, InitializesDefaultSpacesOnFirstSetup)
{
    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(false));
    EXPECT_CALL(*store,
                upsertDoc(STORE_NAME_CMSYNC,
                          ::testing::Truly(
                              [](const store::Doc& doc)
                              {
                                  const auto config = doc.getArray();
                                  return config.has_value() && config->size() == 2;
                              })))
        .WillOnce(::testing::Invoke(
            [](const base::Name&, const store::Doc& doc)
            {
                expectStateDocHasSpaces(doc, {std::string(STORE_ORIGIN_STANDARD), std::string(STORE_ORIGIN_CUSTOM)});
                return store::mocks::storeOk();
            }));

    EXPECT_NO_THROW((cm::sync::CMSync {indexer, crud, store, router, DEFAULT_ATTEMPTS, DEFAULT_WAIT_SECONDS}));
}

TEST_F(CMSyncConstructorTest, LoadsExistingStateWithoutReinitializingDefaults)
{
    const auto storedState = createStoredState();

    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(true));
    EXPECT_CALL(*store, readDoc(STORE_NAME_CMSYNC))
        .WillOnce(::testing::Return(store::mocks::storeReadDocResp(storedState)));
    EXPECT_CALL(*store, upsertDoc(::testing::_, ::testing::_)).Times(0);

    EXPECT_NO_THROW((cm::sync::CMSync {indexer, crud, store, router, DEFAULT_ATTEMPTS, DEFAULT_WAIT_SECONDS}));
}

TEST_F(CMSyncConstructorTest, LoadsExistingStateWithoutReinitializingDefaultsOnZeroAttempts)
{
    const auto storedState = createStoredState();

    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(true));
    EXPECT_CALL(*store, readDoc(STORE_NAME_CMSYNC))
        .WillOnce(::testing::Return(store::mocks::storeReadDocResp(storedState)));
    EXPECT_CALL(*store, upsertDoc(::testing::_, ::testing::_)).Times(0);

    EXPECT_NO_THROW((cm::sync::CMSync {indexer, crud, store, router, 0u, DEFAULT_WAIT_SECONDS}));
}

TEST_F(CMSyncConstructorTest, LoadsExistingStateWithoutReinitializingDefaultsOnZeroWaitSeconds)
{
    const auto storedState = createStoredState();

    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(true));
    EXPECT_CALL(*store, readDoc(STORE_NAME_CMSYNC))
        .WillOnce(::testing::Return(store::mocks::storeReadDocResp(storedState)));
    EXPECT_CALL(*store, upsertDoc(::testing::_, ::testing::_)).Times(0);

    EXPECT_NO_THROW((cm::sync::CMSync {indexer, crud, store, router, DEFAULT_ATTEMPTS, 0u}));
}

TEST_F(CMSyncConstructorTest, ThrowsWhenReadDocFailsDuringLoad)
{
    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(true));
    EXPECT_CALL(*store, readDoc(STORE_NAME_CMSYNC))
        .WillOnce(::testing::Return(store::mocks::storeReadError<store::Doc>()));

    EXPECT_THROW((cm::sync::CMSync {indexer, crud, store, router, DEFAULT_ATTEMPTS, DEFAULT_WAIT_SECONDS}),
                 std::runtime_error);
}

TEST_F(CMSyncConstructorTest, ThrowsWhenStoredStateIsNotArray)
{
    json::Json notArray {};
    notArray.setString("not an array");

    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(true));
    EXPECT_CALL(*store, readDoc(STORE_NAME_CMSYNC))
        .WillOnce(::testing::Return(store::mocks::storeReadDocResp(notArray)));

    EXPECT_THROW((cm::sync::CMSync {indexer, crud, store, router, DEFAULT_ATTEMPTS, DEFAULT_WAIT_SECONDS}),
                 std::runtime_error);
}

TEST_F(CMSyncConstructorTest, ThrowsWhenUpsertFailsOnFirstSetup)
{
    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(false));
    EXPECT_CALL(*store, upsertDoc(STORE_NAME_CMSYNC, ::testing::_))
        .WillOnce(::testing::Return(store::mocks::storeError()));

    EXPECT_THROW((cm::sync::CMSync {indexer, crud, store, router, DEFAULT_ATTEMPTS, DEFAULT_WAIT_SECONDS}),
                 std::runtime_error);
}

TEST_F(CMSyncConstructorTest, ThrowsWhenStoredEntryMissingOriginSpace)
{
    json::Json state {};
    state.setArray();
    json::Json badEntry {};
    badEntry.setString("some_ns", "/namespace_id");
    // No /origin_space field
    state.appendJson(badEntry);

    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(true));
    EXPECT_CALL(*store, readDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(store::mocks::storeReadDocResp(state)));

    EXPECT_THROW((cm::sync::CMSync {indexer, crud, store, router, DEFAULT_ATTEMPTS, DEFAULT_WAIT_SECONDS}),
                 std::runtime_error);
}

TEST_F(CMSyncConstructorTest, ThrowsWhenStoredEntryHasEmptyOriginSpace)
{
    json::Json state {};
    state.setArray();
    json::Json badEntry {};
    badEntry.setString("", "/origin_space");
    badEntry.setString("some_ns", "/namespace_id");
    state.appendJson(badEntry);

    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(true));
    EXPECT_CALL(*store, readDoc(STORE_NAME_CMSYNC)).WillOnce(::testing::Return(store::mocks::storeReadDocResp(state)));

    EXPECT_THROW((cm::sync::CMSync {indexer, crud, store, router, DEFAULT_ATTEMPTS, DEFAULT_WAIT_SECONDS}),
                 std::runtime_error);
}

// ==================== Synchronize Tests ====================

// Case: Space does not exist in remote — should skip
TEST_F(CMSyncSynchronizeTest, SkipsWhenSpaceDoesNotExistInRemote)
{
    auto state = createStoredStateWithNs("standard", "dummy_ns_id");
    auto sync = createSyncWithState(state);

    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(false));

    EXPECT_NO_THROW(sync->synchronize());
}

// Case 1: Policy disabled in indexer, route exists — deletes route and namespace
TEST_F(CMSyncSynchronizeTest, Case1_PolicyDisabledWithExistingRoute)
{
    auto state = createStoredStateWithNs("standard", "old_ns");
    auto sync = createSyncWithState(state);

    // existSpaceInRemote
    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(true));

    // getPolicyHashAndEnabledFromRemote → disabled
    EXPECT_CALL(*indexer, getPolicyHashAndEnabled(::testing::Eq("standard")))
        .WillOnce(::testing::Return(std::make_pair(std::string("hash1"), false)));

    // Route exists
    EXPECT_CALL(*router, existsEntry("cmsync_standard")).WillOnce(::testing::Return(true));
    auto entry = makeRouterEntry("cmsync_standard", "old_ns", 1, router::env::State::ENABLED, "hash1");
    EXPECT_CALL(*router, getEntry("cmsync_standard"))
        .WillOnce(::testing::Return(base::RespOrError<router::prod::Entry>(entry)));

    // Delete route
    EXPECT_CALL(*router, deleteEntry("cmsync_standard")).WillOnce(::testing::Return(std::nullopt));

    // Delete namespace
    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("old_ns"))).Times(1);

    // Dump state (sets dummy ns id)
    EXPECT_CALL(*store, upsertDoc(STORE_NAME_CMSYNC, ::testing::_))
        .WillOnce(::testing::Return(store::mocks::storeOk()));

    EXPECT_NO_THROW(sync->synchronize());
}

// Case 1: Policy disabled in indexer, no route — just skips
TEST_F(CMSyncSynchronizeTest, Case1_PolicyDisabledNoRoute)
{
    auto state = createStoredStateWithNs("standard", "dummy_ns_id");
    auto sync = createSyncWithState(state);

    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*indexer, getPolicyHashAndEnabled(::testing::Eq("standard")))
        .WillOnce(::testing::Return(std::make_pair(std::string("hash1"), false)));

    // No route
    EXPECT_CALL(*router, existsEntry("cmsync_standard")).WillOnce(::testing::Return(false));

    EXPECT_NO_THROW(sync->synchronize());
}

// Case 2: Policy enabled, hash unchanged — skips synchronization
TEST_F(CMSyncSynchronizeTest, Case2_PolicyEnabledHashUnchanged)
{
    auto state = createStoredStateWithNs("standard", "current_ns");
    auto sync = createSyncWithState(state);

    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*indexer, getPolicyHashAndEnabled(::testing::Eq("standard")))
        .WillOnce(::testing::Return(std::make_pair(std::string("same_hash"), true)));

    // Route exists with same hash
    EXPECT_CALL(*router, existsEntry("cmsync_standard")).WillOnce(::testing::Return(true));
    auto entry = makeRouterEntry("cmsync_standard", "current_ns", 1, router::env::State::ENABLED, "same_hash");
    EXPECT_CALL(*router, getEntry("cmsync_standard"))
        .WillOnce(::testing::Return(base::RespOrError<router::prod::Entry>(entry)));

    // No download, no route update
    EXPECT_NO_THROW(sync->synchronize());
}

// Case 3: Policy enabled, no route exists — full sync (download + create route)
TEST_F(CMSyncSynchronizeTest, Case3_PolicyEnabledNoRouteExists)
{
    auto state = createStoredStateWithNs("standard", "dummy_ns_id");
    auto sync = createSyncWithState(state);

    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*indexer, getPolicyHashAndEnabled(::testing::Eq("standard")))
        .WillOnce(::testing::Return(std::make_pair(std::string("new_hash"), true)));

    // Route does NOT exist (for synchronize's route check)
    EXPECT_CALL(*router, existsEntry("cmsync_standard"))
        .WillOnce(::testing::Return(false))  // routeConfig check
        .WillOnce(::testing::Return(false)); // syncNamespaceInRoute check

    // downloadAndEnrichNamespace: existsNamespace for generated ID
    EXPECT_CALL(*crud, existsNamespace(::testing::_)).WillOnce(::testing::Return(false));

    // getPolicy for download
    wiconnector::PolicyResources resources;
    EXPECT_CALL(*indexer, getPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(resources));

    // importNamespace
    EXPECT_CALL(
        *crud,
        importNamespace(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, true))
        .Times(1);

    // syncNamespaceInRoute: no existing route → create new
    EXPECT_CALL(*router, getEntries()).WillOnce(::testing::Return(std::list<router::prod::Entry> {}));
    EXPECT_CALL(*router, postEntry(::testing::_)).WillOnce(::testing::Return(std::nullopt));

    // Dump state after sync
    EXPECT_CALL(*store, upsertDoc(STORE_NAME_CMSYNC, ::testing::_))
        .WillOnce(::testing::Return(store::mocks::storeOk()));

    EXPECT_NO_THROW(sync->synchronize());
}

// Case 4: Policy enabled, hash changed — hot-swap + delete old namespace
TEST_F(CMSyncSynchronizeTest, Case4_PolicyEnabledHashChanged)
{
    auto state = createStoredStateWithNs("standard", "old_ns");
    auto sync = createSyncWithState(state);

    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*indexer, getPolicyHashAndEnabled(::testing::Eq("standard")))
        .WillOnce(::testing::Return(std::make_pair(std::string("new_hash"), true)));

    // Route exists with different hash
    auto entry = makeRouterEntry("cmsync_standard", "old_ns", 1, router::env::State::ENABLED, "old_hash");
    EXPECT_CALL(*router, existsEntry("cmsync_standard"))
        .WillOnce(::testing::Return(true))  // routeConfig check
        .WillOnce(::testing::Return(true)); // syncNamespaceInRoute check
    EXPECT_CALL(*router, getEntry("cmsync_standard"))
        .WillOnce(::testing::Return(base::RespOrError<router::prod::Entry>(entry)));

    // downloadAndEnrichNamespace
    EXPECT_CALL(*crud, existsNamespace(::testing::_)).WillOnce(::testing::Return(false));
    wiconnector::PolicyResources resources;
    EXPECT_CALL(*indexer, getPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(resources));
    EXPECT_CALL(
        *crud,
        importNamespace(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, true))
        .Times(1);

    // hot-swap
    EXPECT_CALL(*router, hotSwapNamespace("cmsync_standard", ::testing::_, ::testing::_))
        .WillOnce(::testing::Return(std::nullopt));

    // Dump state
    EXPECT_CALL(*store, upsertDoc(STORE_NAME_CMSYNC, ::testing::_))
        .WillOnce(::testing::Return(store::mocks::storeOk()));

    // Delete old namespace (old_ns != dummy_ns_id)
    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("old_ns"))).Times(1);

    EXPECT_NO_THROW(sync->synchronize());
}

// Case 4 variant: route exists but disabled (different hash) — should still sync
TEST_F(CMSyncSynchronizeTest, Case4_RouteDisabledHashChanged)
{
    auto state = createStoredStateWithNs("standard", "old_ns");
    auto sync = createSyncWithState(state);

    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*indexer, getPolicyHashAndEnabled(::testing::Eq("standard")))
        .WillOnce(::testing::Return(std::make_pair(std::string("new_hash"), true)));

    // Route exists but DISABLED — enabledRoute is false, so hash comparison is skipped → sync happens
    auto entry = makeRouterEntry("cmsync_standard", "old_ns", 1, router::env::State::DISABLED, "old_hash");
    EXPECT_CALL(*router, existsEntry("cmsync_standard"))
        .WillOnce(::testing::Return(true))
        .WillOnce(::testing::Return(true));
    EXPECT_CALL(*router, getEntry("cmsync_standard"))
        .WillOnce(::testing::Return(base::RespOrError<router::prod::Entry>(entry)));

    EXPECT_CALL(*crud, existsNamespace(::testing::_)).WillOnce(::testing::Return(false));
    wiconnector::PolicyResources resources;
    EXPECT_CALL(*indexer, getPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(resources));
    EXPECT_CALL(
        *crud,
        importNamespace(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, true))
        .Times(1);

    EXPECT_CALL(*router, hotSwapNamespace("cmsync_standard", ::testing::_, ::testing::_))
        .WillOnce(::testing::Return(std::nullopt));
    EXPECT_CALL(*store, upsertDoc(STORE_NAME_CMSYNC, ::testing::_))
        .WillOnce(::testing::Return(store::mocks::storeOk()));
    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("old_ns"))).Times(1);

    EXPECT_NO_THROW(sync->synchronize());
}

// Error: getEntry fails for existing route — should throw during synchronize (caught per-namespace)
TEST_F(CMSyncSynchronizeTest, ContinuesWhenGetEntryFails)
{
    auto state = createStoredStateWithNs("standard", "old_ns");
    auto sync = createSyncWithState(state);

    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*indexer, getPolicyHashAndEnabled(::testing::Eq("standard")))
        .WillOnce(::testing::Return(std::make_pair(std::string("hash1"), true)));

    EXPECT_CALL(*router, existsEntry("cmsync_standard")).WillOnce(::testing::Return(true));
    EXPECT_CALL(*router, getEntry("cmsync_standard"))
        .WillOnce(::testing::Return(base::RespOrError<router::prod::Entry>(base::Error {"route error"})));

    // The per-namespace catch block handles the error without throwing
    EXPECT_NO_THROW(sync->synchronize());
}

// Error: hot-swap fails — should rollback new namespace and continue
TEST_F(CMSyncSynchronizeTest, RollsBackWhenHotSwapFails)
{
    auto state = createStoredStateWithNs("standard", "old_ns");
    auto sync = createSyncWithState(state);

    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*indexer, getPolicyHashAndEnabled(::testing::Eq("standard")))
        .WillOnce(::testing::Return(std::make_pair(std::string("new_hash"), true)));

    auto entry = makeRouterEntry("cmsync_standard", "old_ns", 1, router::env::State::ENABLED, "old_hash");
    EXPECT_CALL(*router, existsEntry("cmsync_standard"))
        .WillOnce(::testing::Return(true))
        .WillOnce(::testing::Return(true));
    EXPECT_CALL(*router, getEntry("cmsync_standard"))
        .WillOnce(::testing::Return(base::RespOrError<router::prod::Entry>(entry)));

    EXPECT_CALL(*crud, existsNamespace(::testing::_)).WillOnce(::testing::Return(false));
    wiconnector::PolicyResources resources;
    EXPECT_CALL(*indexer, getPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(resources));
    EXPECT_CALL(
        *crud,
        importNamespace(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, true))
        .Times(1);

    // hot-swap fails
    EXPECT_CALL(*router, hotSwapNamespace("cmsync_standard", ::testing::_, ::testing::_))
        .WillOnce(::testing::Return(base::Error {"hot-swap failed"}));

    // Rollback: delete newly created namespace
    EXPECT_CALL(*crud, deleteNamespace(::testing::_)).Times(1);

    // Should not throw — error is caught per-namespace
    EXPECT_NO_THROW(sync->synchronize());
}

// Error: importNamespace fails during download — rolls back and rethrows (caught per-namespace)
TEST_F(CMSyncSynchronizeTest, ContinuesWhenImportNamespaceFails)
{
    auto state = createStoredStateWithNs("standard", "dummy_ns_id");
    auto sync = createSyncWithState(state);

    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*indexer, getPolicyHashAndEnabled(::testing::Eq("standard")))
        .WillOnce(::testing::Return(std::make_pair(std::string("new_hash"), true)));

    EXPECT_CALL(*router, existsEntry("cmsync_standard")).WillOnce(::testing::Return(false));

    EXPECT_CALL(*crud, existsNamespace(::testing::_)).WillOnce(::testing::Return(false));
    wiconnector::PolicyResources resources;
    EXPECT_CALL(*indexer, getPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(resources));

    // importNamespace throws
    EXPECT_CALL(
        *crud,
        importNamespace(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, true))
        .WillOnce(::testing::Throw(std::runtime_error("import failed")));

    // Rollback in downloadNamespace
    EXPECT_CALL(*crud, deleteNamespace(::testing::_)).Times(1);

    // Error caught per-namespace
    EXPECT_NO_THROW(sync->synchronize());
}

// Multiple spaces: one fails, other succeeds
TEST_F(CMSyncSynchronizeTest, ContinuesWithNextSpaceAfterFailure)
{
    auto state = createStoredState(); // standard + custom
    auto sync = createSyncWithState(state);

    // Standard — space does not exist in remote
    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(false));

    // Custom — enabled, no route, full sync
    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("custom"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*indexer, getPolicyHashAndEnabled(::testing::Eq("custom")))
        .WillOnce(::testing::Return(std::make_pair(std::string("hash_custom"), true)));

    EXPECT_CALL(*router, existsEntry("cmsync_custom"))
        .WillOnce(::testing::Return(false))
        .WillOnce(::testing::Return(false));

    EXPECT_CALL(*crud, existsNamespace(::testing::_)).WillOnce(::testing::Return(false));
    wiconnector::PolicyResources resources;
    EXPECT_CALL(*indexer, getPolicy(::testing::Eq("custom"))).WillOnce(::testing::Return(resources));
    EXPECT_CALL(
        *crud,
        importNamespace(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, true))
        .Times(1);

    EXPECT_CALL(*router, getEntries()).WillOnce(::testing::Return(std::list<router::prod::Entry> {}));
    EXPECT_CALL(*router, postEntry(::testing::_)).WillOnce(::testing::Return(std::nullopt));
    EXPECT_CALL(*store, upsertDoc(STORE_NAME_CMSYNC, ::testing::_))
        .WillOnce(::testing::Return(store::mocks::storeOk()));

    // Delete old namespace (stored_custom_ns != dummy_ns_id)
    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("stored_custom_ns"))).Times(1);

    EXPECT_NO_THROW(sync->synchronize());
}

// Edge case: dummy namespace ID not deleted after sync (old=dummy)
TEST_F(CMSyncSynchronizeTest, DoesNotDeleteDummyNamespaceAfterSync)
{
    auto state = createStoredStateWithNs("standard", "dummy_ns_id");
    auto sync = createSyncWithState(state);

    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*indexer, getPolicyHashAndEnabled(::testing::Eq("standard")))
        .WillOnce(::testing::Return(std::make_pair(std::string("hash1"), true)));

    EXPECT_CALL(*router, existsEntry("cmsync_standard"))
        .WillOnce(::testing::Return(false))
        .WillOnce(::testing::Return(false));

    EXPECT_CALL(*crud, existsNamespace(::testing::_)).WillOnce(::testing::Return(false));
    wiconnector::PolicyResources resources;
    EXPECT_CALL(*indexer, getPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(resources));
    EXPECT_CALL(
        *crud,
        importNamespace(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, true))
        .Times(1);

    EXPECT_CALL(*router, getEntries()).WillOnce(::testing::Return(std::list<router::prod::Entry> {}));
    EXPECT_CALL(*router, postEntry(::testing::_)).WillOnce(::testing::Return(std::nullopt));
    EXPECT_CALL(*store, upsertDoc(STORE_NAME_CMSYNC, ::testing::_))
        .WillOnce(::testing::Return(store::mocks::storeOk()));

    // StrictMock ensures deleteNamespace is NOT called (old ns = dummy)
    EXPECT_NO_THROW(sync->synchronize());
}

// Error: postEntry fails when creating a new route — should rollback new namespace
TEST_F(CMSyncSynchronizeTest, RollsBackWhenPostEntryFails)
{
    auto state = createStoredStateWithNs("standard", "dummy_ns_id");
    auto sync = createSyncWithState(state);

    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*indexer, getPolicyHashAndEnabled(::testing::Eq("standard")))
        .WillOnce(::testing::Return(std::make_pair(std::string("hash"), true)));

    EXPECT_CALL(*router, existsEntry("cmsync_standard"))
        .WillOnce(::testing::Return(false))
        .WillOnce(::testing::Return(false));

    EXPECT_CALL(*crud, existsNamespace(::testing::_)).WillOnce(::testing::Return(false));
    wiconnector::PolicyResources resources;
    EXPECT_CALL(*indexer, getPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(resources));
    EXPECT_CALL(
        *crud,
        importNamespace(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, true))
        .Times(1);

    EXPECT_CALL(*router, getEntries()).WillOnce(::testing::Return(std::list<router::prod::Entry> {}));
    EXPECT_CALL(*router, postEntry(::testing::_)).WillOnce(::testing::Return(base::Error {"post failed"}));

    // Rollback: delete the newly created namespace
    EXPECT_CALL(*crud, deleteNamespace(::testing::_)).Times(1);

    EXPECT_NO_THROW(sync->synchronize());
}

// Namespace ID collision during generation — retries until unique
TEST_F(CMSyncSynchronizeTest, RetriesNamespaceIdGenerationOnCollision)
{
    auto state = createStoredStateWithNs("standard", "dummy_ns_id");
    auto sync = createSyncWithState(state);

    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*indexer, getPolicyHashAndEnabled(::testing::Eq("standard")))
        .WillOnce(::testing::Return(std::make_pair(std::string("hash"), true)));

    EXPECT_CALL(*router, existsEntry("cmsync_standard"))
        .WillOnce(::testing::Return(false))
        .WillOnce(::testing::Return(false));

    // First generated ID already exists, second is unique
    EXPECT_CALL(*crud, existsNamespace(::testing::_))
        .WillOnce(::testing::Return(true))
        .WillOnce(::testing::Return(false));

    wiconnector::PolicyResources resources;
    EXPECT_CALL(*indexer, getPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(resources));
    EXPECT_CALL(
        *crud,
        importNamespace(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, true))
        .Times(1);

    EXPECT_CALL(*router, getEntries()).WillOnce(::testing::Return(std::list<router::prod::Entry> {}));
    EXPECT_CALL(*router, postEntry(::testing::_)).WillOnce(::testing::Return(std::nullopt));
    EXPECT_CALL(*store, upsertDoc(STORE_NAME_CMSYNC, ::testing::_))
        .WillOnce(::testing::Return(store::mocks::storeOk()));

    EXPECT_NO_THROW(sync->synchronize());
}

// ==================== Abort Tests ====================

// Abort before loop: shouldAbort returns true immediately — no remote calls should be made
TEST_F(CMSyncSynchronizeTest, AbortsBeforeLoopWhenShouldAbortReturnsTrue)
{
    auto state = createStoredState(); // standard + custom
    auto sync = createSyncWithState(state);

    // No expectations on indexer, crud, or router — nothing should be called
    EXPECT_NO_THROW(sync->synchronize([]() { return true; }));
}

// Abort mid-loop: shouldAbort returns true after the first namespace is processed
TEST_F(CMSyncSynchronizeTest, AbortsMidLoopAfterFirstNamespace)
{
    auto state = createStoredState(); // standard + custom
    auto sync = createSyncWithState(state);

    // Counter to abort after the first namespace check
    int callCount = 0;
    auto shouldAbort = [&callCount]()
    {
        // 1: before lock → false
        // 2: start of loop for "standard" → false
        // 3: executeWithRetry in existSpaceInRemote before attempt → false (existsPolicy returns false → skip)
        // 4: start of loop for "custom" → true (abort)
        return ++callCount > 3;
    };

    // Standard space: does not exist in remote — skipped quickly
    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(false));

    // Custom space: should NOT be called because abort triggers at start of second iteration

    EXPECT_NO_THROW(sync->synchronize(shouldAbort));
}

// Abort during download: shouldAbort triggers before downloadAndEnrichNamespace
TEST_F(CMSyncSynchronizeTest, AbortsBeforeDownload)
{
    auto state = createStoredStateWithNs("standard", "dummy_ns_id");
    auto sync = createSyncWithState(state);

    int callCount = 0;
    auto shouldAbort = [&callCount]()
    {
        // 1: before lock → false
        // 2: start of loop → false
        // 3: executeWithRetry in existSpaceInRemote → false (existsPolicy returns true)
        // 4: before getPolicyHashAndEnabled → false
        // 5: executeWithRetry in getPolicyHashAndEnabled → false
        // 6: before downloadAndEnrichNamespace → true (abort)
        return ++callCount > 5;
    };

    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*indexer, getPolicyHashAndEnabled(::testing::Eq("standard")))
        .WillOnce(::testing::Return(std::make_pair(std::string("new_hash"), true)));

    // No route exists — case 3 (new sync needed), but abort triggers before download
    EXPECT_CALL(*router, existsEntry("cmsync_standard")).WillOnce(::testing::Return(false));

    // No download or route sync should happen
    EXPECT_NO_THROW(sync->synchronize(shouldAbort));
}

// Abort during hot swap: shouldAbort causes hotSwapNamespace to return an error — rollback downloaded namespace
TEST_F(CMSyncSynchronizeTest, AbortsInHotSwapRollsBackNamespace)
{
    auto state = createStoredStateWithNs("standard", "stored_ns");
    auto sync = createSyncWithState(state);

    // shouldAbort always returns false at CMSync level, but hotSwapNamespace simulates abort by returning error
    auto shouldAbort = []()
    {
        return false;
    };

    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*indexer, getPolicyHashAndEnabled(::testing::Eq("standard")))
        .WillOnce(::testing::Return(std::make_pair(std::string("new_hash"), true)));

    // Route exists → hot swap path
    EXPECT_CALL(*router, existsEntry("cmsync_standard"))
        .WillOnce(::testing::Return(true))  // routeConfig check
        .WillOnce(::testing::Return(true)); // syncNamespaceInRoute check

    auto routeEntry = makeRouterEntry("cmsync_standard", "stored_ns", 1, router::env::State::ENABLED, "old_hash");
    EXPECT_CALL(*router, getEntry("cmsync_standard")).WillOnce(::testing::Return(routeEntry));

    EXPECT_CALL(*crud, existsNamespace(::testing::_)).WillOnce(::testing::Return(false));
    wiconnector::PolicyResources resources;
    EXPECT_CALL(*indexer, getPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(resources));
    EXPECT_CALL(
        *crud,
        importNamespace(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, true))
        .Times(1);

    // hotSwapNamespace returns abort error
    EXPECT_CALL(*router, hotSwapNamespace("cmsync_standard", ::testing::_, ::testing::_))
        .WillOnce(::testing::Return(base::Error {"Hot swap aborted"}));

    // Rollback: the downloaded namespace should be deleted after hot swap failure
    EXPECT_CALL(*crud, deleteNamespace(::testing::_)).Times(1);

    EXPECT_NO_THROW(sync->synchronize(shouldAbort));
}

// Default nullptr: synchronize without abort callback works as before
TEST_F(CMSyncSynchronizeTest, WorksWithNullAbortCallback)
{
    auto state = createStoredStateWithNs("standard", "dummy_ns_id");
    auto sync = createSyncWithState(state);

    EXPECT_CALL(*indexer, existsPolicy(::testing::Eq("standard"))).WillOnce(::testing::Return(false));

    EXPECT_NO_THROW(sync->synchronize(nullptr));
}
