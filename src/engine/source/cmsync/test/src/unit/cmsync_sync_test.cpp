#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/json.hpp>
#include <base/logging.hpp>
#include <base/syncStatus.hpp>
#include <cmcontent/fakeContentTopic.hpp>
#include <cmcontent/registration.hpp>
#include <cmcrud/mockcmcrud.hpp>
#include <cmsync/cmsync.hpp>
#include <router/mockRouter.hpp>
#include <store/mockStore.hpp>
#include <wiconnector/mockswindexerconnector.hpp>

/*
 * Orchestration coverage for CMSync: how a cycle's result becomes the space's persisted state and
 * the status the API serves. None of it could be reached before, because CMSync built a concrete
 * ContentRegister that opens real connections on construction; the injectable topic factory is what
 * makes it testable, and these are the cases the design document required be kept.
 */

using namespace ::testing;

namespace
{

constexpr std::string_view SPACE_STANDARD = "standard";
constexpr std::string_view SPACE_CUSTOM = "custom";
const base::Name STORE_NAME_CMSYNC {"cmsync/status/0"};
constexpr std::size_t DEFAULT_ATTEMPTS = 1U;
constexpr std::size_t DEFAULT_WAIT_SECONDS = 0U;

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

/// Persisted state: both default spaces, each already serving a namespace.
json::Json storedState()
{
    json::Json state {};
    state.setArray();

    for (const auto& space : {SPACE_STANDARD, SPACE_CUSTOM})
    {
        json::Json entry {};
        entry.setString(std::string {space}, "/origin_space");
        entry.setString("ns_" + std::string {space}, "/namespace_id");
        entry.setInt64(1700000000, "/last_successful_update");
        entry.setBool(true, "/enabled");
        state.appendJson(entry);
    }
    return state;
}

router::prod::Entry routerEntry(const std::string& routeName, const std::string& nsId, const std::string& hash)
{
    router::prod::EntryPost post(routeName, cm::store::NamespaceId(nsId), 1);
    router::prod::Entry entry(post);
    entry.status(router::env::State::ENABLED);
    entry.hash(hash);
    return entry;
}

/// The session a cycle announces to the ruleset sink.
content_manager::SessionInfo sessionOf(content_manager::SessionKind kind, bool enabled, const std::string& hash)
{
    content_manager::SessionInfo info;
    info.kind = kind;
    info.remoteToken = hash;
    info.probeMetadata = nlohmann::json {{"enabled", enabled},
                                         {"integrations", nlohmann::json::array({"wazuh-core"})}};
    return info;
}

/// One page carrying the policy document a space needs to be deployable.
nlohmann::json policyPage(const std::string& space, const std::string& hash)
{
    return nlohmann::json::array({nlohmann::json {
        {"_id", "policy"},
        {"_index", "wazuh-threatintel-policies-000001"},
        {"_source",
         {{"space", {{"name", space}, {"hash", {{"sha256", hash}}}}},
          {"document", {{"name", "policy/wazuh/0"}, {"enabled", true}}}}}}});
}

class CMSyncOrchestrationTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit();

        // Explicit rather than relying on gmock's bool default. `getEntry` returns
        // `RespOrError<Entry>`, whose first variant alternative is an Entry with no default
        // constructor — so reaching it unstubbed is a confusing runtime failure rather than a
        // compile error. Defaulting "no route exists" keeps every path that has not opted in from
        // getting there at all.
        ON_CALL(*router, existsEntry(_)).WillByDefault(Return(false));
    }

    std::unique_ptr<cm::sync::CMSync> build()
    {
        EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(Return(true));
        EXPECT_CALL(*store, readDoc(STORE_NAME_CMSYNC))
            .WillOnce(Return(store::mocks::storeReadDocResp(storedState())));

        return std::make_unique<cm::sync::CMSync>(indexer,
                                                  crud,
                                                  store,
                                                  router,
                                                  indexerConnection(),
                                                  DEFAULT_ATTEMPTS,
                                                  DEFAULT_WAIT_SECONDS,
                                                  contentOptions(),
                                                  topics.factory());
    }

    /// Let the per-space pre-flight through.
    void expectPreflightPasses()
    {
        ON_CALL(*indexer, existsPolicy(_)).WillByDefault(Return(true));
        ON_CALL(*indexer, isConsumerReadyForSync(_)).WillByDefault(Return(true));
    }

    static std::string topicOf(std::string_view space) { return cmcontent::rulesetTopic(space); }
    static std::string routeOf(std::string_view space) { return "cmsync_" + std::string {space}; }

    static cm::sync::SpaceStatus statusOf(const std::vector<cm::sync::SpaceStatus>& all, std::string_view space)
    {
        for (const auto& entry : all)
        {
            if (entry.name == space)
            {
                return entry;
            }
        }
        ADD_FAILURE() << "no status reported for space '" << space << "'";
        return {};
    }

    std::shared_ptr<NiceMock<wiconnector::mocks::MockWIndexerConnector>> indexer {
        std::make_shared<NiceMock<wiconnector::mocks::MockWIndexerConnector>>()};
    std::shared_ptr<NiceMock<cm::crud::MockCrudService>> crud {
        std::make_shared<NiceMock<cm::crud::MockCrudService>>()};
    std::shared_ptr<NiceMock<store::mocks::MockStore>> store {
        std::make_shared<NiceMock<store::mocks::MockStore>>()};
    std::shared_ptr<NiceMock<router::mocks::MockRouterAPI>> router {
        std::make_shared<NiceMock<router::mocks::MockRouterAPI>>()};

    cmcontent::mocks::FakeTopicRegistry topics;
};

} // namespace

TEST_F(CMSyncOrchestrationTest, RegistersOneTopicPerTrackedSpace)
{
    const auto sync = build();

    EXPECT_THAT(topics.registered(), UnorderedElementsAre(topicOf(SPACE_STANDARD), topicOf(SPACE_CUSTOM)));
}

TEST_F(CMSyncOrchestrationTest, TheTokenIsTheHashTheRouterIsActuallyServing)
{
    // This is the invariant the whole ruleset change detection rests on, and nothing else asserts
    // it: the sink writes `space.hash.sha256` into the policy it imports, the router reports that
    // as the deployed entry's hash, and the next cycle compares the remote hash against it. If the
    // two ever stop being the same string, every cycle becomes a full reload for ever, silently.
    ON_CALL(*router, existsEntry(routeOf(SPACE_STANDARD))).WillByDefault(Return(true));
    ON_CALL(*router, getEntry(routeOf(SPACE_STANDARD)))
        .WillByDefault(Return(routerEntry(routeOf(SPACE_STANDARD), "ns_standard", "deployed-hash")));

    const auto sync = build();

    const auto tokenStore = topics.tokenStoreOf(topicOf(SPACE_STANDARD));
    ASSERT_NE(tokenStore, nullptr);
    EXPECT_EQ(tokenStore->load(topicOf(SPACE_STANDARD)), "deployed-hash");
}

TEST_F(CMSyncOrchestrationTest, ARouteThatDisappearedReadsBackAsNoToken)
{
    ON_CALL(*router, existsEntry(_)).WillByDefault(Return(false));

    const auto sync = build();

    // The router is the source of truth for what is deployed. A route deleted out of band means
    // nothing is serving this space, so the next cycle must rebuild it rather than conclude the
    // content is unchanged and deliver nothing.
    EXPECT_TRUE(topics.tokenStoreOf(topicOf(SPACE_STANDARD))->load(topicOf(SPACE_STANDARD)).empty());
}

TEST_F(CMSyncOrchestrationTest, ADisabledRouteReadsBackAsNoToken)
{
    router::prod::EntryPost post(routeOf(SPACE_STANDARD), cm::store::NamespaceId("ns_standard"), 1);
    router::prod::Entry disabled(post);
    disabled.status(router::env::State::DISABLED);
    disabled.hash("deployed-hash");

    ON_CALL(*router, existsEntry(routeOf(SPACE_STANDARD))).WillByDefault(Return(true));
    ON_CALL(*router, getEntry(routeOf(SPACE_STANDARD))).WillByDefault(Return(disabled));

    const auto sync = build();

    // A disabled route is not serving the content it was built from, so it must not count as
    // "already at this hash".
    EXPECT_TRUE(topics.tokenStoreOf(topicOf(SPACE_STANDARD))->load(topicOf(SPACE_STANDARD)).empty());
}

TEST_F(CMSyncOrchestrationTest, ASuccessfulCycleRecordsTheNewNamespaceAndHash)
{
    expectPreflightPasses();
    ON_CALL(*router, existsEntry(_)).WillByDefault(Return(false));

    cmcontent::mocks::FakeTopicRegistry::Script deployed;
    deployed.outcome.status = content_manager::CycleStatus::Updated;
    deployed.driveSink = [](content_manager::IContentSink& sink)
    {
        ASSERT_EQ(sink.beginSession(sessionOf(content_manager::SessionKind::FullReload, true, "new-hash")),
                  content_manager::SessionDecision::Proceed);

        const auto hits = policyPage(std::string {SPACE_STANDARD}, "new-hash");
        content_manager::ContentPage page;
        page.hits = &hits;
        ASSERT_EQ(sink.acceptPage(page).status, content_manager::PageStatus::Accepted);

        ASSERT_EQ(sink.commit({}).status, content_manager::CommitStatus::Committed);
    };
    topics.script(topicOf(SPACE_STANDARD), {deployed});
    topics.scriptStatus(topicOf(SPACE_CUSTOM), content_manager::CycleStatus::Unchanged);

    const auto sync = build();
    sync->synchronize();

    const auto status = statusOf(sync->getSpacesStatus(), SPACE_STANDARD);
    EXPECT_EQ(status.status, base::SyncStatus::READY);
    EXPECT_TRUE(status.available);
    EXPECT_TRUE(status.enabled);
    EXPECT_EQ(status.hash, "new-hash");
}

TEST_F(CMSyncOrchestrationTest, ADisabledPolicyTearsTheSpaceDownAndKeepsItTracked)
{
    expectPreflightPasses();
    ON_CALL(*router, existsEntry(_)).WillByDefault(Return(true));
    ON_CALL(*router, getEntry(_)).WillByDefault(Return(routerEntry(routeOf(SPACE_STANDARD), "ns_standard", "h")));

    cmcontent::mocks::FakeTopicRegistry::Script disabled;
    disabled.outcome.status = content_manager::CycleStatus::Unchanged;
    disabled.driveSink = [](content_manager::IContentSink& sink)
    {
        // enabled == false means the space must stop being served, not merely stop updating.
        EXPECT_EQ(sink.beginSession(sessionOf(content_manager::SessionKind::FullReload, false, "any")),
                  content_manager::SessionDecision::Skip);
    };
    topics.script(topicOf(SPACE_STANDARD), {disabled});
    topics.scriptStatus(topicOf(SPACE_CUSTOM), content_manager::CycleStatus::Unchanged);

    const auto sync = build();
    sync->synchronize();

    const auto status = statusOf(sync->getSpacesStatus(), SPACE_STANDARD);
    EXPECT_FALSE(status.enabled);
    EXPECT_FALSE(status.available);
    // Still tracked: re-enabling the policy upstream must bring it back without an operator having
    // to re-add the space by hand.
    EXPECT_EQ(sync->getSpacesStatus().size(), 2U);
    EXPECT_EQ(status.status, base::SyncStatus::READY);
}

TEST_F(CMSyncOrchestrationTest, AFailedCycleMarksTheSpaceFailed)
{
    expectPreflightPasses();

    cmcontent::mocks::FakeTopicRegistry::Script failing;
    failing.outcome.status = content_manager::CycleStatus::FailedSink;
    failing.outcome.retryAfter = std::chrono::seconds {30};
    topics.script(topicOf(SPACE_STANDARD), {failing});
    topics.scriptStatus(topicOf(SPACE_CUSTOM), content_manager::CycleStatus::Unchanged);

    const auto sync = build();
    sync->synchronize();

    EXPECT_EQ(statusOf(sync->getSpacesStatus(), SPACE_STANDARD).status, base::SyncStatus::FAILED);
    EXPECT_EQ(statusOf(sync->getSpacesStatus(), SPACE_CUSTOM).status, base::SyncStatus::READY);
}

TEST_F(CMSyncOrchestrationTest, AnUpdateAlreadyRunningLeavesTheSpaceAlone)
{
    expectPreflightPasses();

    cmcontent::mocks::FakeTopicRegistry::Script busy;
    busy.outcome.status = content_manager::CycleStatus::SkippedAlreadyRunning;
    topics.script(topicOf(SPACE_STANDARD), {busy});
    topics.scriptStatus(topicOf(SPACE_CUSTOM), content_manager::CycleStatus::Unchanged);

    const auto sync = build();
    sync->synchronize();

    // Nothing ran, so nothing was observed. Reporting FAILED here would flip a healthy space purely
    // because the on-demand API had been used a moment earlier; reading the sink's outcome would
    // read the *other* cycle's.
    EXPECT_EQ(statusOf(sync->getSpacesStatus(), SPACE_STANDARD).status, base::SyncStatus::READY);
}

TEST_F(CMSyncOrchestrationTest, ARetryableOutcomeIsRetriedUpToTheConfiguredAttempts)
{
    expectPreflightPasses();

    cmcontent::mocks::FakeTopicRegistry::Script deferred;
    deferred.outcome.status = content_manager::CycleStatus::SkippedConsumerNotReady;
    deferred.outcome.retryAfter = std::chrono::seconds {60};
    topics.script(topicOf(SPACE_STANDARD), {deferred});
    topics.scriptStatus(topicOf(SPACE_CUSTOM), content_manager::CycleStatus::Unchanged);

    EXPECT_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillOnce(Return(true));
    EXPECT_CALL(*store, readDoc(STORE_NAME_CMSYNC))
        .WillOnce(Return(store::mocks::storeReadDocResp(storedState())));

    constexpr std::size_t ATTEMPTS = 3;
    const auto sync = std::make_unique<cm::sync::CMSync>(
        indexer, crud, store, router, indexerConnection(), ATTEMPTS, 0, contentOptions(), topics.factory());
    sync->synchronize();

    // runOnce reports by status and executeWithRetry retries on a thrown exception, so a non-zero
    // retryAfter is what the rethrow adapter keys on. A terminal outcome must not be retried.
    EXPECT_EQ(topics.callCount(topicOf(SPACE_STANDARD)), ATTEMPTS);
    EXPECT_EQ(topics.callCount(topicOf(SPACE_CUSTOM)), 1U);
}

TEST_F(CMSyncOrchestrationTest, ASpaceMissingFromTheIndexerIsSkippedWithoutACycle)
{
    ON_CALL(*indexer, existsPolicy(_)).WillByDefault(Return(false));

    const auto sync = build();
    sync->synchronize();

    EXPECT_TRUE(topics.calls().empty());
}

TEST_F(CMSyncOrchestrationTest, OrphanStagingNamespacesAreCollectedOnStartup)
{
    // A cycle killed between importNamespace and the route swap leaves a namespace nothing points
    // at, and the only reference to it died with the process.
    ON_CALL(*crud, listNamespaces())
        .WillByDefault(Return(std::vector<cm::store::NamespaceId> {cm::store::NamespaceId("ns_standard"),
                                                                   cm::store::NamespaceId("cmsync_standard_a1b2"),
                                                                   cm::store::NamespaceId("cmsync_custom_c3d4"),
                                                                   cm::store::NamespaceId("user_namespace")}));

    // Only ours, and only the ones not currently deployed.
    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("cmsync_standard_a1b2"))).Times(1);
    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("cmsync_custom_c3d4"))).Times(1);
    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("ns_standard"))).Times(0);
    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("user_namespace"))).Times(0);

    const auto sync = build();
}

TEST_F(CMSyncOrchestrationTest, ShutdownStopsEveryTopic)
{
    const auto sync = build();

    sync->requestShutdown();

    EXPECT_EQ(topics.stopCount(topicOf(SPACE_STANDARD)), 1U);
    EXPECT_EQ(topics.stopCount(topicOf(SPACE_CUSTOM)), 1U);

    sync->synchronize();
    EXPECT_TRUE(topics.calls().empty());
}
