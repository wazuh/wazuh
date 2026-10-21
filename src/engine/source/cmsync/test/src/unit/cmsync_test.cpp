// SPDX-License-Identifier: AGPL-3.0-or-later
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <variant>
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

/*
 * CMSync's own behaviour: which spaces are tracked, how a cycle's outcome becomes the status the API
 * serves, and what is persisted. The deployment itself is the sink's (cmcontent_utest), the cycle
 * the content manager's (content_manager_utest).
 */

using namespace ::testing;

namespace
{

constexpr std::string_view STANDARD = "standard";
constexpr std::string_view CUSTOM = "custom";
const base::Name STORE_NAME_CMSYNC {"cmsync/status/0"};

std::string topicOf(std::string_view space)
{
    return cmcontent::rulesetTopic(space);
}

std::string routeOf(std::string_view space)
{
    return cmcontent::RulesetSpaceSink::routeName(space);
}

router::prod::Entry routeServing(std::string_view space, const std::string& nsId, const std::string& hash)
{
    router::prod::EntryPost post(routeOf(space), cm::store::NamespaceId(nsId), 1);
    router::prod::Entry entry(post);
    entry.status(router::env::State::ENABLED);
    entry.hash(hash);
    return entry;
}

/// A persisted record for both spaces, as written by an earlier run (including fields no longer read).
json::Json storedState()
{
    json::Json state {};
    state.setArray();
    for (const auto& space : {STANDARD, CUSTOM})
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

content_manager::SessionInfo sessionOf(content_manager::SessionKind kind, bool enabled, const std::string& hash)
{
    content_manager::SessionInfo info;
    info.kind = kind;
    info.remoteToken = hash;
    info.probeMetadata = nlohmann::json {{"enabled", enabled}, {"integrations", nlohmann::json::array({"wazuh-core"})}};
    return info;
}

nlohmann::json policyPage(std::string_view space, const std::string& hash)
{
    return nlohmann::json::array({nlohmann::json {{"_id", "policy"},
                                                  {"_index", "wazuh-threatintel-policies-000001"},
                                                  {"_source",
                                                   {{"space", {{"name", space}, {"hash", {{"sha256", hash}}}}},
                                                    {"document", {{"name", "policy/wazuh/0"}, {"enabled", true}}}}}}});
}

cm::sync::SpaceStatus statusOf(const std::vector<cm::sync::SpaceStatus>& all, std::string_view space)
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

class CMSyncTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit();
        // `getEntry` returns a variant whose first alternative has no default constructor, so an
        // unstubbed call is a confusing failure: default to "no route", and stub getEntry where a
        // route exists.
        ON_CALL(*router, existsEntry(_)).WillByDefault(Return(false));
        ON_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillByDefault(Return(false));
        ON_CALL(*store, upsertDoc(STORE_NAME_CMSYNC, _)).WillByDefault(Return(store::mocks::storeOk()));
    }

    std::unique_ptr<cm::sync::CMSync> build(std::size_t attempts = 1)
    {
        return std::make_unique<cm::sync::CMSync>(
            crud, store, router, topics.factory(), cmcontent::Options {}, cmcontent::RetryPolicy {attempts, 0});
    }

    /// Start from a persisted record.
    void withStoredState()
    {
        ON_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillByDefault(Return(true));
        ON_CALL(*store, readDoc(STORE_NAME_CMSYNC))
            .WillByDefault(Return(store::mocks::storeReadDocResp(storedState())));
    }

    /// The route of @p space serves @p nsId at @p hash from now on.
    void serve(std::string_view space, const std::string& nsId, const std::string& hash)
    {
        ON_CALL(*router, existsEntry(routeOf(space))).WillByDefault(Return(true));
        ON_CALL(*router, getEntry(routeOf(space))).WillByDefault(Return(routeServing(space, nsId, hash)));
    }

    /// Capture the next persisted record.
    std::optional<json::Json>& capturePersisted()
    {
        EXPECT_CALL(*store, upsertDoc(STORE_NAME_CMSYNC, _))
            .WillOnce(
                [this](const base::Name&, const store::Doc& doc)
                {
                    m_persisted.emplace(doc);
                    return store::mocks::storeOk();
                });
        return m_persisted;
    }

    std::shared_ptr<NiceMock<cm::crud::MockCrudService>> crud {std::make_shared<NiceMock<cm::crud::MockCrudService>>()};
    std::shared_ptr<NiceMock<store::mocks::MockStore>> store {std::make_shared<NiceMock<store::mocks::MockStore>>()};
    std::shared_ptr<NiceMock<router::mocks::MockRouterAPI>> router {
        std::make_shared<NiceMock<router::mocks::MockRouterAPI>>()};
    cmcontent::mocks::FakeTopicRegistry topics;

private:
    std::optional<json::Json> m_persisted;
};

} // namespace

TEST_F(CMSyncTest, RegistersOneTopicPerTrackedSpace)
{
    const auto sync = build();

    EXPECT_THAT(topics.registered(), UnorderedElementsAre(topicOf(STANDARD), topicOf(CUSTOM)));

    // `standard` waits for its CTI consumer; nothing writes `custom`, so nothing gates it.
    const auto standard = topics.specOf(topicOf(STANDARD));
    ASSERT_TRUE(standard.readiness.has_value());
    EXPECT_EQ(standard.readiness->consumerId, cmcontent::RULESET_CONSUMER_ID);
    EXPECT_FALSE(topics.specOf(topicOf(CUSTOM)).readiness.has_value());
}

TEST_F(CMSyncTest, EachSpacesSinkIsAlsoItsTokenStore)
{
    // One record of what is deployed: the route. The token is its hash, read by the same object
    // that swaps it.
    serve(STANDARD, "ns_standard", "deployed-hash");
    const auto sync = build();

    const auto tokenStore = topics.tokenStoreOf(topicOf(STANDARD));
    ASSERT_NE(tokenStore, nullptr);
    const auto* asSink = dynamic_cast<cmcontent::RulesetSpaceSink*>(topics.sinkOf(topicOf(STANDARD)).get());
    ASSERT_NE(asSink, nullptr);
    EXPECT_EQ(dynamic_cast<cmcontent::RulesetSpaceSink*>(tokenStore.get()), asSink);
    EXPECT_EQ(tokenStore->load(topicOf(STANDARD)), "deployed-hash");
}

TEST_F(CMSyncTest, AFirstStartReportsBothSpacesReadyAndWritesNothing)
{
    EXPECT_CALL(*store, upsertDoc(_, _)).Times(0);
    const auto sync = build();

    const auto status = sync->getSpacesStatus();
    ASSERT_EQ(status.size(), 2U);
    EXPECT_EQ(statusOf(status, STANDARD).status, base::SyncStatus::READY);
    EXPECT_FALSE(statusOf(status, STANDARD).available);
}

TEST_F(CMSyncTest, LoadsThePersistedRecordAndTheDeployedRoute)
{
    withStoredState();
    serve(STANDARD, "ns_standard", "deployed-hash");
    EXPECT_CALL(*store, upsertDoc(_, _)).Times(0);

    const auto sync = build();

    const auto standard = statusOf(sync->getSpacesStatus(), STANDARD);
    EXPECT_EQ(standard.lastSuccessfulUpdate, 1700000000U);
    EXPECT_TRUE(standard.enabled);
    // The router says what is deployed, so a restart reports it without waiting for a sync.
    EXPECT_TRUE(standard.available);
    EXPECT_EQ(standard.hash, "deployed-hash");
    EXPECT_FALSE(statusOf(sync->getSpacesStatus(), CUSTOM).available);
}

TEST_F(CMSyncTest, RejectsAMalformedRecord)
{
    json::Json notAnArray {};
    notAnArray.setString("nonsense", "/whatever");
    ON_CALL(*store, existsDoc(STORE_NAME_CMSYNC)).WillByDefault(Return(true));
    ON_CALL(*store, readDoc(STORE_NAME_CMSYNC)).WillByDefault(Return(store::mocks::storeReadDocResp(notAnArray)));

    EXPECT_THROW(build(), std::runtime_error);
}

TEST_F(CMSyncTest, RefusesAMissingTopicFactory)
{
    EXPECT_THROW(cm::sync::CMSync(crud, store, router, {}, cmcontent::Options {}, cmcontent::RetryPolicy {}),
                 std::invalid_argument);
}

TEST_F(CMSyncTest, OrphanNamespacesAreCollectedAtStartup)
{
    serve(STANDARD, "cmsync_standard_live", "h");
    ON_CALL(*crud, listNamespaces())
        .WillByDefault(Return(std::vector<cm::store::NamespaceId> {cm::store::NamespaceId("cmsync_standard_live"),
                                                                   cm::store::NamespaceId("cmsync_standard_a1b2"),
                                                                   cm::store::NamespaceId("cmsync_custom_c3d4"),
                                                                   cm::store::NamespaceId("user_namespace")}));

    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("cmsync_standard_a1b2"))).Times(1);
    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("cmsync_custom_c3d4"))).Times(1);
    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("cmsync_standard_live"))).Times(0);
    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("user_namespace"))).Times(0);

    const auto sync = build();
}

TEST_F(CMSyncTest, ASuccessfulCycleIsReportedAndPersisted)
{
    cmcontent::mocks::FakeTopicRegistry::Script deployed;
    deployed.outcome.status = content_manager::CycleStatus::Updated;
    deployed.driveSink = [this](content_manager::IContentSink& sink)
    {
        ASSERT_EQ(sink.beginSession(sessionOf(content_manager::SessionKind::FullReload, true, "new-hash")),
                  content_manager::SessionDecision::Proceed);
        const auto hits = policyPage(STANDARD, "new-hash");
        content_manager::ContentPage page;
        page.hits = &hits;
        ASSERT_EQ(sink.acceptPage(page).status, content_manager::PageStatus::Accepted);
        ASSERT_EQ(sink.commit({}).status, content_manager::CommitStatus::Committed);
        serve(STANDARD, "cmsync_standard_new", "new-hash"); // What the route swap did.
    };
    topics.script(topicOf(STANDARD), {deployed});
    topics.scriptStatus(topicOf(CUSTOM), content_manager::CycleStatus::Unchanged);

    const auto sync = build();
    auto& persisted = capturePersisted();
    sync->synchronize();

    const auto status = statusOf(sync->getSpacesStatus(), STANDARD);
    EXPECT_EQ(status.status, base::SyncStatus::READY);
    EXPECT_TRUE(status.available);
    EXPECT_TRUE(status.enabled);
    EXPECT_EQ(status.hash, "new-hash");
    EXPECT_GT(status.lastSuccessfulUpdate, 0U);

    ASSERT_TRUE(persisted.has_value());
    const auto entries = persisted->getArray();
    ASSERT_TRUE(entries.has_value());
    ASSERT_EQ(entries->size(), 2U);
    std::string namespaceId;
    EXPECT_NE(entries->front().getString(namespaceId, std::string_view {"/namespace_id"}), json::RetGet::Success)
        << "the router records the namespace; the state document does not";
}

TEST_F(CMSyncTest, ADisabledPolicyIsReportedAndTheSpaceStaysTracked)
{
    serve(STANDARD, "ns_standard", "h");
    cmcontent::mocks::FakeTopicRegistry::Script disabled;
    disabled.outcome.status = content_manager::CycleStatus::Unchanged;
    disabled.driveSink = [this](content_manager::IContentSink& sink)
    {
        EXPECT_EQ(sink.beginSession(sessionOf(content_manager::SessionKind::FullReload, false, "any")),
                  content_manager::SessionDecision::Skip);
        ON_CALL(*router, existsEntry(routeOf(STANDARD))).WillByDefault(Return(false)); // The teardown.
    };
    topics.script(topicOf(STANDARD), {disabled});
    topics.scriptStatus(topicOf(CUSTOM), content_manager::CycleStatus::Unchanged);

    const auto sync = build();
    sync->synchronize();

    const auto status = statusOf(sync->getSpacesStatus(), STANDARD);
    EXPECT_FALSE(status.enabled);
    EXPECT_FALSE(status.available);
    EXPECT_EQ(status.status, base::SyncStatus::READY);
    // Re-enabling the policy upstream brings it back with no operator action.
    EXPECT_EQ(sync->getSpacesStatus().size(), 2U);
}

TEST_F(CMSyncTest, AFailureIsRetriedThenReportedAndClearedByTheNextGoodCycle)
{
    cmcontent::mocks::FakeTopicRegistry::Script failing;
    failing.outcome.status = content_manager::CycleStatus::FailedTransport;
    cmcontent::mocks::FakeTopicRegistry::Script unchanged;
    unchanged.outcome.status = content_manager::CycleStatus::Unchanged;
    topics.script(topicOf(STANDARD), {failing, failing, unchanged});
    topics.scriptStatus(topicOf(CUSTOM), content_manager::CycleStatus::Unchanged);

    const auto sync = build(/*attempts=*/2);
    sync->synchronize();

    EXPECT_EQ(topics.callCount(topicOf(STANDARD)), 2U);
    EXPECT_EQ(statusOf(sync->getSpacesStatus(), STANDARD).status, base::SyncStatus::FAILED);
    EXPECT_EQ(statusOf(sync->getSpacesStatus(), CUSTOM).status, base::SyncStatus::READY);

    sync->synchronize();
    EXPECT_EQ(statusOf(sync->getSpacesStatus(), STANDARD).status, base::SyncStatus::READY);
}

TEST_F(CMSyncTest, ADeferralIsNotRetriedNorAFailure)
{
    topics.scriptStatus(topicOf(STANDARD), content_manager::CycleStatus::SkippedConsumerNotReady);
    topics.scriptStatus(topicOf(CUSTOM), content_manager::CycleStatus::Unchanged);

    const auto sync = build(/*attempts=*/3);
    sync->synchronize();

    // The deployed ruleset is still in force; the next scheduled run is the retry.
    EXPECT_EQ(topics.callCount(topicOf(STANDARD)), 1U);
    EXPECT_EQ(statusOf(sync->getSpacesStatus(), STANDARD).status, base::SyncStatus::READY);
}

TEST_F(CMSyncTest, ACycleThatDidNotRunLeavesTheStatusAlone)
{
    cmcontent::mocks::FakeTopicRegistry::Script failing;
    failing.outcome.status = content_manager::CycleStatus::FailedSink;
    cmcontent::mocks::FakeTopicRegistry::Script busy;
    busy.outcome.status = content_manager::CycleStatus::SkippedAlreadyRunning;
    topics.script(topicOf(STANDARD), {failing, busy});
    topics.scriptStatus(topicOf(CUSTOM), content_manager::CycleStatus::Unchanged);

    const auto sync = build();
    sync->synchronize();
    ASSERT_EQ(statusOf(sync->getSpacesStatus(), STANDARD).status, base::SyncStatus::FAILED);

    // Nothing ran, so nothing was observed: the last real result stands.
    sync->synchronize();
    EXPECT_EQ(statusOf(sync->getSpacesStatus(), STANDARD).status, base::SyncStatus::FAILED);
}

TEST_F(CMSyncTest, ShutdownStopsEveryTopicAndTheNextRun)
{
    const auto sync = build();

    sync->requestShutdown();

    EXPECT_EQ(topics.stopCount(topicOf(STANDARD)), 1U);
    EXPECT_EQ(topics.stopCount(topicOf(CUSTOM)), 1U);

    sync->synchronize();
    EXPECT_TRUE(topics.calls().empty());
}
