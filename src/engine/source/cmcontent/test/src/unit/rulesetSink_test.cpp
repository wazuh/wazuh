// SPDX-License-Identifier: AGPL-3.0-or-later
#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <cmcrud/mockcmcrud.hpp>
#include <router/mockRouter.hpp>

#include <cmcontent/rulesetSink.hpp>

using namespace cmcontent;
using namespace ::testing;

namespace
{

constexpr auto SPACE = "standard";
constexpr auto ROUTE = "cmsync_standard";

content_manager::SessionInfo sessionWith(content_manager::SessionKind kind, nlohmann::json metadata)
{
    content_manager::SessionInfo info;
    info.topic = "content.ruleset.standard";
    info.kind = kind;
    info.remoteToken = "remote-hash";
    info.probeMetadata = std::move(metadata);
    return info;
}

content_manager::SessionInfo sessionOf(content_manager::SessionKind kind,
                                       bool enabled = true,
                                       const std::vector<std::string>& integrations = {"int1"})
{
    return sessionWith(kind, nlohmann::json {{"enabled", enabled}, {"integrations", integrations}});
}

nlohmann::json hitOf(const std::string& index, nlohmann::json source)
{
    return nlohmann::json {{"_id", "doc-1"}, {"_index", index}, {"_source", std::move(source)}};
}

nlohmann::json policyHit()
{
    return hitOf("wazuh-threatintel-policies-000001",
                 nlohmann::json {{"space", {{"name", SPACE}, {"hash", {{"sha256", "remote-hash"}}}}},
                                 {"document", {{"name", "policy/wazuh/0"}, {"enabled", true}}}});
}

content_manager::ContentPage pageOf(const nlohmann::json& hits)
{
    content_manager::ContentPage page;
    page.topic = "content.ruleset.standard";
    page.hits = &hits;
    return page;
}

::router::prod::Entry routeServing(const std::string& namespaceId,
                                   const std::string& hash,
                                   ::router::env::State state = ::router::env::State::ENABLED)
{
    ::router::prod::EntryPost post(ROUTE, cm::store::NamespaceId(namespaceId), 1);
    ::router::prod::Entry entry(post);
    entry.status(state);
    entry.hash(hash);
    return entry;
}

class RulesetSpaceSinkTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit();
        crud = std::make_shared<NiceMock<cm::crud::MockCrudService>>();
        router = std::make_shared<NiceMock<::router::mocks::MockRouterAPI>>();
        sink = std::make_shared<RulesetSpaceSink>(crud, router, SPACE);

        ON_CALL(*crud, existsNamespace(_)).WillByDefault(Return(false));
        ON_CALL(*router, existsEntry(_)).WillByDefault(Return(false));
        ON_CALL(*router, getEntries()).WillByDefault(Return(std::list<::router::prod::Entry> {}));
        ON_CALL(*router, postEntry(_)).WillByDefault(Return(base::OptError {}));
        ON_CALL(*router, hotSwapNamespace(_, _)).WillByDefault(Return(base::OptError {}));
        ON_CALL(*router, deleteEntry(_)).WillByDefault(Return(base::OptError {}));
    }

    /// The route exists and serves @p namespaceId at @p hash.
    void serve(const std::string& namespaceId,
               const std::string& hash = "deployed-hash",
               ::router::env::State state = ::router::env::State::ENABLED)
    {
        ON_CALL(*router, existsEntry(std::string {ROUTE})).WillByDefault(Return(true));
        ON_CALL(*router, getEntry(std::string {ROUTE})).WillByDefault(Return(routeServing(namespaceId, hash, state)));
    }

    /// Open a full session and hand it one page holding the policy.
    void stagePolicy()
    {
        ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
                  content_manager::SessionDecision::Proceed);
        const auto hits = nlohmann::json::array({policyHit()});
        ASSERT_EQ(sink->acceptPage(pageOf(hits)).status, content_manager::PageStatus::Accepted);
    }

    std::shared_ptr<NiceMock<cm::crud::MockCrudService>> crud;
    std::shared_ptr<NiceMock<::router::mocks::MockRouterAPI>> router;
    std::shared_ptr<RulesetSpaceSink> sink;
};

} // namespace

TEST_F(RulesetSpaceSinkTest, TheRouteIsNamedAfterTheSpace)
{
    EXPECT_EQ(RulesetSpaceSink::routeName(SPACE), ROUTE);
}

TEST_F(RulesetSpaceSinkTest, ADisabledPolicyTearsDownTheRouteAndTheNamespaceItServes)
{
    serve("cmsync_standard_abcd");
    EXPECT_CALL(*router, deleteEntry(std::string {ROUTE})).Times(1);
    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("cmsync_standard_abcd"))).Times(1);

    EXPECT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload, /*enabled=*/false)),
              content_manager::SessionDecision::Skip);
    EXPECT_EQ(sink->deployment().enabled, false);
}

TEST_F(RulesetSpaceSinkTest, APolicyWithAnEmptyIntegrationListCountsAsDisabled)
{
    // `enabled` and the integration list are separate fields and can disagree; a policy with no
    // integrations would deploy a namespace that routes nothing.
    EXPECT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload, /*enabled=*/true, {})),
              content_manager::SessionDecision::Skip);
    EXPECT_EQ(sink->deployment().enabled, false);
}

TEST_F(RulesetSpaceSinkTest, AMalformedPolicyAbortsAndKeepsTheDeployedRuleset)
{
    serve("cmsync_standard_abcd");
    EXPECT_CALL(*router, deleteEntry(_)).Times(0);
    EXPECT_CALL(*crud, deleteNamespace(_)).Times(0);

    // One bad document must not stop event processing for the space.
    const std::vector<nlohmann::json> malformed {
        nlohmann::json {{"enabled", true}, {"integrations", nlohmann::json::object()}},
        nlohmann::json {{"enabled", true}, {"integrations", ""}},
        nlohmann::json {{"enabled", true}, {"integrations", nullptr}},
        nlohmann::json {{"enabled", true}},
        nlohmann::json {{"enabled", "yes"}, {"integrations", {"int1"}}},
        nlohmann::json {{"integrations", {"int1"}}},
        nlohmann::json::object()};
    for (const auto& metadata : malformed)
    {
        EXPECT_EQ(sink->beginSession(sessionWith(content_manager::SessionKind::FullReload, metadata)),
                  content_manager::SessionDecision::Abort)
            << metadata.dump();
    }
}

TEST_F(RulesetSpaceSinkTest, ASpaceWithNoPolicyInTheIndexerIsLeftAlone)
{
    serve("cmsync_standard_abcd");
    EXPECT_CALL(*router, deleteEntry(_)).Times(0);

    auto info = sessionWith(content_manager::SessionKind::NoChange, nlohmann::json::object());
    info.remoteToken.clear();

    EXPECT_EQ(sink->beginSession(info), content_manager::SessionDecision::Skip);
}

TEST_F(RulesetSpaceSinkTest, NoChangeIsSkippedWithoutStaging)
{
    EXPECT_CALL(*crud, existsNamespace(_)).Times(0);

    EXPECT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::NoChange)),
              content_manager::SessionDecision::Skip);
    EXPECT_EQ(sink->deployment().enabled, true);
}

TEST_F(RulesetSpaceSinkTest, AssemblesResourcesByIndexAndCreatesTheRoute)
{
    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    auto hits = nlohmann::json::array();
    hits.push_back(hitOf("wazuh-threatintel-kvdbs-000001", nlohmann::json {{"document", {{"name", "kvdb/a/0"}}}}));
    hits.push_back(
        hitOf("wazuh-threatintel-decoders-000001", nlohmann::json {{"document", {{"name", "decoder/a/0"}}}}));
    hits.push_back(hitOf("wazuh-threatintel-filters-000001", nlohmann::json {{"document", {{"name", "filter/a/0"}}}}));
    hits.push_back(
        hitOf("wazuh-threatintel-integrations-000001", nlohmann::json {{"document", {{"name", "integration/a/0"}}}}));
    hits.push_back(policyHit());
    ASSERT_EQ(sink->acceptPage(pageOf(hits)).status, content_manager::PageStatus::Accepted);

    EXPECT_CALL(*crud, importNamespace(_, SizeIs(1), SizeIs(1), SizeIs(1), SizeIs(1), _, true)).Times(1);
    EXPECT_CALL(*router, postEntry(_)).Times(1);
    EXPECT_CALL(*crud, deleteNamespace(_)).Times(0); // Nothing was deployed before.

    EXPECT_EQ(sink->commit({}).status, content_manager::CommitStatus::Committed);
}

TEST_F(RulesetSpaceSinkTest, AnExistingRouteIsHotSwappedAndTheNamespaceItServedRetired)
{
    serve("cmsync_standard_0000");
    stagePolicy();

    EXPECT_CALL(*router, hotSwapNamespace(std::string {ROUTE}, _)).Times(1);
    EXPECT_CALL(*router, postEntry(_)).Times(0);
    // The router names the namespace in force, whoever deployed it: nothing else keeps a copy.
    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("cmsync_standard_0000"))).Times(1);

    EXPECT_EQ(sink->commit({}).status, content_manager::CommitStatus::Committed);
}

TEST_F(RulesetSpaceSinkTest, APageWithoutAPolicyIsRejectedAsUnusableContent)
{
    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    auto hits = nlohmann::json::array(
        {hitOf("wazuh-threatintel-decoders-000001", nlohmann::json {{"document", {{"name", "decoder/a/0"}}}})});
    ASSERT_EQ(sink->acceptPage(pageOf(hits)).status, content_manager::PageStatus::Accepted);

    EXPECT_CALL(*crud, importNamespace(_, _, _, _, _, _, _)).Times(0);

    // RetryFull: without a policy there is nothing to route, which is a content problem.
    EXPECT_EQ(sink->commit({}).status, content_manager::CommitStatus::RejectedRetryFull);
}

TEST_F(RulesetSpaceSinkTest, APolicyWithoutAHashIsRejected)
{
    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    auto hits = nlohmann::json::array(
        {hitOf("wazuh-threatintel-policies-000001",
               nlohmann::json {{"space", {{"name", SPACE}}}, {"document", {{"name", "policy/wazuh/0"}}}})});

    EXPECT_EQ(sink->acceptPage(pageOf(hits)).status, content_manager::PageStatus::Reject);
}

TEST_F(RulesetSpaceSinkTest, AnUnrecognisedIndexIsRejected)
{
    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    auto hits = nlohmann::json::array({hitOf("something-else", nlohmann::json {{"document", {{"name", "x"}}}})});

    // Silently dropping it would deploy a namespace that is quietly missing resources.
    EXPECT_EQ(sink->acceptPage(pageOf(hits)).status, content_manager::PageStatus::Reject);
}

TEST_F(RulesetSpaceSinkTest, AFailedImportRollsBackTheStagingNamespace)
{
    stagePolicy();

    ON_CALL(*crud, importNamespace(_, _, _, _, _, _, _)).WillByDefault(Throw(std::runtime_error("import failed")));
    ON_CALL(*crud, existsNamespace(_)).WillByDefault(Return(true));
    EXPECT_CALL(*crud, deleteNamespace(_)).Times(1);

    EXPECT_EQ(sink->commit({}).status, content_manager::CommitStatus::RejectedRetrySame);
}

TEST_F(RulesetSpaceSinkTest, AFailedRouteSwapRollsBackTheImportedNamespace)
{
    stagePolicy();

    ON_CALL(*router, postEntry(_)).WillByDefault(Return(base::Error {"no priority available"}));
    ON_CALL(*crud, existsNamespace(_)).WillByDefault(Return(true));

    // The namespace was imported but nothing points at it, so it is garbage.
    EXPECT_CALL(*crud, deleteNamespace(_)).Times(1);

    EXPECT_EQ(sink->commit({}).status, content_manager::CommitStatus::RejectedRetrySame);
}

TEST_F(RulesetSpaceSinkTest, AbortDiscardsTheStagingNamespace)
{
    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    ON_CALL(*crud, existsNamespace(_)).WillByDefault(Return(true));
    EXPECT_CALL(*crud, deleteNamespace(_)).Times(1);

    sink->abort(content_manager::AbortReason::StopRequested, "shutting down");
}

TEST_F(RulesetSpaceSinkTest, DeadDependenciesAbortTheSession)
{
    RulesetSpaceSink orphan {std::weak_ptr<cm::crud::ICrudService> {}, std::weak_ptr<::router::IRouterAPI> {}, SPACE};

    EXPECT_EQ(orphan.beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Abort);
}

TEST_F(RulesetSpaceSinkTest, TheTokenIsTheHashTheEnabledRouteServes)
{
    // The invariant ruleset change detection rests on: the sink writes `space.hash.sha256` into the
    // policy it imports, the router reports it as the route's hash, and the next cycle compares the
    // remote hash against it.
    serve("cmsync_standard_abcd", "deployed-hash");
    EXPECT_EQ(sink->load("topic"), "deployed-hash");

    // Writes are no-ops: the route swap already recorded the hash.
    EXPECT_TRUE(sink->store("topic", "other"));
    EXPECT_TRUE(sink->clear("topic"));
    EXPECT_EQ(sink->load("topic"), "deployed-hash");
}

TEST_F(RulesetSpaceSinkTest, AMissingOrDisabledRouteReadsAsNoToken)
{
    // Nothing serving the space means the next cycle must rebuild it.
    EXPECT_TRUE(sink->load("topic").empty());

    serve("cmsync_standard_abcd", "deployed-hash", ::router::env::State::DISABLED);
    EXPECT_TRUE(sink->load("topic").empty());
}

TEST_F(RulesetSpaceSinkTest, TheDeploymentIsReadFromTheRouter)
{
    EXPECT_FALSE(sink->deployment().available);
    EXPECT_FALSE(sink->deployment().enabled.has_value()) << "no policy probed yet";

    serve("cmsync_standard_abcd", "deployed-hash");
    const auto deployment = sink->deployment();
    EXPECT_TRUE(deployment.available);
    EXPECT_EQ(deployment.hash, "deployed-hash");
}

TEST_F(RulesetSpaceSinkTest, OrphansAreTheSpacesNamespacesNoRouteServes)
{
    serve("cmsync_standard_live");
    ON_CALL(*crud, listNamespaces())
        .WillByDefault(Return(std::vector<cm::store::NamespaceId> {cm::store::NamespaceId("cmsync_standard_live"),
                                                                   cm::store::NamespaceId("cmsync_standard_a1b2"),
                                                                   cm::store::NamespaceId("cmsync_custom_c3d4"),
                                                                   cm::store::NamespaceId("user_namespace")}));

    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("cmsync_standard_a1b2"))).Times(1);
    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("cmsync_standard_live"))).Times(0);
    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("cmsync_custom_c3d4"))).Times(0); // Another space's.
    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("user_namespace"))).Times(0);

    sink->collectOrphanNamespaces();
}

TEST_F(RulesetSpaceSinkTest, WithNoRouteEveryNamespaceOfTheSpaceIsAnOrphan)
{
    ON_CALL(*crud, listNamespaces())
        .WillByDefault(Return(std::vector<cm::store::NamespaceId> {cm::store::NamespaceId("cmsync_standard_a1b2")}));
    EXPECT_CALL(*crud, deleteNamespace(cm::store::NamespaceId("cmsync_standard_a1b2"))).Times(1);

    sink->collectOrphanNamespaces();
}

TEST_F(RulesetSpaceSinkTest, AnUnreadableRouteCollectsNothing)
{
    // A dead namespace cannot be told from a deployed one without the route: deleting a live
    // ruleset is never worth the disk.
    ON_CALL(*router, existsEntry(std::string {ROUTE})).WillByDefault(Return(true));
    ON_CALL(*router, getEntry(std::string {ROUTE}))
        .WillByDefault(Return(base::RespOrError<::router::prod::Entry> {base::Error {"unreadable"}}));
    ON_CALL(*crud, listNamespaces())
        .WillByDefault(Return(std::vector<cm::store::NamespaceId> {cm::store::NamespaceId("cmsync_standard_a1b2")}));
    EXPECT_CALL(*crud, deleteNamespace(_)).Times(0);

    sink->collectOrphanNamespaces();
}
