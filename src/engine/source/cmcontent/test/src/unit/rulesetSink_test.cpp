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

content_manager::SessionInfo sessionOf(content_manager::SessionKind kind,
                                       bool enabled = true,
                                       const std::vector<std::string>& integrations = {"int1"})
{
    content_manager::SessionInfo info;
    info.topic = "content.ruleset.standard";
    info.kind = kind;
    info.remoteToken = "remote-hash";
    info.probeMetadata = nlohmann::json {{"enabled", enabled}, {"integrations", integrations}};
    return info;
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

class RulesetSpaceSinkTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit();
        crud = std::make_shared<NiceMock<cm::crud::MockCrudService>>();
        router = std::make_shared<NiceMock<::router::mocks::MockRouterAPI>>();
        sink = std::make_shared<RulesetSpaceSink>(crud, router, SPACE, ROUTE);

        ON_CALL(*crud, existsNamespace(_)).WillByDefault(Return(false));
        ON_CALL(*router, existsEntry(_)).WillByDefault(Return(false));
        ON_CALL(*router, getEntries()).WillByDefault(Return(std::list<::router::prod::Entry> {}));
        ON_CALL(*router, postEntry(_)).WillByDefault(Return(base::OptError {}));
        ON_CALL(*router, hotSwapNamespace(_, _)).WillByDefault(Return(base::OptError {}));
        ON_CALL(*router, deleteEntry(_)).WillByDefault(Return(base::OptError {}));
    }

    std::shared_ptr<NiceMock<cm::crud::MockCrudService>> crud;
    std::shared_ptr<NiceMock<::router::mocks::MockRouterAPI>> router;
    std::shared_ptr<RulesetSpaceSink> sink;
};

} // namespace

TEST_F(RulesetSpaceSinkTest, ADisabledPolicyTearsTheSpaceDown)
{
    const cm::store::NamespaceId current {"cmsync_standard_abcd"};
    sink->prepare(current);

    ON_CALL(*router, existsEntry(std::string {ROUTE})).WillByDefault(Return(true));
    EXPECT_CALL(*router, deleteEntry(std::string {ROUTE})).Times(1);
    EXPECT_CALL(*crud, deleteNamespace(current)).Times(1);

    EXPECT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload, /*enabled=*/false)),
              content_manager::SessionDecision::Skip);

    const auto outcome = sink->takeOutcome();
    EXPECT_TRUE(outcome.disabled);
    EXPECT_FALSE(outcome.routeAvailable);
}

TEST_F(RulesetSpaceSinkTest, APolicyWithoutIntegrationsCountsAsDisabled)
{
    sink->prepare(std::nullopt);
    ON_CALL(*router, existsEntry(std::string {ROUTE})).WillByDefault(Return(false));

    // `enabled` and the integration list are separate fields and can disagree; a policy with no
    // integrations would deploy a namespace that routes nothing.
    EXPECT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload, /*enabled=*/true, {})),
              content_manager::SessionDecision::Skip);
    EXPECT_TRUE(sink->takeOutcome().disabled);
}

TEST_F(RulesetSpaceSinkTest, NoChangeIsSkipped)
{
    sink->prepare(std::nullopt);
    ON_CALL(*router, existsEntry(std::string {ROUTE})).WillByDefault(Return(true));

    EXPECT_CALL(*crud, existsNamespace(_)).Times(0);

    EXPECT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::NoChange)),
              content_manager::SessionDecision::Skip);

    const auto outcome = sink->takeOutcome();
    EXPECT_TRUE(outcome.routeAvailable);
    EXPECT_EQ(outcome.hash, "remote-hash");
}

TEST_F(RulesetSpaceSinkTest, AssemblesResourcesByIndexAndPromotes)
{
    sink->prepare(std::nullopt);
    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    auto hits = nlohmann::json::array();
    hits.push_back(hitOf("wazuh-threatintel-kvdbs-000001", nlohmann::json {{"document", {{"name", "kvdb/a/0"}}}}));
    hits.push_back(hitOf("wazuh-threatintel-decoders-000001", nlohmann::json {{"document", {{"name", "decoder/a/0"}}}}));
    hits.push_back(hitOf("wazuh-threatintel-filters-000001", nlohmann::json {{"document", {{"name", "filter/a/0"}}}}));
    hits.push_back(
        hitOf("wazuh-threatintel-integrations-000001", nlohmann::json {{"document", {{"name", "integration/a/0"}}}}));
    hits.push_back(policyHit());

    ASSERT_EQ(sink->acceptPage(pageOf(hits)).status, content_manager::PageStatus::Accepted);

    // Every resource kind reaches the import in its own bucket, and the policy carries the hash the
    // router will later report back — which is how the next cycle recognises "already deployed".
    EXPECT_CALL(*crud,
                importNamespace(_,
                                SizeIs(1),  // kvdbs
                                SizeIs(1),  // decoders
                                SizeIs(1),  // filters
                                SizeIs(1),  // integrations
                                _,
                                true))
        .Times(1);
    EXPECT_CALL(*router, postEntry(_)).Times(1);

    content_manager::CommitInfo info;
    info.topic = "content.ruleset.standard";
    info.finalToken = "remote-hash";

    EXPECT_EQ(sink->commit(info).status, content_manager::CommitStatus::Committed);

    const auto outcome = sink->takeOutcome();
    EXPECT_TRUE(outcome.applied);
    EXPECT_EQ(outcome.hash, "remote-hash");
    EXPECT_TRUE(outcome.newNamespaceId.has_value());
}

TEST_F(RulesetSpaceSinkTest, AnExistingRouteIsHotSwappedAndTheOldNamespaceRemoved)
{
    const cm::store::NamespaceId previous {"cmsync_standard_0000"};
    sink->prepare(previous);

    ON_CALL(*router, existsEntry(std::string {ROUTE})).WillByDefault(Return(true));

    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    auto hits = nlohmann::json::array({policyHit()});
    ASSERT_EQ(sink->acceptPage(pageOf(hits)).status, content_manager::PageStatus::Accepted);

    EXPECT_CALL(*router, hotSwapNamespace(std::string {ROUTE}, _)).Times(1);
    EXPECT_CALL(*router, postEntry(_)).Times(0);
    EXPECT_CALL(*crud, deleteNamespace(previous)).Times(1);

    EXPECT_EQ(sink->commit({}).status, content_manager::CommitStatus::Committed);
}

TEST_F(RulesetSpaceSinkTest, APageWithoutAPolicyIsRejectedAsUnusableContent)
{
    sink->prepare(std::nullopt);
    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    auto hits = nlohmann::json::array(
        {hitOf("wazuh-threatintel-decoders-000001", nlohmann::json {{"document", {{"name", "decoder/a/0"}}}})});
    ASSERT_EQ(sink->acceptPage(pageOf(hits)).status, content_manager::PageStatus::Accepted);

    EXPECT_CALL(*crud, importNamespace(_, _, _, _, _, _, _)).Times(0);

    // RetryFull, not RetrySame: without a policy there is nothing to route, and that is a content
    // problem — the next cycle must re-fetch from scratch rather than trust the token.
    EXPECT_EQ(sink->commit({}).status, content_manager::CommitStatus::RejectedRetryFull);
}

TEST_F(RulesetSpaceSinkTest, APolicyWithoutAHashIsRejected)
{
    sink->prepare(std::nullopt);
    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    auto hits = nlohmann::json::array({hitOf("wazuh-threatintel-policies-000001",
                                             nlohmann::json {{"space", {{"name", SPACE}}},
                                                             {"document", {{"name", "policy/wazuh/0"}}}})});

    EXPECT_EQ(sink->acceptPage(pageOf(hits)).status, content_manager::PageStatus::Reject);
}

TEST_F(RulesetSpaceSinkTest, AnUnrecognisedIndexIsRejected)
{
    sink->prepare(std::nullopt);
    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    auto hits = nlohmann::json::array({hitOf("something-else", nlohmann::json {{"document", {{"name", "x"}}}})});

    // Silently dropping it would deploy a namespace that is quietly missing resources.
    EXPECT_EQ(sink->acceptPage(pageOf(hits)).status, content_manager::PageStatus::Reject);
}

TEST_F(RulesetSpaceSinkTest, AFailedImportRollsBackTheStagingNamespace)
{
    sink->prepare(std::nullopt);
    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    auto hits = nlohmann::json::array({policyHit()});
    ASSERT_EQ(sink->acceptPage(pageOf(hits)).status, content_manager::PageStatus::Accepted);

    ON_CALL(*crud, importNamespace(_, _, _, _, _, _, _)).WillByDefault(Throw(std::runtime_error("import failed")));
    ON_CALL(*crud, existsNamespace(_)).WillByDefault(Return(true));
    EXPECT_CALL(*crud, deleteNamespace(_)).Times(1);

    EXPECT_EQ(sink->commit({}).status, content_manager::CommitStatus::RejectedRetrySame);
    EXPECT_FALSE(sink->takeOutcome().applied);
}

TEST_F(RulesetSpaceSinkTest, AFailedRouteSwapRollsBackTheImportedNamespace)
{
    sink->prepare(std::nullopt);
    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    auto hits = nlohmann::json::array({policyHit()});
    ASSERT_EQ(sink->acceptPage(pageOf(hits)).status, content_manager::PageStatus::Accepted);

    ON_CALL(*router, postEntry(_)).WillByDefault(Return(base::Error {"no priority available"}));
    ON_CALL(*crud, existsNamespace(_)).WillByDefault(Return(true));

    // The namespace was imported but nothing points at it, so it is garbage. Leaving it would
    // accumulate one dead namespace per failed cycle.
    EXPECT_CALL(*crud, deleteNamespace(_)).Times(1);

    EXPECT_EQ(sink->commit({}).status, content_manager::CommitStatus::RejectedRetrySame);
}

TEST_F(RulesetSpaceSinkTest, AbortDiscardsTheStagingNamespace)
{
    sink->prepare(std::nullopt);
    ASSERT_EQ(sink->beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Proceed);

    ON_CALL(*crud, existsNamespace(_)).WillByDefault(Return(true));
    EXPECT_CALL(*crud, deleteNamespace(_)).Times(1);

    sink->abort(content_manager::AbortReason::StopRequested, "shutting down");
}

TEST_F(RulesetSpaceSinkTest, DeadDependenciesAbortTheSession)
{
    RulesetSpaceSink orphan {std::weak_ptr<cm::crud::ICrudService> {},
                             std::weak_ptr<::router::IRouterAPI> {},
                             SPACE,
                             ROUTE};

    EXPECT_EQ(orphan.beginSession(sessionOf(content_manager::SessionKind::FullReload)),
              content_manager::SessionDecision::Abort);
}
