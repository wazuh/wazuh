// SPDX-License-Identifier: AGPL-3.0-or-later
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/json.hpp>
#include <base/logging.hpp>
#include <base/syncStatus.hpp>
#include <cmcontent/registration.hpp>
#include <cmcrud/mockcmcrud.hpp>
#include <cmsync/cmsync.hpp>
#include <contentIndexer.hpp>
#include <router/mockRouter.hpp>
#include <store/mockStore.hpp>
#include <wiconnector/mockswindexerconnector.hpp>

/*
 * Component-level: CMSync wired to real content registrations over the shared content manager, with
 * only the far ends (store, router, namespace store, indexer) faked. The registrations are handed a
 * fake indexer, as production hands them the Engine's own (D1 of the content manager), so neither a
 * running indexer nor keystore credentials are needed. What this exercises is the wiring: that a
 * registration is created per tracked space, that a cycle can be driven end to end without
 * throwing, and that the outcome lands in the status the API serves.
 */

namespace
{

/**
 * @brief An indexer with nothing published on it.
 *
 * Answers rather than throws: an exception thrown here, in the test binary, and caught inside the
 * content manager's library would depend on RTTI matching across the two. "Nothing there" is what a
 * cycle sees on a fresh cluster, and it handles that as a deferral, not an error.
 */
class EmptyIndexer final : public content_manager::IContentIndexer
{
public:
    content_manager::ContentPit openPit(const std::vector<std::string>&, std::string_view keepAlive, bool) override
    {
        return content_manager::ContentPit {"pit", 0, std::string {keepAlive}};
    }

    void closePit(const content_manager::ContentPit&) noexcept override {}

    nlohmann::json search(const content_manager::ContentPit&,
                          std::size_t,
                          const nlohmann::json&,
                          const nlohmann::json&,
                          const std::optional<nlohmann::json>&,
                          const std::optional<nlohmann::json>&,
                          const std::optional<nlohmann::json>&) override
    {
        return nlohmann::json {{"hits", nlohmann::json::array()}};
    }

    nlohmann::json
    searchIndex(std::string_view, std::size_t, const nlohmann::json&, const std::optional<nlohmann::json>&) override
    {
        return nlohmann::json {{"hits", nlohmann::json::array()}};
    }
};

constexpr size_t DEFAULT_ATTEMPTS = 1U;
constexpr size_t DEFAULT_WAIT_SECONDS = 0U;

cmcontent::Options contentOptions()
{
    cmcontent::Options options;
    options.pageSize = 100;
    options.consumerRetrySeconds = 1;
    return options;
}

class CMSyncComponentTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit();

        indexer = std::make_shared<::testing::NiceMock<wiconnector::mocks::MockWIndexerConnector>>();
        crud = std::make_shared<::testing::NiceMock<cm::crud::MockCrudService>>();
        store = std::make_shared<::testing::NiceMock<store::mocks::MockStore>>();
        router = std::make_shared<::testing::NiceMock<::router::mocks::MockRouterAPI>>();

        ON_CALL(*store, existsDoc(::testing::_)).WillByDefault(::testing::Return(false));
        ON_CALL(*store, upsertDoc(::testing::_, ::testing::_))
            .WillByDefault(::testing::Return(store::mocks::storeOk()));
        ON_CALL(*router, existsEntry(::testing::_)).WillByDefault(::testing::Return(false));
    }

    std::unique_ptr<cm::sync::CMSync> create()
    {
        return std::make_unique<cm::sync::CMSync>(indexer,
                                                  crud,
                                                  store,
                                                  router,
                                                  std::make_shared<EmptyIndexer>(),
                                                  DEFAULT_ATTEMPTS,
                                                  DEFAULT_WAIT_SECONDS,
                                                  contentOptions());
    }

    std::shared_ptr<::testing::NiceMock<wiconnector::mocks::MockWIndexerConnector>> indexer;
    std::shared_ptr<::testing::NiceMock<cm::crud::MockCrudService>> crud;
    std::shared_ptr<::testing::NiceMock<store::mocks::MockStore>> store;
    std::shared_ptr<::testing::NiceMock<::router::mocks::MockRouterAPI>> router;
};

} // namespace

TEST_F(CMSyncComponentTest, RegistersOneTopicPerTrackedSpace)
{
    // One registration per space rather than one for the whole ruleset: the hash, the promotion and
    // the route are all already per-space. Constructing twice would collide on the topic names, so
    // this also proves the first instance released them.
    {
        const auto first = create();
        ASSERT_EQ(first->getSpacesStatus().size(), 2U);
    }

    const auto second = create();
    EXPECT_EQ(second->getSpacesStatus().size(), 2U);
}

TEST_F(CMSyncComponentTest, ACycleAgainstAnUnreachableIndexerFailsWithoutThrowing)
{
    const auto sync = create();

    // existsPolicy is the first thing a space's cycle does; making it throw simulates a dead
    // indexer. Nothing may escape: synchronize() runs on a scheduler worker.
    ON_CALL(*indexer, existsPolicy(::testing::_))
        .WillByDefault(::testing::Throw(std::runtime_error("connection refused")));

    EXPECT_NO_THROW(sync->synchronize());

    const auto status = sync->getSpacesStatus();
    ASSERT_EQ(status.size(), 2U);
    for (const auto& entry : status)
    {
        EXPECT_EQ(entry.status, base::SyncStatus::FAILED);
    }
}

TEST_F(CMSyncComponentTest, ShutdownInterruptsTheIteration)
{
    const auto sync = create();

    ON_CALL(*indexer, existsPolicy(::testing::_)).WillByDefault(::testing::Return(true));
    ON_CALL(*indexer, isConsumerReadyForSync(::testing::_)).WillByDefault(::testing::Return(false));

    sync->requestShutdown();
    EXPECT_NO_THROW(sync->synchronize());
}
