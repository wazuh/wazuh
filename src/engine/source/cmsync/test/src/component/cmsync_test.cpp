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
#include <cmcontent/contentTopic.hpp>
#include <cmcrud/mockcmcrud.hpp>
#include <cmsync/cmsync.hpp>
#include <contentIndexer.hpp>
#include <router/mockRouter.hpp>
#include <store/mockStore.hpp>

/*
 * Component-level: CMSync wired to real content registrations over the shared content manager, with
 * only the far ends (store, router, namespace store, indexer) faked. What this exercises is the
 * wiring: a registration per tracked space, a cycle driven end to end without throwing, and the
 * outcome landing in the status the API serves.
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
        return std::make_unique<cm::sync::CMSync>(crud,
                                                  store,
                                                  router,
                                                  cmcontent::defaultTopicFactory(indexer),
                                                  contentOptions(),
                                                  cmcontent::RetryPolicy {1, 0});
    }

    std::shared_ptr<EmptyIndexer> indexer {std::make_shared<EmptyIndexer>()};
    std::shared_ptr<::testing::NiceMock<cm::crud::MockCrudService>> crud;
    std::shared_ptr<::testing::NiceMock<store::mocks::MockStore>> store;
    std::shared_ptr<::testing::NiceMock<::router::mocks::MockRouterAPI>> router;
};

} // namespace

TEST_F(CMSyncComponentTest, RegistersOneTopicPerTrackedSpace)
{
    // Building twice proves the first instance released its registrations.
    {
        const auto first = create();
        ASSERT_EQ(first->getSpacesStatus().size(), 2U);
    }

    const auto second = create();
    EXPECT_EQ(second->getSpacesStatus().size(), 2U);
}

TEST_F(CMSyncComponentTest, AnEmptyIndexerDefersOrFindsNothingWithoutFailing)
{
    const auto sync = create();

    // `standard` waits for a consumer document the indexer does not have; `custom` finds no policy.
    // Neither is a failure, and nothing may escape: synchronize() runs on a scheduler worker.
    EXPECT_NO_THROW(sync->synchronize());

    for (const auto& entry : sync->getSpacesStatus())
    {
        EXPECT_EQ(entry.status, base::SyncStatus::READY) << entry.name;
        EXPECT_FALSE(entry.available) << entry.name;
    }
}

TEST_F(CMSyncComponentTest, ShutdownBeforeASyncRunsNothing)
{
    const auto sync = create();

    sync->requestShutdown();
    EXPECT_NO_THROW(sync->synchronize());
}
