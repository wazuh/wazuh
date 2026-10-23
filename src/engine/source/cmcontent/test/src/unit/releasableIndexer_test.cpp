// SPDX-License-Identifier: AGPL-3.0-or-later
#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <stdexcept>
#include <thread>

#include <gtest/gtest.h>

#include <cmcontent/releasableIndexer.hpp>

namespace
{

/// Counts calls; a search can be made to block until the test lets it return.
class CountingIndexer final : public content_manager::IContentIndexer
{
public:
    content_manager::ContentPit openPit(const std::vector<std::string>&, std::string_view, bool) override
    {
        ++calls;
        return content_manager::ContentPit {"pit", 0, "1m"};
    }

    void closePit(const content_manager::ContentPit&) noexcept override { ++calls; }

    nlohmann::json search(const content_manager::ContentPit&,
                          std::size_t,
                          const nlohmann::json&,
                          const nlohmann::json&,
                          const std::optional<nlohmann::json>&,
                          const std::optional<nlohmann::json>&,
                          const std::optional<nlohmann::json>&) override
    {
        ++calls;
        if (block)
        {
            entered.set_value();
            proceed.get_future().wait();
        }
        return nlohmann::json {{"hits", nlohmann::json::array()}};
    }

    nlohmann::json
    searchIndex(std::string_view, std::size_t, const nlohmann::json&, const std::optional<nlohmann::json>&) override
    {
        ++calls;
        return nlohmann::json::object();
    }

    std::atomic<int> calls {0};
    bool block {false};
    std::promise<void> entered;
    std::promise<void> proceed;
};

const content_manager::ContentPit PIT {"pit", 0, "1m"};

} // namespace

TEST(ReleasableIndexerTest, ForwardsEveryCall)
{
    auto inner = std::make_shared<CountingIndexer>();
    cmcontent::ReleasableIndexer indexer {inner};

    indexer.openPit({"index"}, "1m", false);
    indexer.search(PIT, 1, nlohmann::json::object(), nlohmann::json::array(), {}, {}, {});
    indexer.searchIndex("index", 1, nlohmann::json::object(), {});
    indexer.closePit(PIT);

    EXPECT_EQ(inner->calls, 4);
}

TEST(ReleasableIndexerTest, ReleaseDropsItsShareOfTheIndexer)
{
    auto inner = std::make_shared<CountingIndexer>();
    const std::weak_ptr<CountingIndexer> watch = inner;
    cmcontent::ReleasableIndexer indexer {std::move(inner)};

    indexer.release();

    // The topics keep the wrapper alive; the connector behind it must not be.
    EXPECT_TRUE(watch.expired());
}

TEST(ReleasableIndexerTest, AfterReleaseCallsFailLikeAnUnreachableIndexer)
{
    cmcontent::ReleasableIndexer indexer {std::make_shared<CountingIndexer>()};
    indexer.release();
    indexer.release(); // Idempotent.

    EXPECT_THROW(indexer.openPit({"index"}, "1m", false), std::runtime_error);
    EXPECT_THROW(indexer.search(PIT, 1, nlohmann::json::object(), nlohmann::json::array(), {}, {}, {}),
                 std::runtime_error);
    EXPECT_THROW(indexer.searchIndex("index", 1, nlohmann::json::object(), {}), std::runtime_error);
    EXPECT_NO_THROW(indexer.closePit(PIT));
}

TEST(ReleasableIndexerTest, ReleaseWaitsForACallInFlight)
{
    auto inner = std::make_shared<CountingIndexer>();
    inner->block = true;
    const std::weak_ptr<CountingIndexer> watch = inner;
    auto entered = inner->entered.get_future();
    cmcontent::ReleasableIndexer indexer {std::move(inner)};

    std::thread call {[&indexer]()
                      { indexer.search(PIT, 1, nlohmann::json::object(), nlohmann::json::array(), {}, {}, {}); }};
    entered.wait();

    auto released = std::async(std::launch::async, [&indexer]() { indexer.release(); });
    EXPECT_EQ(released.wait_for(std::chrono::milliseconds {100}), std::future_status::timeout)
        << "the connector must not go away under a running request";

    watch.lock()->proceed.set_value();
    call.join();
    released.get();
    EXPECT_TRUE(watch.expired());
}

TEST(ReleasableIndexerTest, RefusesANullIndexer)
{
    EXPECT_THROW(cmcontent::ReleasableIndexer {nullptr}, std::invalid_argument);
}
