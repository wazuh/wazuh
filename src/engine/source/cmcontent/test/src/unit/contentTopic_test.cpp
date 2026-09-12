#include <atomic>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <cmcontent/contentTopic.hpp>

using namespace cmcontent;

TEST(TokenCellTest, StartsAtItsSeedAndRoundTrips)
{
    TokenCell cell {"hash-1"};
    EXPECT_EQ(cell.get(), "hash-1");

    cell.set("hash-2");
    EXPECT_EQ(cell.get(), "hash-2");
}

TEST(TokenCellTest, DefaultsToNoToken)
{
    EXPECT_TRUE(TokenCell {}.get().empty());
}

TEST(TokenCellTest, SurvivesConcurrentReadersAndWriters)
{
    // The cell exists precisely because the content cycle and the sync service touch the token from
    // different threads: a scheduled cycle runs on the service's thread, an on-demand one on a lane
    // worker. Under TSan this is the test that fails if the lock is ever dropped.
    TokenCell cell {"initial"};
    std::atomic<bool> go {false};
    std::vector<std::thread> threads;

    for (int writer = 0; writer < 4; ++writer)
    {
        threads.emplace_back(
            [&cell, &go, writer]
            {
                while (!go.load())
                {
                }
                for (int i = 0; i < 500; ++i)
                {
                    cell.set("hash-" + std::to_string(writer) + "-" + std::to_string(i));
                }
            });
    }
    for (int reader = 0; reader < 4; ++reader)
    {
        threads.emplace_back(
            [&cell, &go]
            {
                while (!go.load())
                {
                }
                for (int i = 0; i < 500; ++i)
                {
                    EXPECT_FALSE(cell.get().empty());
                }
            });
    }

    go.store(true);
    for (auto& thread : threads)
    {
        thread.join();
    }
}

TEST(CellTokenStoreTest, ReadsAndWritesThroughTheCell)
{
    auto cell = std::make_shared<TokenCell>("hash-1");
    auto store = cellTokenStore(cell);

    EXPECT_EQ(store->load("content.ioc.url_domain"), "hash-1");

    EXPECT_TRUE(store->store("content.ioc.url_domain", "hash-2"));
    EXPECT_EQ(cell->get(), "hash-2");
    EXPECT_EQ(store->load("content.ioc.url_domain"), "hash-2");
}

TEST(CellTokenStoreTest, ClearEmptiesTheCell)
{
    auto cell = std::make_shared<TokenCell>("hash-1");
    auto store = cellTokenStore(cell);

    // "No token" is what makes the next cycle a full reload, and for a hash-tracked topic that is
    // exactly an empty hash — there is no separate absent state to represent.
    EXPECT_TRUE(store->clear("content.ioc.url_domain"));
    EXPECT_TRUE(cell->get().empty());
}

TEST(CellTokenStoreTest, KeepsTheCellAliveOnItsOwn)
{
    std::weak_ptr<TokenCell> weak;
    std::shared_ptr<content_manager::IContentTokenStore> store;
    {
        auto cell = std::make_shared<TokenCell>("hash-1");
        weak = cell;
        store = cellTokenStore(cell);
    }

    // The registration outlives the local handle the service built it from; a store holding a raw
    // reference would read freed memory on the next cycle.
    ASSERT_FALSE(weak.expired());
    EXPECT_EQ(store->load("topic"), "hash-1");
}

TEST(DerivedTokenStoreTest, ReadsFromTheLoaderAndDiscardsWrites)
{
    std::string deployed {"route-hash"};
    auto store = derivedTokenStore([&deployed] { return deployed; });

    EXPECT_EQ(store->load("content.ruleset.standard"), "route-hash");

    deployed = "route-hash-2";
    EXPECT_EQ(store->load("content.ruleset.standard"), "route-hash-2");

    // Nothing to write: the token is a property of state the commit already changed, so a second
    // copy could only ever disagree with the first.
    EXPECT_TRUE(store->store("content.ruleset.standard", "ignored"));
    EXPECT_EQ(store->load("content.ruleset.standard"), "route-hash-2");
}

TEST(DerivedTokenStoreTest, AThrowingLoaderReadsAsNoToken)
{
    auto store = derivedTokenStore([]() -> std::string { throw std::runtime_error("router is gone"); });

    // Never across the DSO boundary: the contract is noexcept, so a host that cannot answer must
    // degrade to "no token" — which costs a full reload, not a crash.
    EXPECT_TRUE(store->load("content.ruleset.standard").empty());
}
