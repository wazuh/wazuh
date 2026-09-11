// SPDX-License-Identifier: AGPL-3.0-or-later
#include <atomic>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <base/logging.hpp>
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

namespace
{

/// Records every dispatch and holds its completion, so a test decides when each one "finishes".
class FakeLane
{
public:
    OnDemandDispatch dispatch()
    {
        return [this](const std::string& topic,
                      content_manager::RunRequest request,
                      std::function<void(content_manager::OnDemandResult)> completion)
        {
            topics.push_back(topic);
            requests.push_back(request);
            pending.push_back(std::move(completion));
        };
    }

    /// Finish the oldest dispatch that has not been answered yet.
    void answerNext(content_manager::OnDemandCode code)
    {
        ASSERT_LT(answered, pending.size());
        auto completion = std::move(pending[answered++]);
        completion(content_manager::OnDemandResult {code, "detail"});
    }

    std::vector<std::string> topics;
    std::vector<content_manager::RunRequest> requests;
    std::vector<std::function<void(content_manager::OnDemandResult)>> pending;
    std::size_t answered {0};
};

class OnDemandSequenceTest : public ::testing::Test
{
protected:
    void SetUp() override { logging::testInit(); }

    FakeLane lane;
};

} // namespace

TEST_F(OnDemandSequenceTest, QueuesOneTopicAtATimeInOrder)
{
    // Six topics, as the IOC sync registers: all at once would not fit a lane four slots deep.
    const std::vector<std::string> topics {"t1", "t2", "t3", "t4", "t5", "t6"};
    requestOnDemandInSequence(topics, "test", lane.dispatch());

    for (std::size_t done = 0; done < topics.size(); ++done)
    {
        // Only ever one in flight: the next is queued by the previous one's completion.
        ASSERT_EQ(lane.topics.size(), done + 1);
        EXPECT_EQ(lane.topics.back(), topics[done]);
        EXPECT_TRUE(lane.requests.back().onDemand);
        EXPECT_FALSE(lane.requests.back().forceFullReload);
        lane.answerNext(content_manager::OnDemandCode::Completed);
    }

    EXPECT_EQ(lane.topics, topics);
}

TEST_F(OnDemandSequenceTest, AFullLaneEndsTheSequence)
{
    requestOnDemandInSequence({"t1", "t2", "t3"}, "test", lane.dispatch());

    lane.answerNext(content_manager::OnDemandCode::Completed);
    lane.answerNext(content_manager::OnDemandCode::QueueFull);

    // Whatever rejected t2 would reject t3 too; the sequence stops and says so instead of trying.
    EXPECT_EQ(lane.topics, (std::vector<std::string> {"t1", "t2"}));
}

TEST_F(OnDemandSequenceTest, AShuttingDownLaneEndsTheSequence)
{
    requestOnDemandInSequence({"t1", "t2"}, "test", lane.dispatch());

    lane.answerNext(content_manager::OnDemandCode::ShuttingDown);

    EXPECT_EQ(lane.topics, (std::vector<std::string> {"t1"}));
}

TEST_F(OnDemandSequenceTest, OneTopicThatCannotRunDoesNotStopTheRest)
{
    requestOnDemandInSequence({"t1", "t2", "t3", "t4"}, "test", lane.dispatch());

    lane.answerNext(content_manager::OnDemandCode::AlreadyRunning);
    lane.answerNext(content_manager::OnDemandCode::Failed);
    lane.answerNext(content_manager::OnDemandCode::UnknownTopic);
    lane.answerNext(content_manager::OnDemandCode::Completed);

    EXPECT_EQ(lane.topics, (std::vector<std::string> {"t1", "t2", "t3", "t4"}));
}

TEST_F(OnDemandSequenceTest, AnInlineAnswerQueuesTheNextOnTheSameCall)
{
    // A rejection is answered inside dispatch itself; the next topic must still be queued.
    std::vector<std::string> seen;
    requestOnDemandInSequence(
        {"t1", "t2", "t3"},
        "test",
        [&seen](const std::string& topic,
                content_manager::RunRequest,
                std::function<void(content_manager::OnDemandResult)> completion)
        {
            seen.push_back(topic);
            completion(content_manager::OnDemandResult {content_manager::OnDemandCode::AlreadyRunning, "running"});
        });

    EXPECT_EQ(seen, (std::vector<std::string> {"t1", "t2", "t3"}));
}

TEST_F(OnDemandSequenceTest, NoTopicsDispatchesNothing)
{
    requestOnDemandInSequence({}, "test", lane.dispatch());
    EXPECT_TRUE(lane.topics.empty());
}
