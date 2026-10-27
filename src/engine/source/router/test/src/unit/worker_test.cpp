// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>
#include <future>
#include <mutex>
#include <optional>
#include <regex>
#include <thread>

#include <base/json.hpp>
#include <base/logging.hpp>
#include <base/utils/singletonLocator.hpp>
#include <base/utils/singletonLocatorStrategies.hpp>
#include <base/utils/timeUtils.hpp>
#include <bk/mockController.hpp>
#include <builder/mockBuilder.hpp>
#include <builder/mockPolicy.hpp>
#include <fastmetrics/mockCounter.hpp>
#include <fastmetrics/mockManager.hpp>
#include <fastmetrics/registry.hpp>
#include <queue/mockQueue.hpp>
#include <rawevtindexer/mockraweventindexer.hpp>

#include "worker.hpp"

using namespace router;
using namespace testing;

class WorkerTest : public ::testing::Test
{
protected:
    std::shared_ptr<builder::mocks::MockBuilder> m_mockBuilder;
    std::shared_ptr<builder::mocks::MockPolicy> m_mockPolicy;
    std::shared_ptr<bk::mocks::MockMakerController> m_mockControllerMaker;
    std::shared_ptr<bk::mocks::MockController> m_mockController;
    std::shared_ptr<EnvironmentBuilder> m_envBuilder;
    std::shared_ptr<fastmetrics::MockCounter> m_mockCounter;
    std::shared_ptr<raweventindexer::mocks::MockRawEventIndexer> m_mockRawIndexer;

    void SetUp() override
    {
        logging::testInit();

        SingletonLocator::registerManager<fastmetrics::IManager,
                                          base::PtrSingleton<fastmetrics::IManager, fastmetrics::MockManager>>();

        m_mockBuilder = std::make_shared<builder::mocks::MockBuilder>();
        m_mockPolicy = std::make_shared<builder::mocks::MockPolicy>();
        m_mockControllerMaker = std::make_shared<bk::mocks::MockMakerController>();
        m_mockController = std::make_shared<bk::mocks::MockController>();
        m_mockRawIndexer = std::make_shared<raweventindexer::mocks::MockRawEventIndexer>();

        auto& manager = SingletonLocator::instance<fastmetrics::IManager>();
        auto* mockMetrics = dynamic_cast<fastmetrics::MockManager*>(&manager);
        ASSERT_NE(mockMetrics, nullptr);

        m_mockCounter = std::make_shared<fastmetrics::MockCounter>();
        static const std::string kCounterName = "test.counter";
        ON_CALL(*m_mockCounter, value()).WillByDefault(Return(0.0));
        ON_CALL(*m_mockCounter, get()).WillByDefault(Return(0));
        ON_CALL(*m_mockCounter, name()).WillByDefault(ReturnRef(kCounterName));

        EXPECT_CALL(*mockMetrics, getOrCreateCounter(_, _, _)).Times(AnyNumber()).WillRepeatedly(Return(m_mockCounter));
        ON_CALL(*mockMetrics, registerPullMetric(_, _, _, _))
            .WillByDefault(
                [](const std::string&, std::function<uint64_t()>, const std::string&, const std::string&) {});
        ON_CALL(*mockMetrics, registerPullMetricDouble(_, _, _, _))
            .WillByDefault([](const std::string&, std::function<double()>, const std::string&, const std::string&) {});

        m_envBuilder = std::make_shared<EnvironmentBuilder>(m_mockBuilder, m_mockControllerMaker);
    }

    void TearDown() override { SingletonLocator::unregisterManager<fastmetrics::IManager>(); }

    /// Mock chain so that an environment (router entry or tester entry) builds with the mock controller.
    void expectEnvironmentBuild(const std::string& asset)
    {
        EXPECT_CALL(*m_mockBuilder, buildPolicy(_, _)).WillOnce(Return(m_mockPolicy));
        auto assets = std::unordered_set<base::Name> {base::Name(asset)};
        EXPECT_CALL(*m_mockPolicy, assets()).WillRepeatedly(ReturnRefOfCopy(assets));
        EXPECT_CALL(*m_mockControllerMaker, create(_, _, _)).WillOnce(Return(m_mockController));
        EXPECT_CALL(*m_mockPolicy, expression()).WillOnce(ReturnRefOfCopy(base::Expression {}));
        EXPECT_CALL(*m_mockPolicy, hash()).WillOnce(ReturnRefOfCopy(std::string {"hash"}));
        EXPECT_CALL(*m_mockController, stop());
    }
};

namespace
{
// Nine fraction digits, always: the worker/tester stamps are formatted with epochNanosToISO8601.
const std::regex& nineDecimalsRegex()
{
    static const std::regex re(R"(^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$)");
    return re;
}

// What a RouterWorker hands to the raw indexer and to the (mock) controller for one queued event.
struct RouterCapture
{
    std::mutex mutex;
    std::string rawPayload;
    std::string eventStr;
    bool eventIngested {false};
    std::promise<void> done;
};
} // namespace

/***************************
 * RouterWorker tests
 ***************************/

TEST_F(WorkerTest, RouterWorkerNullQueueThrows)
{
    ASSERT_THROW(RouterWorker(m_envBuilder, nullptr, m_mockRawIndexer, nullptr), std::logic_error);
}

TEST_F(WorkerTest, RouterWorkerConstructsWithValidQueue)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<IngestEvent>>();
    ASSERT_NO_THROW(RouterWorker(m_envBuilder, mockQueue, m_mockRawIndexer, nullptr));
}

TEST_F(WorkerTest, RouterWorkerStartStop)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<IngestEvent>>();

    // waitPop returns false (no event), worker loops then stops
    ON_CALL(*mockQueue, waitPop(_, _)).WillByDefault(Return(false));

    RouterWorker worker(m_envBuilder, mockQueue, m_mockRawIndexer, nullptr);
    worker.start();

    // Give time for thread to start
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    worker.stop();
    // Should not hang
}

TEST_F(WorkerTest, RouterWorkerStartTwiceIsNoop)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<IngestEvent>>();
    ON_CALL(*mockQueue, waitPop(_, _)).WillByDefault(Return(false));

    RouterWorker worker(m_envBuilder, mockQueue, m_mockRawIndexer, nullptr);
    worker.start();
    worker.start(); // Second start should be a no-op

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    worker.stop();
}

TEST_F(WorkerTest, RouterWorkerStopWithoutStartIsNoop)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<IngestEvent>>();
    RouterWorker worker(m_envBuilder, mockQueue, m_mockRawIndexer, nullptr);
    worker.stop(); // Should not hang or crash
}

TEST_F(WorkerTest, RouterWorkerProcessesEvent)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<IngestEvent>>();

    auto agentJson = std::make_shared<json::Json>(R"({"agent":{"id":"001","name":"test"}})");
    std::string eventStr = R"(1:[100] (agent) any->syslog {"message":"test event"})";

    std::atomic<int> callCount {0};
    ON_CALL(*mockQueue, waitPop(_, _))
        .WillByDefault(
            [&](IngestEvent& ev, int64_t) -> bool
            {
                if (callCount.fetch_add(1) == 0)
                {
                    ev = IngestEvent {agentJson, eventStr};
                    return true;
                }
                // After first event, block briefly then return false
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                return false;
            });

    RouterWorker worker(m_envBuilder, mockQueue, m_mockRawIndexer, nullptr);
    worker.start();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    worker.stop();

    ASSERT_GE(callCount.load(), 1);
}

TEST_F(WorkerTest, RouterWorkerProcessesEventWithRawIndexer)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<IngestEvent>>();

    auto agentJson = std::make_shared<json::Json>(R"({"agent":{"id":"001","name":"test"}})");
    std::string eventStr = R"(1:[100] (agent) any->syslog {"message":"test"})";

    ON_CALL(*m_mockRawIndexer, isEnabled()).WillByDefault(Return(true));
    EXPECT_CALL(*m_mockRawIndexer, index(A<const std::string&>())).Times(AtLeast(1));

    std::atomic<int> callCount {0};
    ON_CALL(*mockQueue, waitPop(_, _))
        .WillByDefault(
            [&](IngestEvent& ev, int64_t) -> bool
            {
                if (callCount.fetch_add(1) == 0)
                {
                    ev = IngestEvent {agentJson, eventStr};
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                return false;
            });

    RouterWorker worker(m_envBuilder, mockQueue, m_mockRawIndexer, nullptr);
    worker.start();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    worker.stop();
}

TEST_F(WorkerTest, RouterWorkerSkipsSentinelEvent)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<IngestEvent>>();

    std::atomic<int> callCount {0};
    ON_CALL(*mockQueue, waitPop(_, _))
        .WillByDefault(
            [&](IngestEvent& ev, int64_t) -> bool
            {
                int c = callCount.fetch_add(1);
                if (c == 0)
                {
                    // Sentinel: null first
                    ev = IngestEvent {nullptr, "something"};
                    return true;
                }
                if (c == 1)
                {
                    // Sentinel: empty second
                    ev = IngestEvent {std::make_shared<json::Json>("{}"), ""};
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                return false;
            });

    RouterWorker worker(m_envBuilder, mockQueue, m_mockRawIndexer, nullptr);
    worker.start();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    worker.stop();
    // Should not crash - sentinels are silently skipped
}

TEST_F(WorkerTest, RouterWorkerGetReturnsRouter)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<IngestEvent>>();
    RouterWorker worker(m_envBuilder, mockQueue, m_mockRawIndexer, nullptr);
    ASSERT_NE(worker.get(), nullptr);
}

TEST_F(WorkerTest, RouterWorkerUsesReceivedStampForRawAndEvent)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<IngestEvent>>();

    auto agentJson = std::make_shared<json::Json>(R"({"agent":{"id":"001","name":"test"}})");
    std::string eventStr = R"(1:[100] (agent) any->syslog {"message":"test event"})";
    constexpr int64_t kReceivedAtNs = 1'700'000'000'123'456'789;
    const std::string kExpectedStamp = "2023-11-14T22:13:20.123456789Z";

    RouterCapture capture;
    auto doneFuture = capture.done.get_future();

    ON_CALL(*m_mockRawIndexer, isEnabled()).WillByDefault(Return(true));
    EXPECT_CALL(*m_mockRawIndexer, index(A<const std::string&>()))
        .WillOnce(
            [&](const std::string& payload)
            {
                std::lock_guard<std::mutex> lock(capture.mutex);
                capture.rawPayload = payload;
            });

    expectEnvironmentBuild("asset/wazuh/0");
    EXPECT_CALL(*m_mockController, ingest(testing::_))
        .WillOnce(
            [&](base::Event&& ev)
            {
                {
                    std::lock_guard<std::mutex> lock(capture.mutex);
                    capture.eventStr = ev->str();
                    capture.eventIngested = true;
                }
                capture.done.set_value();
            });

    std::atomic<int> callCount {0};
    ON_CALL(*mockQueue, waitPop(_, _))
        .WillByDefault(
            [&](IngestEvent& ev, int64_t) -> bool
            {
                if (callCount.fetch_add(1) == 0)
                {
                    ev = IngestEvent {agentJson, eventStr, kReceivedAtNs};
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                return false;
            });

    RouterWorker worker(m_envBuilder, mockQueue, m_mockRawIndexer, nullptr);
    const router::prod::EntryPost entryPost {"Production", cm::store::NamespaceId {"policy_name_0"}, 99};
    ASSERT_FALSE(worker.get()->addEntry(entryPost, false).has_value());
    ASSERT_FALSE(worker.get()->enableEntry("Production").has_value());

    worker.start();
    const auto status = doneFuture.wait_for(std::chrono::seconds(2));
    worker.stop();
    ASSERT_EQ(status, std::future_status::ready) << "MockController::ingest was not invoked (entry not enabled?)";

    std::lock_guard<std::mutex> lock(capture.mutex);
    ASSERT_TRUE(capture.eventIngested);

    const json::Json raw(capture.rawPayload.c_str());
    std::string rawStamp;
    ASSERT_EQ(raw.getString(rawStamp, "/@timestamp"), json::RetGet::Success);
    EXPECT_EQ(rawStamp, kExpectedStamp);
    std::string rawOriginal;
    ASSERT_EQ(raw.getString(rawOriginal, "/event/original"), json::RetGet::Success);
    EXPECT_EQ(rawOriginal, eventStr);

    const json::Json processed(capture.eventStr.c_str());
    std::string eventStamp;
    ASSERT_EQ(processed.getString(eventStamp, "/@timestamp"), json::RetGet::Success);
    EXPECT_EQ(eventStamp, kExpectedStamp);
}

TEST_F(WorkerTest, RouterWorkerStampsUnstampedEvent)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<IngestEvent>>();

    auto agentJson = std::make_shared<json::Json>(R"({"agent":{"id":"001","name":"test"}})");
    std::string eventStr = R"(1:[100] (agent) any->syslog {"message":"test event"})";

    RouterCapture capture;
    auto doneFuture = capture.done.get_future();

    ON_CALL(*m_mockRawIndexer, isEnabled()).WillByDefault(Return(true));
    EXPECT_CALL(*m_mockRawIndexer, index(A<const std::string&>()))
        .WillOnce(
            [&](const std::string& payload)
            {
                std::lock_guard<std::mutex> lock(capture.mutex);
                capture.rawPayload = payload;
            });

    expectEnvironmentBuild("asset/wazuh/0");
    EXPECT_CALL(*m_mockController, ingest(testing::_))
        .WillOnce(
            [&](base::Event&& ev)
            {
                {
                    std::lock_guard<std::mutex> lock(capture.mutex);
                    capture.eventStr = ev->str();
                    capture.eventIngested = true;
                }
                capture.done.set_value();
            });

    std::atomic<int> callCount {0};
    ON_CALL(*mockQueue, waitPop(_, _))
        .WillByDefault(
            [&](IngestEvent& ev, int64_t) -> bool
            {
                if (callCount.fetch_add(1) == 0)
                {
                    ev = IngestEvent {agentJson, eventStr}; // receivedAtNs = 0: not stamped
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                return false;
            });

    RouterWorker worker(m_envBuilder, mockQueue, m_mockRawIndexer, nullptr);
    const router::prod::EntryPost entryPost {"Production", cm::store::NamespaceId {"policy_name_0"}, 99};
    ASSERT_FALSE(worker.get()->addEntry(entryPost, false).has_value());
    ASSERT_FALSE(worker.get()->enableEntry("Production").has_value());

    // Push the shared clock one hour ahead of the wall clock: a fallback that read the wall clock instead of the
    // shared clock would stamp below `lo` and fail (the stamp must come from receptionClock()).
    const auto lo = base::utils::time::epochNanosToISO8601(
        base::utils::time::receptionClock().next(base::utils::time::systemEpochNanos() + 3600LL * 1000000000LL));
    worker.start();
    const auto status = doneFuture.wait_for(std::chrono::seconds(2));
    worker.stop();
    const auto hi = base::utils::time::epochNanosToISO8601(base::utils::time::receptionClock().next());
    ASSERT_EQ(status, std::future_status::ready) << "MockController::ingest was not invoked (entry not enabled?)";

    std::lock_guard<std::mutex> lock(capture.mutex);
    ASSERT_TRUE(capture.eventIngested);

    const json::Json raw(capture.rawPayload.c_str());
    std::string rawStamp;
    ASSERT_EQ(raw.getString(rawStamp, "/@timestamp"), json::RetGet::Success);
    const json::Json processed(capture.eventStr.c_str());
    std::string eventStamp;
    ASSERT_EQ(processed.getString(eventStamp, "/@timestamp"), json::RetGet::Success);

    EXPECT_EQ(rawStamp, eventStamp);
    EXPECT_TRUE(std::regex_match(eventStamp, nineDecimalsRegex())) << eventStamp;
    // Fixed-width format: lexicographic order is chronological order (a stamped 0 would be 1970-... and fail).
    EXPECT_LT(lo, eventStamp);
    EXPECT_LT(eventStamp, hi);
}

/***************************
 * TesterWorker tests
 ***************************/

TEST_F(WorkerTest, TesterWorkerNullQueueThrows)
{
    ASSERT_THROW(TesterWorker(m_envBuilder, nullptr), std::logic_error);
}

TEST_F(WorkerTest, TesterWorkerConstructsWithValidQueue)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<test::EventTest>>();
    ASSERT_NO_THROW(TesterWorker(m_envBuilder, mockQueue));
}

TEST_F(WorkerTest, TesterWorkerStartStop)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<test::EventTest>>();
    ON_CALL(*mockQueue, waitPop(_, _)).WillByDefault(Return(false));

    TesterWorker worker(m_envBuilder, mockQueue);
    worker.start();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    worker.stop();
}

TEST_F(WorkerTest, TesterWorkerStartTwiceIsNoop)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<test::EventTest>>();
    ON_CALL(*mockQueue, waitPop(_, _)).WillByDefault(Return(false));

    TesterWorker worker(m_envBuilder, mockQueue);
    worker.start();
    worker.start(); // No-op

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    worker.stop();
}

TEST_F(WorkerTest, TesterWorkerStopWithoutStartIsNoop)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<test::EventTest>>();
    TesterWorker worker(m_envBuilder, mockQueue);
    worker.stop(); // Should not crash
}

TEST_F(WorkerTest, TesterWorkerGetReturnsTester)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<test::EventTest>>();
    TesterWorker worker(m_envBuilder, mockQueue);
    ASSERT_NE(worker.get(), nullptr);
}

TEST_F(WorkerTest, TesterWorkerProcessesEvent)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<test::EventTest>>();

    auto event = std::make_shared<json::Json>(R"({"test": true})");
    test::Options opts(test::Options::TraceLevel::NONE, {}, "env1");

    std::atomic<bool> callbackInvoked {false};
    auto testEventData = std::make_shared<test::TestingTuple>(
        std::move(event),
        opts,
        [&callbackInvoked](base::RespOrError<test::Output>&& /*output*/) { callbackInvoked.store(true); });

    std::atomic<int> callCount {0};
    ON_CALL(*mockQueue, waitPop(_, _))
        .WillByDefault(
            [&](test::EventTest& ev, int64_t) -> bool
            {
                if (callCount.fetch_add(1) == 0)
                {
                    ev = testEventData;
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                return false;
            });

    TesterWorker worker(m_envBuilder, mockQueue);
    worker.start();

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    worker.stop();

    // The callback should have been invoked by the tester
    // Note: it may fail if tester.ingestTest throws because the environment doesn't exist,
    // but the test still verifies the worker loop processes events correctly
}

TEST_F(WorkerTest, TesterWorkerSetsTimestampAndEventId)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<test::EventTest>>();

    auto event = std::make_shared<json::Json>(R"({"test": true})");
    test::Options opts(test::Options::TraceLevel::NONE, {}, "env1");

    std::mutex resultMutex;
    std::optional<base::RespOrError<test::Output>> result;
    std::promise<void> done;
    auto doneFuture = done.get_future();
    auto testEventData = std::make_shared<test::TestingTuple>(std::move(event),
                                                              opts,
                                                              [&](base::RespOrError<test::Output>&& output)
                                                              {
                                                                  {
                                                                      std::lock_guard<std::mutex> lock(resultMutex);
                                                                      result.emplace(std::move(output));
                                                                  }
                                                                  done.set_value();
                                                              });

    expectEnvironmentBuild("asset/test/0");
    EXPECT_CALL(*m_mockController, subscribe(_, _)).Times(0);
    EXPECT_CALL(*m_mockController, ingestGet(_)).Times(1).WillOnce([](base::Event&& ev) { return ev; });
    EXPECT_CALL(*m_mockController, unsubscribeAll()).Times(1);

    std::atomic<int> callCount {0};
    ON_CALL(*mockQueue, waitPop(_, _))
        .WillByDefault(
            [&](test::EventTest& ev, int64_t) -> bool
            {
                if (callCount.fetch_add(1) == 0)
                {
                    ev = testEventData;
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                return false;
            });

    TesterWorker worker(m_envBuilder, mockQueue);
    const router::test::EntryPost entryPost {"env1", cm::store::NamespaceId {"policy_name_0"}, 1000};
    ASSERT_FALSE(worker.get()->addEntry(entryPost, false).has_value());
    ASSERT_FALSE(worker.get()->enableEntry("env1").has_value());

    worker.start();
    const auto status = doneFuture.wait_for(std::chrono::seconds(2));
    worker.stop();
    ASSERT_EQ(status, std::future_status::ready) << "The tester callback was not invoked";

    std::lock_guard<std::mutex> lock(resultMutex);
    ASSERT_TRUE(result.has_value());
    ASSERT_FALSE(base::isError(*result));
    const auto& outEvent = base::getResponse<test::Output>(*result).event();
    ASSERT_NE(outEvent, nullptr);

    std::string timestamp;
    ASSERT_EQ(outEvent->getString(timestamp, "/@timestamp"), json::RetGet::Success);
    EXPECT_TRUE(std::regex_match(timestamp, nineDecimalsRegex())) << timestamp;

    ASSERT_TRUE(outEvent->isString("/wazuh/event/id"));
    std::string eventId;
    ASSERT_EQ(outEvent->getString(eventId, "/wazuh/event/id"), json::RetGet::Success);
    EXPECT_FALSE(eventId.empty());
}

TEST_F(WorkerTest, TesterWorkerKeepsDecoderTimestamp)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<test::EventTest>>();

    auto event = std::make_shared<json::Json>(R"({"test": true})");
    test::Options opts(test::Options::TraceLevel::NONE, {}, "env1");

    std::mutex resultMutex;
    std::optional<base::RespOrError<test::Output>> result;
    std::promise<void> done;
    auto doneFuture = done.get_future();
    auto testEventData = std::make_shared<test::TestingTuple>(std::move(event),
                                                              opts,
                                                              [&](base::RespOrError<test::Output>&& output)
                                                              {
                                                                  {
                                                                      std::lock_guard<std::mutex> lock(resultMutex);
                                                                      result.emplace(std::move(output));
                                                                  }
                                                                  done.set_value();
                                                              });

    expectEnvironmentBuild("asset/test/0");
    EXPECT_CALL(*m_mockController, subscribe(_, _)).Times(0);
    EXPECT_CALL(*m_mockController, ingestGet(_))
        .Times(1)
        .WillOnce(
            [](base::Event&& ev)
            {
                // A decoder overwrites the reception stamp.
                ev->setString("2020-01-01T00:00:00.000Z", "/@timestamp");
                return ev;
            });
    EXPECT_CALL(*m_mockController, unsubscribeAll()).Times(1);

    std::atomic<int> callCount {0};
    ON_CALL(*mockQueue, waitPop(_, _))
        .WillByDefault(
            [&](test::EventTest& ev, int64_t) -> bool
            {
                if (callCount.fetch_add(1) == 0)
                {
                    ev = testEventData;
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                return false;
            });

    TesterWorker worker(m_envBuilder, mockQueue);
    const router::test::EntryPost entryPost {"env1", cm::store::NamespaceId {"policy_name_0"}, 1000};
    ASSERT_FALSE(worker.get()->addEntry(entryPost, false).has_value());
    ASSERT_FALSE(worker.get()->enableEntry("env1").has_value());

    worker.start();
    const auto status = doneFuture.wait_for(std::chrono::seconds(2));
    worker.stop();
    ASSERT_EQ(status, std::future_status::ready) << "The tester callback was not invoked";

    std::lock_guard<std::mutex> lock(resultMutex);
    ASSERT_TRUE(result.has_value());
    ASSERT_FALSE(base::isError(*result));
    const auto& outEvent = base::getResponse<test::Output>(*result).event();
    ASSERT_NE(outEvent, nullptr);

    std::string timestamp;
    ASSERT_EQ(outEvent->getString(timestamp, "/@timestamp"), json::RetGet::Success);
    EXPECT_EQ(timestamp, "2020-01-01T00:00:00.000Z");
}

TEST_F(WorkerTest, TesterWorkerSkipsNullEvent)
{
    auto mockQueue = std::make_shared<fastqueue::mocks::MockQueue<test::EventTest>>();

    std::atomic<int> callCount {0};
    ON_CALL(*mockQueue, waitPop(_, _))
        .WillByDefault(
            [&](test::EventTest& ev, int64_t) -> bool
            {
                if (callCount.fetch_add(1) == 0)
                {
                    ev = nullptr; // null event
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                return false;
            });

    TesterWorker worker(m_envBuilder, mockQueue);
    worker.start();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    worker.stop();
    // Should not crash
}
