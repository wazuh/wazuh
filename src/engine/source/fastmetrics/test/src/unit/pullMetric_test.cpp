#include <gtest/gtest.h>

#include <atomic>
#include <memory>
#include <vector>

#include <fastmetrics/manager.hpp>
#include <fastmetrics/pullMetric.hpp>
#include <fastmetrics/registry.hpp>

using namespace fastmetrics;

class PullMetricTest : public ::testing::Test
{
protected:
    Manager manager;
};

TEST_F(PullMetricTest, BasicPullMetric)
{
    // Simulate a queue with size() method
    std::atomic<size_t> queueSize{0};

    // Register pull metric with lambda
    manager.registerPullMetric<size_t>("queue.size", [&queueSize]() { return queueSize.load(); });

    // Initially empty
    auto metric = manager.get("queue.size");
    ASSERT_NE(metric, nullptr);
    EXPECT_EQ(metric->type(), MetricType::PULL);
    EXPECT_EQ(metric->value(), 0.0);

    // Change underlying value
    queueSize = 42;
    EXPECT_EQ(metric->value(), 42.0);

    // Change again
    queueSize = 100;
    EXPECT_EQ(metric->value(), 100.0);
}

TEST_F(PullMetricTest, PullMetricWithSharedPtr)
{
    // Safe pattern: capture shared_ptr
    struct Queue
    {
        std::atomic<size_t> m_size{0};
        size_t size() const { return m_size.load(); }
    };

    auto queue = std::make_shared<Queue>();

    // Safe: shared_ptr keeps queue alive
    manager.registerPullMetric<size_t>("safe.queue.size", [queue]() { return queue->size(); });

    queue->m_size = 123;

    auto metric = manager.get("safe.queue.size");
    ASSERT_NE(metric, nullptr);
    EXPECT_EQ(metric->value(), 123.0);
}

TEST_F(PullMetricTest, PullMetricDerivedValue)
{
    // Multiple queues combined
    std::atomic<size_t> queueA{10};
    std::atomic<size_t> queueB{20};

    manager.registerPullMetric<size_t>("total.queue.size", [&queueA, &queueB]() {
        return queueA.load() + queueB.load();
    });

    auto metric = manager.get("total.queue.size");
    ASSERT_NE(metric, nullptr);
    EXPECT_EQ(metric->value(), 30.0);

    queueA = 50;
    EXPECT_EQ(metric->value(), 70.0);
}

TEST_F(PullMetricTest, PullMetricEnableDisable)
{
    std::atomic<size_t> value{42};

    manager.registerPullMetric<size_t>("test.value", [&value]() { return value.load(); });

    auto metric = manager.get("test.value");
    ASSERT_NE(metric, nullptr);
    EXPECT_TRUE(metric->isEnabled());
    EXPECT_EQ(metric->value(), 42.0);

    // Disable
    metric->disable();
    EXPECT_FALSE(metric->isEnabled());
    EXPECT_EQ(metric->value(), 0.0); // Returns 0 when disabled

    // Enable again
    metric->enable();
    EXPECT_TRUE(metric->isEnabled());
    EXPECT_EQ(metric->value(), 42.0);
}

TEST_F(PullMetricTest, PullMetricExceptionHandling)
{
    // Lambda that throws
    manager.registerPullMetric<size_t>("failing.metric", []() -> size_t { throw std::runtime_error("oops"); });

    auto metric = manager.get("failing.metric");
    ASSERT_NE(metric, nullptr);

    // Should return 0 instead of crashing
    EXPECT_EQ(metric->value(), 0.0);
}

TEST_F(PullMetricTest, PullMetricTypedAccess)
{
    std::atomic<size_t> value{12345};

    manager.registerPullMetric<size_t>("typed.value", [&value]() { return value.load(); });

    auto metric = manager.get("typed.value");
    ASSERT_NE(metric, nullptr);

    // Cast to specific type to get typed access
    auto pullMetric = std::dynamic_pointer_cast<PullMetric<size_t>>(metric);
    ASSERT_NE(pullMetric, nullptr);

    // Direct typed access (no double conversion)
    EXPECT_EQ(pullMetric->getValue(), 12345);
}

TEST_F(PullMetricTest, MixedPushAndPullMetrics)
{
    // PUSH metric (maintains state)
    auto counter = manager.getOrCreateCounter("events.processed");
    counter->add(100);

    // PULL metric (lazy evaluation)
    std::atomic<size_t> queueSize{42};
    manager.registerPullMetric<size_t>("queue.size", [&queueSize]() { return queueSize.load(); });

    // Both should be listable
    auto names = manager.getAllNames();
    EXPECT_EQ(names.size(), 2);

    // Both should be accessible
    EXPECT_NE(manager.get("events.processed"), nullptr);
    EXPECT_NE(manager.get("queue.size"), nullptr);

    // Different types
    EXPECT_EQ(manager.get("events.processed")->type(), MetricType::COUNTER);
    EXPECT_EQ(manager.get("queue.size")->type(), MetricType::PULL);
}

TEST_F(PullMetricTest, RealWorldQueueExample)
{
    // Simulate orchestrator queue scenario
    struct EventQueue
    {
        std::vector<int> items;
        size_t size() const { return items.size(); }
        void push(int val) { items.push_back(val); }
    };

    auto queue = std::make_shared<EventQueue>();

    // Register pull metric pointing to real queue
    manager.registerPullMetric<size_t>("orchestrator.queue.size", [queue]() { return queue->size(); });

    // Query shows real size
    auto metric = manager.get("orchestrator.queue.size");
    EXPECT_EQ(metric->value(), 0.0);

    // Add items
    queue->push(1);
    queue->push(2);
    queue->push(3);

    // Metric automatically reflects current size (no manual update needed!)
    EXPECT_EQ(metric->value(), 3.0);
}
