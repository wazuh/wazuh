#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <limits>
#include <memory>
#include <stdexcept>
#include <vector>

#include <fastmetrics/manager.hpp>
#include <fastmetrics/pullMetric.hpp>
#include <fastmetrics/registry.hpp>

using namespace fastmetrics;

// ============================================================
// Helper types for PullMetric tests
// ============================================================
class PullMetricTest : public ::testing::Test
{
protected:
    Manager manager;
};

// ============================================================
// PullMetric Tests
// ============================================================

TEST_F(PullMetricTest, BasicPullMetric)
{
    // Simulate a queue with size() method
    std::atomic<uint64_t> queueSize {0};

    // Register pull metric with lambda
    manager.registerPullMetric("queue.size", [&queueSize]() { return queueSize.load(); });

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
        std::atomic<uint64_t> m_size {0};
        uint64_t size() const { return m_size.load(); }
    };

    auto queue = std::make_shared<Queue>();

    // Safe: shared_ptr keeps queue alive
    manager.registerPullMetric("safe.queue.size", [queue]() { return queue->size(); });

    queue->m_size = 123;

    auto metric = manager.get("safe.queue.size");
    ASSERT_NE(metric, nullptr);
    EXPECT_EQ(metric->value(), 123.0);
}

TEST_F(PullMetricTest, PullMetricDerivedValue)
{
    // Multiple queues combined
    std::atomic<uint64_t> queueA {10};
    std::atomic<uint64_t> queueB {20};

    manager.registerPullMetric("total.queue.size", [&queueA, &queueB]() { return queueA.load() + queueB.load(); });

    auto metric = manager.get("total.queue.size");
    ASSERT_NE(metric, nullptr);
    EXPECT_EQ(metric->value(), 30.0);

    queueA = 50;
    EXPECT_EQ(metric->value(), 70.0);
}

TEST_F(PullMetricTest, PullMetricEnableDisable)
{
    std::atomic<uint64_t> value {42};

    manager.registerPullMetric("test.value", [&value]() { return value.load(); });

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
    manager.registerPullMetric("failing.metric", []() -> uint64_t { throw std::runtime_error("oops"); });

    auto metric = manager.get("failing.metric");
    ASSERT_NE(metric, nullptr);

    // Should return 0 instead of crashing
    EXPECT_EQ(metric->value(), 0.0);
}

TEST_F(PullMetricTest, PullMetricTypedAccess)
{
    std::atomic<uint64_t> value {12345};

    manager.registerPullMetric("typed.value", [&value]() { return value.load(); });

    auto metric = manager.get("typed.value");
    ASSERT_NE(metric, nullptr);

    // Cast to specific type to get typed access
    auto pullMetric = std::dynamic_pointer_cast<PullMetric<uint64_t>>(metric);
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
    std::atomic<uint64_t> queueSize {42};
    manager.registerPullMetric("queue.size", [&queueSize]() { return queueSize.load(); });

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
        uint64_t size() const { return items.size(); }
        void push(int val) { items.push_back(val); }
    };

    auto queue = std::make_shared<EventQueue>();

    // Register pull metric pointing to real queue
    manager.registerPullMetric("orchestrator.queue.size", [queue]() { return queue->size(); });

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

// ============================================================
// Helper types for Manager::writeAllMetrics() tests
// ============================================================

class CapturingWriter : public streamlog::WriterEvent
{
public:
    std::vector<std::string> lines;

    bool operator()(std::string&& message) override
    {
        lines.push_back(std::move(message));
        return true;
    }
};

class ThrowingWriter : public streamlog::WriterEvent
{
public:
    bool operator()(std::string&& /*message*/) override { throw std::runtime_error("Writer failure"); }
};

// ============================================================
// writeAllMetrics()
// ============================================================

class ManagerWriteAllMetricsTest : public ::testing::Test
{
protected:
    Manager manager;

    void TearDown() override { manager.clear(); }

    // Extract a numeric field from a JSON line (returns NaN if not found)
    static double extractDouble(const std::string& json, const std::string& field)
    {
        std::string key = "\"" + field + "\":";
        auto pos = json.find(key);
        if (pos == std::string::npos)
            return std::numeric_limits<double>::quiet_NaN();
        pos += key.size();
        auto end = json.find_first_of(",}", pos);
        return std::stod(json.substr(pos, end - pos));
    }

    // Extract a string field from a JSON line (returns empty string if not found)
    static std::string extractString(const std::string& json, const std::string& field)
    {
        std::string key = "\"" + field + "\":\"";
        auto pos = json.find(key);
        if (pos == std::string::npos)
            return "";
        pos += key.size();
        auto end = json.find('"', pos);
        return json.substr(pos, end - pos);
    }

    // Find the line whose "name" field matches the given metric name
    static const std::string* findLine(const std::vector<std::string>& lines, const std::string& name)
    {
        for (const auto& line : lines)
        {
            if (extractString(line, "name") == name)
                return &line;
        }
        return nullptr;
    }
};

TEST_F(ManagerWriteAllMetricsTest, NoRegisteredMetrics)
{
    auto writer = std::make_shared<CapturingWriter>();
    manager.writeAllMetrics(writer);
    EXPECT_TRUE(writer->lines.empty());
}

TEST_F(ManagerWriteAllMetricsTest, SingleRegisteredMetric)
{
    auto counter = manager.getOrCreateCounter("single.counter");
    counter->add(42);

    auto writer = std::make_shared<CapturingWriter>();
    manager.writeAllMetrics(writer);

    ASSERT_EQ(writer->lines.size(), 1u);
    const auto& line = writer->lines[0];
    EXPECT_EQ(extractString(line, "name"), "single.counter");
    EXPECT_DOUBLE_EQ(extractDouble(line, "value"), 42.0);
    EXPECT_GT(extractDouble(line, "timestamp"), 0.0);
}

TEST_F(ManagerWriteAllMetricsTest, MultipleRegisteredMetrics)
{
    manager.getOrCreateCounter("multi.counter")->add(10);
    manager.getOrCreateGaugeInt("multi.gauge")->set(20);

    std::atomic<uint64_t> pullVal {30};
    manager.registerPullMetric("multi.pull", [&pullVal]() { return pullVal.load(); });

    auto writer = std::make_shared<CapturingWriter>();
    manager.writeAllMetrics(writer);

    ASSERT_EQ(writer->lines.size(), 3u);

    const auto* counterLine = findLine(writer->lines, "multi.counter");
    const auto* gaugeLine = findLine(writer->lines, "multi.gauge");
    const auto* pullLine = findLine(writer->lines, "multi.pull");

    ASSERT_NE(counterLine, nullptr);
    ASSERT_NE(gaugeLine, nullptr);
    ASSERT_NE(pullLine, nullptr);

    EXPECT_DOUBLE_EQ(extractDouble(*counterLine, "value"), 10.0);
    EXPECT_DOUBLE_EQ(extractDouble(*gaugeLine, "value"), 20.0);
    EXPECT_DOUBLE_EQ(extractDouble(*pullLine, "value"), 30.0);

    for (const auto& line : writer->lines) EXPECT_GT(extractDouble(line, "timestamp"), 0.0);
}

TEST_F(ManagerWriteAllMetricsTest, DisabledMetrics)
{
    auto counter = manager.getOrCreateCounter("disabled.counter");
    counter->add(100);
    counter->disable();

    auto writer = std::make_shared<CapturingWriter>();
    manager.writeAllMetrics(writer);

    ASSERT_FALSE(counter->isEnabled());
    ASSERT_EQ(counter->value(), 0.0);
    ASSERT_EQ(writer->lines.size(), 1u);
    const auto& line = writer->lines[0];
    EXPECT_EQ(extractString(line, "name"), "disabled.counter");
    EXPECT_DOUBLE_EQ(extractDouble(line, "value"), 0.0);
}

TEST_F(ManagerWriteAllMetricsTest, TimestampField)
{
    manager.getOrCreateCounter("ts.counter");

    auto before =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();

    auto writer = std::make_shared<CapturingWriter>();
    manager.writeAllMetrics(writer);

    auto after =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();

    ASSERT_EQ(writer->lines.size(), 1u);
    long long ts = static_cast<long long>(extractDouble(writer->lines[0], "timestamp"));
    EXPECT_GE(ts, before);
    EXPECT_LE(ts, after);
}

TEST_F(ManagerWriteAllMetricsTest, ExceptionInWriter)
{
    manager.getOrCreateCounter("exc.counter");

    auto throwingWriter = std::make_shared<ThrowingWriter>();
    EXPECT_NO_THROW(manager.writeAllMetrics(throwingWriter));
}

TEST_F(ManagerWriteAllMetricsTest, OutputContentValidation)
{
    manager.getOrCreateCounter("validated.counter")->add(7);

    std::atomic<uint64_t> pullVal {55};
    manager.registerPullMetric("validated.pull", [&pullVal]() { return pullVal.load(); });

    auto writer = std::make_shared<CapturingWriter>();
    manager.writeAllMetrics(writer);

    ASSERT_EQ(writer->lines.size(), 2u);

    for (const auto& line : writer->lines)
    {
        EXPECT_EQ(line.front(), '{');
        EXPECT_EQ(line.back(), '}');
        EXPECT_NE(line.find("\"timestamp\":"), std::string::npos);
        EXPECT_NE(line.find("\"name\":"), std::string::npos);
        EXPECT_NE(line.find("\"value\":"), std::string::npos);
    }

    const auto* counterLine = findLine(writer->lines, "validated.counter");
    const auto* pullLine = findLine(writer->lines, "validated.pull");

    ASSERT_NE(counterLine, nullptr);
    ASSERT_NE(pullLine, nullptr);

    EXPECT_DOUBLE_EQ(extractDouble(*counterLine, "value"), 7.0);
    EXPECT_DOUBLE_EQ(extractDouble(*pullLine, "value"), 55.0);
}
