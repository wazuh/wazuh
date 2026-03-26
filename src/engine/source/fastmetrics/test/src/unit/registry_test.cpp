#include <algorithm>
#include <gtest/gtest.h>
#include <thread>

#include <fastmetrics/manager.hpp>

using namespace fastmetrics;

class RegistryTest : public ::testing::Test
{
protected:
    std::unique_ptr<Manager> registry;

    void SetUp() override { registry = std::make_unique<Manager>(); }

    void TearDown() override { registry->clear(); }
};

TEST_F(RegistryTest, CreateCounter)
{
    auto counter = registry->getOrCreateCounter("test.counter", "Test counter", "count");

    ASSERT_NE(counter, nullptr);
    EXPECT_EQ(counter->name(), "test.counter");
    EXPECT_EQ(counter->type(), MetricType::COUNTER);
}

TEST_F(RegistryTest, GetOrCreateReturnsExisting)
{
    auto counter1 = registry->getOrCreateCounter("test.counter");
    auto counter2 = registry->getOrCreateCounter("test.counter");

    // Should return the same instance
    EXPECT_EQ(counter1, counter2);

    counter1->add(10);
    EXPECT_EQ(counter2->get(), 10);
}

TEST_F(RegistryTest, CreateGauges)
{
    auto gaugeInt = registry->getOrCreateGaugeInt("test.gauge.int");
    auto gaugeDouble = registry->getOrCreateGaugeDouble("test.gauge.double");

    ASSERT_NE(gaugeInt, nullptr);
    ASSERT_NE(gaugeDouble, nullptr);

    EXPECT_EQ(gaugeInt->type(), MetricType::GAUGE_INT);
    EXPECT_EQ(gaugeDouble->type(), MetricType::GAUGE_DBL);
}

TEST_F(RegistryTest, GetMetric)
{
    registry->getOrCreateCounter("counter.one");
    registry->getOrCreateGaugeInt("gauge.two");

    auto metric1 = registry->get("counter.one");
    auto metric2 = registry->get("gauge.two");
    auto metric3 = registry->get("nonexistent");

    EXPECT_NE(metric1, nullptr);
    EXPECT_NE(metric2, nullptr);
    EXPECT_EQ(metric3, nullptr);
}

TEST_F(RegistryTest, Exists)
{
    registry->getOrCreateCounter("test.counter");

    EXPECT_TRUE(registry->exists("test.counter"));
    EXPECT_FALSE(registry->exists("nonexistent"));
}

TEST_F(RegistryTest, GetAllNames)
{
    registry->getOrCreateCounter("metric.one");
    registry->getOrCreateCounter("metric.two");
    registry->getOrCreateGaugeInt("metric.three");

    auto names = registry->getAllNames();

    EXPECT_EQ(names.size(), 3);
    EXPECT_NE(std::find(names.begin(), names.end(), "metric.one"), names.end());
    EXPECT_NE(std::find(names.begin(), names.end(), "metric.two"), names.end());
    EXPECT_NE(std::find(names.begin(), names.end(), "metric.three"), names.end());
}

TEST_F(RegistryTest, Count)
{
    EXPECT_EQ(registry->count(), 0);

    registry->getOrCreateCounter("metric.one");
    EXPECT_EQ(registry->count(), 1);

    registry->getOrCreateCounter("metric.two");
    EXPECT_EQ(registry->count(), 2);

    // Getting existing metric doesn't increase count
    registry->getOrCreateCounter("metric.one");
    EXPECT_EQ(registry->count(), 2);
}

TEST_F(RegistryTest, EnableDisableAll)
{
    auto counter = registry->getOrCreateCounter("test.counter");
    auto gauge = registry->getOrCreateGaugeInt("test.gauge");

    EXPECT_TRUE(counter->isEnabled());
    EXPECT_TRUE(gauge->isEnabled());

    registry->disableAll();
    EXPECT_FALSE(registry->isEnabled());
    EXPECT_FALSE(counter->isEnabled());
    EXPECT_FALSE(gauge->isEnabled());

    // Updates should be ignored
    counter->add(10);
    gauge->set(100);
    EXPECT_EQ(counter->get(), 0);
    EXPECT_EQ(gauge->get(), 0);

    registry->enableAll();
    EXPECT_TRUE(registry->isEnabled());
    EXPECT_TRUE(counter->isEnabled());
    EXPECT_TRUE(gauge->isEnabled());

    counter->add(10);
    gauge->set(100);
    EXPECT_EQ(counter->get(), 10);
    EXPECT_EQ(gauge->get(), 100);
}

TEST_F(RegistryTest, Clear)
{
    registry->getOrCreateCounter("metric.one");
    registry->getOrCreateCounter("metric.two");

    EXPECT_EQ(registry->count(), 2);

    registry->clear();
    EXPECT_EQ(registry->count(), 0);
}

TEST_F(RegistryTest, ThreadSafety)
{
    constexpr int NUM_THREADS = 10;

    std::vector<std::thread> threads;
    for (int i = 0; i < NUM_THREADS; ++i)
    {
        threads.emplace_back(
            [this, i]()
            {
                // Each thread creates and updates its own metric
                std::string name = "metric." + std::to_string(i);
                auto counter = registry->getOrCreateCounter(name);

                for (int j = 0; j < 1000; ++j)
                {
                    counter->add(1);
                }
            });
    }

    // Also create some shared metrics
    for (int i = 0; i < NUM_THREADS; ++i)
    {
        threads.emplace_back(
            [this]()
            {
                auto counter = registry->getOrCreateCounter("shared.metric");
                for (int j = 0; j < 1000; ++j)
                {
                    counter->add(1);
                }
            });
    }

    for (auto& t : threads)
    {
        t.join();
    }

    // Check individual metrics
    for (int i = 0; i < NUM_THREADS; ++i)
    {
        std::string name = "metric." + std::to_string(i);
        auto counter = std::dynamic_pointer_cast<ICounter>(registry->get(name));
        ASSERT_NE(counter, nullptr);
        EXPECT_EQ(counter->get(), 1000);
    }

    // Check shared metric
    auto sharedCounter = std::dynamic_pointer_cast<ICounter>(registry->get("shared.metric"));
    ASSERT_NE(sharedCounter, nullptr);
    EXPECT_EQ(sharedCounter->get(), NUM_THREADS * 1000);
}
