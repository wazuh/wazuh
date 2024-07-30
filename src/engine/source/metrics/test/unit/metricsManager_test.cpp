#include <gtest/gtest.h>
#include <memory>

#include <base/json.hpp>
#include <base/logging.hpp>
#include <metrics/metricsManager.hpp>

using namespace metricsManager;

class MetricsInterfaceTest : public ::testing::Test
{
protected:
    MetricsInterfaceTest() { m_manager = std::make_shared<MetricsManager>(); }

    ~MetricsInterfaceTest() {}

    void SetUp() override { logging::testInit(); }

    void TearDown() override {}

    std::shared_ptr<IMetricsManager> m_manager;
};

TEST_F(MetricsInterfaceTest, managerAvailable)
{
    ASSERT_NE(m_manager, nullptr);
}

TEST_F(MetricsInterfaceTest, getMetricsScopeNew)
{
    auto newScope = m_manager->getMetricsScope("scope_main");
    ASSERT_NE(newScope, nullptr);
}

TEST_F(MetricsInterfaceTest, getMetricsScopeExisting)
{
    auto newScope = m_manager->getMetricsScope("scope_main");
    auto existingScope = m_manager->getMetricsScope("scope_main");
    ASSERT_EQ(existingScope, newScope);
}

TEST_F(MetricsInterfaceTest, getMetricsScopeNamesEmpty)
{
    auto scopeNames = m_manager->getScopeNames();
    ASSERT_EQ(scopeNames.size(), 0);
}

TEST_F(MetricsInterfaceTest, getMetricsScopeNames)
{
    auto scope0 = m_manager->getMetricsScope("scope_0");
    auto scope1 = m_manager->getMetricsScope("scope_1");
    auto scopeNames = m_manager->getScopeNames();
    ASSERT_EQ(scopeNames.size(), 2);
    ASSERT_EQ(scopeNames[0], "scope_0");
    ASSERT_EQ(scopeNames[1], "scope_1");
}

TEST_F(MetricsInterfaceTest, getAllMetricsEmpty)
{
    auto contents = m_manager->getAllMetrics();
    ASSERT_EQ(contents.isNull(), true);
}

TEST_F(MetricsInterfaceTest, getAllMetricsOneScope)
{
    auto scope0 = m_manager->getMetricsScope("scope_0");
    auto contents = m_manager->getAllMetrics();
    ASSERT_EQ(contents.size(), 1);
}

TEST_F(MetricsInterfaceTest, getAllMetricsOneScopeOneCounter)
{
    auto scope0 = m_manager->getMetricsScope("scope_0");
    auto counter0 = scope0->getCounterDouble("counter_0");
    counter0->addValue(5);
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    auto record = m_manager->getAllMetrics().getArray("/scope_0/counter_0/records");
    auto name = record.value()[0].getString("/instrument_name");

    ASSERT_TRUE(name);
    ASSERT_EQ(name, "counter_0");
}

TEST_F(MetricsInterfaceTest, getAllMetricsOneScopeTwoCounters)
{
    auto scope0 = m_manager->getMetricsScope("scope_0");
    auto counter0 = scope0->getCounterDouble("counter_0");
    auto counter1 = scope0->getCounterUInteger("counter_1");
    counter0->addValue(5.0);
    counter1->addValue(2);
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    auto record = m_manager->getAllMetrics().getArray("/scope_0/counter_0/records");
    auto name = record.value()[0].getString("/instrument_name");

    ASSERT_TRUE(name);
    ASSERT_EQ(name, "counter_0");

    record = m_manager->getAllMetrics().getArray("/scope_0/counter_1/records");
    name = record.value()[0].getString("/instrument_name");

    ASSERT_TRUE(name);
    ASSERT_EQ(name, "counter_1");
}

TEST_F(MetricsInterfaceTest, getAllMetricsHistogram)
{
    auto scope0 = m_manager->getMetricsScope("scope_0");
    auto histogram0 = scope0->getHistogramUInteger("histogram_0");

    const auto NUMBER_RECORS {1000};

    for (int i = 0; i < NUMBER_RECORS; i++)
    {
        histogram0->recordValue(rand() % 10000);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    auto record = m_manager->getAllMetrics().getArray("/scope_0/histogram_0/records");
    auto attributes = record.value()[0].getArray("/attributes");

    EXPECT_EQ(attributes.value()[0].getInt("/count").value(), NUMBER_RECORS);
    EXPECT_EQ(attributes.value()[0].getString("/type").value(), "HistogramPointData");
}

TEST_F(MetricsInterfaceTest, gaugeTest)
{
    auto scope0 = m_manager->getMetricsScope("scope_0");
    auto gauge0 = scope0->getGaugeInteger("gauge_0", 0);

    const auto TEST_VALUE {10};

    gauge0->setValue(TEST_VALUE);

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    auto record = m_manager->getAllMetrics().getArray("/scope_0/gauge_0/records");

    auto attributes = record.value()[0].getArray("/attributes");

    EXPECT_EQ(attributes.value()[0].getString("/type").value(), "LastValuePointData");
    EXPECT_EQ(attributes.value()[0].getInt("/value").value(), TEST_VALUE);
}
