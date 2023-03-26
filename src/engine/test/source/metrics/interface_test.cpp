#include <gtest/gtest.h>
#include <memory>

#include <metrics/metricsManager.hpp>
#include <json/json.hpp>

using namespace metrics_manager;

class MetricsInterfaceTest : public ::testing::Test
{
protected:

    MetricsInterfaceTest() 
    {
        m_manager = std::make_shared<MetricsManager>();
    }

    ~MetricsInterfaceTest() 
    {
        
    }

    void TearDown() override
    {

    }

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
    ASSERT_EQ(contents.size(), 0);
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
    auto contents = m_manager->getAllMetrics();
    std::cout << contents.prettyStr() << std::endl;
}

