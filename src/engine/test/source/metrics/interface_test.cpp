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
    auto contents = m_manager->getAllMetrics();
    
    auto json_scope = contents.getObject("/scope_0");
    ASSERT_TRUE(json_scope);
    auto scope_0=json_scope.value()[0];
    auto name=std::get<1>(scope_0).getString("/scope");
    ASSERT_TRUE(name);
    ASSERT_EQ(name, "counter_0");
}

TEST_F(MetricsInterfaceTest, getAllMetricsOneScopeTwoCounters)
{
    auto scope0 = m_manager->getMetricsScope("scope_0");
    auto counter0 = scope0->getCounterDouble("counter_0");
    auto counter1 = scope0->getCounterInteger("counter_1");
    counter0->addValue(5.0);
    counter1->addValue(2);
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    auto contents = m_manager->getAllMetrics();
    std::cout << contents.prettyStr() << std::endl;
    
    auto json_scope = contents.getObject("/scope_0");
    ASSERT_TRUE(json_scope);
    auto scope_0=json_scope.value()[0];
    auto name=std::get<1>(scope_0).getString("/scope");
    ASSERT_TRUE(name);
    ASSERT_EQ(name, "counter_0");

    auto scope_1=json_scope.value()[1];
    auto name2=std::get<1>(scope_1).getString("/scope");
    ASSERT_TRUE(name2);
    ASSERT_EQ(name2, "counter_1");
}

TEST_F(MetricsInterfaceTest, getAllMetricsHistogram)
{
    auto scope0 = m_manager->getMetricsScope("scope_0");
    auto histogram0 = scope0->getHistogramInteger("histogram_0");
    
    for (int i=0; i<100; i++)
    {
        histogram0->recordValue(rand()%100);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    auto contents = m_manager->getAllMetrics();
    std::cout << contents.prettyStr() << std::endl;
}
