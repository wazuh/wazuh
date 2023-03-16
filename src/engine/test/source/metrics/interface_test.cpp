#include <gtest/gtest.h>
#include <memory>

#include <metrics/metricsManager.hpp>

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
