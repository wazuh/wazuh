#include <metrics/manager.hpp>

#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <indexerConnector/mockiconnector.hpp>

#include <metrics/mockMetric.hpp>

#include "ot.hpp"

using namespace metrics;
using namespace indexerconnector::mocks;
using namespace metrics::mocks;

TEST(MetricsManagerSingletonTest, Instantiate)
{
    ASSERT_NO_THROW(Manager {});
}

class MetricsManagerTest : public ::testing::Test
{
protected:
    Manager m_manager;
    std::shared_ptr<MockIConnector> m_mockIConnector;

    void SetUp() override
    {
        logging::testInit();
        m_mockIConnector = std::make_shared<MockIConnector>();
    }

    void TearDown() override { m_manager.disable(); }

    std::shared_ptr<Manager::ManagerConfig> testConfig() const
    {
        auto config = std::make_shared<Manager::ManagerConfig>();
        config->indexerConnectorFactory = [connector = m_mockIConnector]()
        {
            return connector;
        };
        config->exportInterval = std::chrono::milliseconds(100);
        config->exportTimeout = std::chrono::milliseconds(33);
        config->logLevel = logging::Level::Err;

        return config;
    }
};

TEST_F(MetricsManagerTest, Configure)
{
    auto config = testConfig();

    ASSERT_THROW(m_manager.configure(nullptr), std::runtime_error);
    auto notManagerCongif = std::make_shared<Manager::Config>();
    ASSERT_THROW(m_manager.configure(notManagerCongif), std::runtime_error);
    ASSERT_NO_THROW(m_manager.configure(config));
    ASSERT_NO_THROW(m_manager.configure(config));

    auto invalidConfig = testConfig();
    invalidConfig->indexerConnectorFactory = nullptr;
    ASSERT_THROW(m_manager.configure(invalidConfig), std::runtime_error);

    invalidConfig = testConfig();
    invalidConfig->exportInterval = std::chrono::milliseconds(0);
    ASSERT_THROW(m_manager.configure(invalidConfig), std::runtime_error);

    invalidConfig = testConfig();
    invalidConfig->exportTimeout = std::chrono::milliseconds(0);
    ASSERT_THROW(m_manager.configure(invalidConfig), std::runtime_error);

    invalidConfig = testConfig();
    invalidConfig->exportTimeout = invalidConfig->exportInterval + std::chrono::milliseconds(1);
    ASSERT_THROW(m_manager.configure(invalidConfig), std::runtime_error);
}

TEST_F(MetricsManagerTest, Enable)
{
    auto config = testConfig();

    // Bad call somewhere in the pipeline creation
    config->indexerConnectorFactory = []()
    {
        return nullptr;
    };
    m_manager.configure(config);
    ASSERT_FALSE(m_manager.isEnabled());
    ASSERT_THROW(m_manager.enable(), std::runtime_error);
    ASSERT_FALSE(m_manager.isEnabled());

    config = testConfig();
    m_manager.configure(config);
    ASSERT_NO_THROW(m_manager.enable());
    ASSERT_TRUE(m_manager.isEnabled());

    // Enabling again should throw
    ASSERT_THROW(m_manager.enable(), std::runtime_error);
    ASSERT_TRUE(m_manager.isEnabled());
}

TEST_F(MetricsManagerTest, Disable)
{
    // Disable should not throw if not enabled
    ASSERT_FALSE(m_manager.isEnabled());
    ASSERT_NO_THROW(m_manager.disable());
    ASSERT_FALSE(m_manager.isEnabled());

    m_manager.configure(testConfig());
    m_manager.enable();
    ASSERT_TRUE(m_manager.isEnabled());
    ASSERT_NO_THROW(m_manager.disable());
    ASSERT_FALSE(m_manager.isEnabled());
}

TEST_F(MetricsManagerTest, Reload)
{
    auto config = testConfig();
    auto shouldThrow = std::make_shared<bool>(false);
    config->indexerConnectorFactory = [shouldThrow, mockConnector = m_mockIConnector]()
    {
        if (*shouldThrow)
        {
            throw std::runtime_error("Test Error");
        }

        return mockConnector;
    };

    // Calling if not enabled mimics configure
    ASSERT_FALSE(m_manager.isEnabled());
    ASSERT_NO_THROW(m_manager.reload(config));
    ASSERT_FALSE(m_manager.isEnabled());

    m_manager.enable();
    ASSERT_TRUE(m_manager.isEnabled());

    // Calling with invalid config should throw and restore
    auto invalidConfig = testConfig();
    invalidConfig->indexerConnectorFactory = nullptr;
    ASSERT_THROW(m_manager.reload(invalidConfig), std::runtime_error);
    ASSERT_TRUE(m_manager.isEnabled());

    // Calling with invalid config and failure to restore
    *shouldThrow = true;
    ASSERT_THROW(m_manager.reload(invalidConfig), std::runtime_error);
    ASSERT_FALSE(m_manager.isEnabled());
}

TEST_F(MetricsManagerTest, AddMetric)
{
    auto config = testConfig();
    m_manager.configure(config);
    std::shared_ptr<IMetric> metric;
    ASSERT_NO_THROW(metric = m_manager.addMetric(MetricType::UINTCOUNTER, "module.metric", "desc", "unit"));

    ASSERT_THROW(m_manager.addMetric(MetricType::UINTCOUNTER, "invalidname", "desc", "unit"), std::runtime_error);
    ASSERT_THROW(m_manager.addMetric(MetricType::UINTCOUNTER, "module.metric", "desc", "unit"), std::runtime_error);
}

TEST_F(MetricsManagerTest, GetMetric)
{
    auto config = testConfig();
    m_manager.configure(config);
    std::shared_ptr<IMetric> metric;
    ASSERT_NO_THROW(metric = m_manager.addMetric(MetricType::UINTCOUNTER, "module.metric", "desc", "unit"));

    ASSERT_EQ(metric, m_manager.getMetric("module.metric"));
    ASSERT_THROW(m_manager.getMetric("non.existent"), std::runtime_error);
}
