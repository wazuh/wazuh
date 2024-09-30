#include <metrics/manager.hpp>

#include <gtest/gtest.h>

#include <base/functionExecutor.hpp>
#include <base/json.hpp>
#include <base/threadSynchronizer.hpp>
#include <indexerConnector/mockiconnector.hpp>

using namespace metrics;
using namespace indexerconnector::mocks;
using namespace base::test;

class FakePublisher
{
private:
    std::shared_mutex m_mutex;
    std::optional<json::Json> m_uintCounterLastValue;
    std::optional<json::Json> m_uintHistogramLastValue;
    std::optional<json::Json> m_doubleCounterLastValue;
    std::optional<json::Json> m_doubleHistogramLastValue;

public:
    void publish(const std::string& message)
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        auto asJson = json::Json(message.c_str());
        auto metrics = asJson.getArray("/data/metrics");
        if (!metrics.has_value() || metrics.value().empty())
        {
            return;
        }

        for (auto& metric : metrics.value())
        {
            auto name = metric.getString("/name").value();
            if (name == "uint.counter")
            {
                m_uintCounterLastValue = metric.getJson("/points/0/value");
            }

            if (name == "uint.histogram")
            {
                m_uintHistogramLastValue = metric.getJson("/points/0/sum");
            }

            if (name == "double.counter")
            {
                m_doubleCounterLastValue = metric.getJson("/points/0/value");
            }

            if (name == "double.histogram")
            {
                m_doubleHistogramLastValue = metric.getJson("/points/0/sum");
            }
        }
    }

    std::optional<json::Json> getUintCounterLastUpdate()
    {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        return m_uintCounterLastValue;
    }

    std::optional<json::Json> getUintHistogramLastUpdate()
    {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        return m_uintHistogramLastValue;
    }

    std::optional<json::Json> getDoubleCounterLastUpdate()
    {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        return m_doubleCounterLastValue;
    }

    std::optional<json::Json> getDoubleHistogramLastUpdate()
    {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        return m_doubleHistogramLastValue;
    }
};

class MetricsTest : public ::testing::Test
{
protected:
    std::shared_ptr<Manager> m_manager;
    std::shared_ptr<Manager::ImplConfig> m_config;
    std::shared_ptr<MockIConnector> m_mockConnector;
    std::shared_ptr<FakePublisher> m_publisher;

    void SetUp() override
    {
        logging::testInit();

        m_manager = std::make_shared<Manager>();

        m_config = std::make_shared<Manager::ImplConfig>();
        m_mockConnector = std::make_shared<MockIConnector>();
        m_config->indexerConnectorFactory = [=]()
        {
            return m_mockConnector;
        };
        m_config->exportInterval = std::chrono::milliseconds(33);
        m_config->exportTimeout = std::chrono::milliseconds(15);

        m_publisher = std::make_shared<FakePublisher>();
        ON_CALL(*m_mockConnector, publish(::testing::_))
            .WillByDefault(::testing::Invoke([publisher = m_publisher](const std::string& message)
                                             { publisher->publish(message); }));
    }

    IManager& managerInstance() { return static_cast<IManager&>(*m_manager); }
    IMetricsManager& getManager() { return static_cast<IMetricsManager&>(*m_manager); }
};

TEST_F(MetricsTest, MetricUpdateEnabledManager)
{
    auto iterations = 10;
    auto jobUpdates = 100;

    ASSERT_NO_THROW(managerInstance().configure(m_config));
    ASSERT_NO_THROW(managerInstance().enable());

    getManager().addMetric(MetricType::UINTCOUNTER, "uint.counter", "desc", "unit");
    getManager().addMetric(MetricType::UINTHISTOGRAM, "uint.histogram", "desc", "unit");
    getManager().addMetric(MetricType::DOUBLECOUNTER, "double.counter", "desc", "unit");
    getManager().addMetric(MetricType::DOUBLEHISTOGRAM, "double.histogram", "desc", "unit");

    auto metricUserJob0 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("uint.counter");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<uint64_t>(1);
        }
    };

    auto metricUserJob1 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("uint.histogram");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<uint64_t>(1);
        }
    };

    auto metricUserJob2 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("double.counter");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<double>(1.0);
        }
    };

    auto metricUserJob3 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("double.histogram");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<double>(1.0);
        }
    };

    EXPECT_CALL(*m_mockConnector, publish(::testing::_)).Times(::testing::AtLeast(1));
    for (auto iter = 0; iter < iterations; iter++)
    {

        std::vector<std::thread> threads;
        threads.emplace_back(metricUserJob0);
        threads.emplace_back(metricUserJob1);
        threads.emplace_back(metricUserJob2);
        threads.emplace_back(metricUserJob3);

        for (auto& thread : threads)
        {
            thread.join();
        }

        // Wait for the metrics to be exported
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        ASSERT_TRUE(m_publisher->getUintCounterLastUpdate().has_value());
        ASSERT_TRUE(m_publisher->getUintHistogramLastUpdate().has_value());
        ASSERT_TRUE(m_publisher->getDoubleCounterLastUpdate().has_value());
        ASSERT_TRUE(m_publisher->getDoubleHistogramLastUpdate().has_value());

        EXPECT_EQ((iter + 1) * jobUpdates, m_publisher->getUintCounterLastUpdate().value().getInt().value());
        EXPECT_EQ((iter + 1) * jobUpdates, m_publisher->getUintHistogramLastUpdate().value().getInt().value());
        EXPECT_EQ((iter + 1) * jobUpdates, m_publisher->getDoubleCounterLastUpdate().value().getDouble().value());
        EXPECT_EQ((iter + 1) * jobUpdates, m_publisher->getDoubleHistogramLastUpdate().value().getDouble().value());
    }
}

TEST_F(MetricsTest, MetricUpdateDisabledManager)
{
    auto iterations = 10;
    auto jobUpdates = 100;

    ASSERT_NO_THROW(managerInstance().configure(m_config));

    getManager().addMetric(MetricType::UINTCOUNTER, "uint.counter", "desc", "unit");
    getManager().addMetric(MetricType::UINTHISTOGRAM, "uint.histogram", "desc", "unit");
    getManager().addMetric(MetricType::DOUBLECOUNTER, "double.counter", "desc", "unit");
    getManager().addMetric(MetricType::DOUBLEHISTOGRAM, "double.histogram", "desc", "unit");

    auto metricUserJob0 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("uint.counter");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<uint64_t>(1);
        }
    };

    auto metricUserJob1 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("uint.histogram");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<uint64_t>(1);
        }
    };

    auto metricUserJob2 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("double.counter");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<double>(1.0);
        }
    };

    auto metricUserJob3 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("double.histogram");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<double>(1.0);
        }
    };

    for (auto iter = 0; iter < iterations; iter++)
    {
        std::vector<std::thread> threads;
        threads.emplace_back(metricUserJob0);
        threads.emplace_back(metricUserJob1);
        threads.emplace_back(metricUserJob2);
        threads.emplace_back(metricUserJob3);

        for (auto& thread : threads)
        {
            thread.join();
        }

        // Wait for the metrics to be exported
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        ASSERT_FALSE(m_publisher->getUintCounterLastUpdate().has_value());
        ASSERT_FALSE(m_publisher->getUintHistogramLastUpdate().has_value());
        ASSERT_FALSE(m_publisher->getDoubleCounterLastUpdate().has_value());
        ASSERT_FALSE(m_publisher->getDoubleHistogramLastUpdate().has_value());
    }
}

TEST_F(MetricsTest, MetricUpdateReloadManager)
{
    auto iterations = 10;
    auto jobUpdates = 100;

    ASSERT_NO_THROW(managerInstance().configure(m_config));
    ASSERT_NO_THROW(managerInstance().enable());

    getManager().addMetric(MetricType::UINTCOUNTER, "uint.counter", "desc", "unit");
    getManager().addMetric(MetricType::UINTHISTOGRAM, "uint.histogram", "desc", "unit");
    getManager().addMetric(MetricType::DOUBLECOUNTER, "double.counter", "desc", "unit");
    getManager().addMetric(MetricType::DOUBLEHISTOGRAM, "double.histogram", "desc", "unit");

    auto metricUserJob0 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("uint.counter");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<uint64_t>(1);
        }
    };

    auto metricUserJob1 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("uint.histogram");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<uint64_t>(1);
        }
    };

    auto metricUserJob2 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("double.counter");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<double>(1.0);
        }
    };

    auto metricUserJob3 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("double.histogram");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<double>(1.0);
        }
    };

    EXPECT_CALL(*m_mockConnector, publish(::testing::_)).Times(::testing::AtLeast(1));
    for (auto iter = 0; iter < iterations; iter++)
    {
        // Reload the manager
        managerInstance().reload(m_config);

        std::vector<std::thread> threads;
        threads.emplace_back(metricUserJob0);
        threads.emplace_back(metricUserJob1);
        threads.emplace_back(metricUserJob2);
        threads.emplace_back(metricUserJob3);

        for (auto& thread : threads)
        {
            thread.join();
        }

        // Wait for the metrics to be exported
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        ASSERT_TRUE(m_publisher->getUintCounterLastUpdate().has_value());
        ASSERT_TRUE(m_publisher->getUintHistogramLastUpdate().has_value());
        ASSERT_TRUE(m_publisher->getDoubleCounterLastUpdate().has_value());
        ASSERT_TRUE(m_publisher->getDoubleHistogramLastUpdate().has_value());

        EXPECT_EQ(jobUpdates, m_publisher->getUintCounterLastUpdate().value().getInt().value());
        EXPECT_EQ(jobUpdates, m_publisher->getUintHistogramLastUpdate().value().getInt().value());
        EXPECT_EQ(jobUpdates, m_publisher->getDoubleCounterLastUpdate().value().getDouble().value());
        EXPECT_EQ(jobUpdates, m_publisher->getDoubleHistogramLastUpdate().value().getDouble().value());
    }
}

TEST_F(MetricsTest, MetricUpdateDisabledModule)
{
    auto iterations = 10;
    auto jobUpdates = 100;

    ASSERT_NO_THROW(managerInstance().configure(m_config));
    ASSERT_NO_THROW(managerInstance().enable());

    getManager().addMetric(MetricType::UINTCOUNTER, "uint.counter", "desc", "unit");
    getManager().addMetric(MetricType::UINTHISTOGRAM, "uint.histogram", "desc", "unit");
    getManager().addMetric(MetricType::DOUBLECOUNTER, "double.counter", "desc", "unit");
    getManager().addMetric(MetricType::DOUBLEHISTOGRAM, "double.histogram", "desc", "unit");

    auto metricUserJob0 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("uint.counter");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<uint64_t>(1);
        }
    };

    auto metricUserJob1 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("uint.histogram");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<uint64_t>(1);
        }
    };

    auto metricUserJob2 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("double.counter");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<double>(1.0);
        }
    };

    auto metricUserJob3 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("double.histogram");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<double>(1.0);
        }
    };

    EXPECT_CALL(*m_mockConnector, publish(::testing::_)).Times(::testing::AtLeast(1));
    for (auto iter = 0; iter < iterations; iter++)
    {
        // Disable the module
        managerInstance().disableModule("uint");

        std::vector<std::thread> threads;
        threads.emplace_back(metricUserJob0);
        threads.emplace_back(metricUserJob1);
        threads.emplace_back(metricUserJob2);
        threads.emplace_back(metricUserJob3);

        for (auto& thread : threads)
        {
            thread.join();
        }

        // Wait for the metrics to be exported
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        ASSERT_FALSE(m_publisher->getUintCounterLastUpdate().has_value());
        ASSERT_FALSE(m_publisher->getUintHistogramLastUpdate().has_value());

        ASSERT_TRUE(m_publisher->getDoubleCounterLastUpdate().has_value());
        ASSERT_TRUE(m_publisher->getDoubleHistogramLastUpdate().has_value());

        EXPECT_EQ((iter + 1) * jobUpdates, m_publisher->getDoubleCounterLastUpdate().value().getDouble().value());
        EXPECT_EQ((iter + 1) * jobUpdates, m_publisher->getDoubleHistogramLastUpdate().value().getDouble().value());
    }
}

TEST_F(MetricsTest, MetricUpdateDisableEnableModule)
{
    auto iterations = 10;
    auto jobUpdates = 100;

    ASSERT_NO_THROW(managerInstance().configure(m_config));
    ASSERT_NO_THROW(managerInstance().enable());

    getManager().addMetric(MetricType::UINTCOUNTER, "uint.counter", "desc", "unit");
    getManager().addMetric(MetricType::UINTHISTOGRAM, "uint.histogram", "desc", "unit");
    getManager().addMetric(MetricType::DOUBLECOUNTER, "double.counter", "desc", "unit");
    getManager().addMetric(MetricType::DOUBLEHISTOGRAM, "double.histogram", "desc", "unit");

    auto metricUserJob0 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("uint.counter");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<uint64_t>(1);
        }
    };

    auto metricUserJob1 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("uint.histogram");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<uint64_t>(1);
        }
    };

    auto metricUserJob2 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("double.counter");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<double>(1.0);
        }
    };

    auto metricUserJob3 = [&, jobUpdates]()
    {
        auto metric = getManager().getMetric("double.histogram");
        for (auto i = 0; i < jobUpdates; i++)
        {
            metric->update<double>(1.0);
        }
    };

    EXPECT_CALL(*m_mockConnector, publish(::testing::_)).Times(::testing::AtLeast(1));
    for (auto iter = 0; iter < iterations; iter++)
    {
        // Reload module
        managerInstance().disableModule("uint");
        managerInstance().enableModule("uint");

        std::vector<std::thread> threads;
        threads.emplace_back(metricUserJob0);
        threads.emplace_back(metricUserJob1);
        threads.emplace_back(metricUserJob2);
        threads.emplace_back(metricUserJob3);

        for (auto& thread : threads)
        {
            thread.join();
        }

        // Wait for the metrics to be exported
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        ASSERT_TRUE(m_publisher->getUintCounterLastUpdate().has_value());
        ASSERT_TRUE(m_publisher->getUintHistogramLastUpdate().has_value());
        ASSERT_TRUE(m_publisher->getDoubleCounterLastUpdate().has_value());
        ASSERT_TRUE(m_publisher->getDoubleHistogramLastUpdate().has_value());

        EXPECT_EQ((iter + 1) * jobUpdates, m_publisher->getUintCounterLastUpdate().value().getInt().value());
        EXPECT_EQ((iter + 1) * jobUpdates, m_publisher->getUintHistogramLastUpdate().value().getInt().value());
        EXPECT_EQ((iter + 1) * jobUpdates, m_publisher->getDoubleCounterLastUpdate().value().getDouble().value());
        EXPECT_EQ((iter + 1) * jobUpdates, m_publisher->getDoubleHistogramLastUpdate().value().getDouble().value());
    }
}
