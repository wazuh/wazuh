#include <metrics/manager.hpp>

#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <base/functionExecutor.hpp>
#include <base/logging.hpp>
#include <base/threadSynchronizer.hpp>
#include <indexerConnector/mockiconnector.hpp>
#include <metric/metric.hpp>

#include "ot.hpp"

using namespace metrics;
using namespace indexerconnector::mocks;
using namespace base::test;

TEST(MetricsManagerSingletonTest, Instantiate)
{
    ASSERT_NO_THROW(Manager {});
}

/*******************************************************************************
 * Single Threaded Tests
 * Not testing metric OT interaction with manager OT
 ******************************************************************************/
class MetricsManagerTest : public ::testing::Test
{
protected:
    Manager m_manager;
    std::shared_ptr<MockIConnector> m_mockIConnector;

    void SetUp() override { m_mockIConnector = std::make_shared<MockIConnector>(); }

    void TearDown() override { m_manager.disable(); }

    std::shared_ptr<Manager::ImplConfig> testConfig() const
    {
        auto config = std::make_shared<Manager::ImplConfig>();
        config->indexerConnectorFactory = [connector = m_mockIConnector]()
        {
            return connector;
        };
        config->exportInterval = std::chrono::milliseconds(100);
        config->exportTimeout = std::chrono::milliseconds(33);
        config->logLevel = logging::Level::Warn;

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
    ASSERT_NO_THROW(m_manager.addMetric(MetricType::UINTCOUNTER, "module.metric", "desc", "unit"));

    // Adding a metric with invalid name should throw
    ASSERT_THROW(m_manager.addMetric(MetricType::UINTCOUNTER, "invalidname", "desc", "unit"), std::runtime_error);
    // Adding the same metric again should throw
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
    ASSERT_THROW(m_manager.getMetric("invalidname"), std::runtime_error);
}

TEST_F(MetricsManagerTest, EnableModule)
{
    auto config = testConfig();
    m_manager.configure(config);
    ASSERT_NO_THROW(m_manager.addMetric(MetricType::UINTCOUNTER, "module.metric", "desc", "unit"));

    // Enabling a module that does not exist should throw
    ASSERT_THROW(m_manager.enableModule("non_existent"), std::runtime_error);
    // Enabling a module that exists should not throw
    ASSERT_NO_THROW(m_manager.enableModule("module"));
    // Enabling a module that is already enabled should not throw
    ASSERT_NO_THROW(m_manager.enableModule("module"));
    // Enabling a module with invalid name should throw
    ASSERT_THROW(m_manager.enableModule("invalid.name"), std::runtime_error);
}

TEST_F(MetricsManagerTest, DisableModule)
{
    auto config = testConfig();
    m_manager.configure(config);
    ASSERT_NO_THROW(m_manager.addMetric(MetricType::UINTCOUNTER, "module.metric", "desc", "unit"));

    // Disabling a module that does not exist should throw
    ASSERT_THROW(m_manager.disableModule("non_existent"), std::runtime_error);
    // Disabling a module that exists should not throw
    ASSERT_NO_THROW(m_manager.disableModule("module"));
    // Disabling a module that is already disabled should not throw
    ASSERT_NO_THROW(m_manager.disableModule("module"));
    // Disabling a module with invalid name should throw
    ASSERT_THROW(m_manager.disableModule("invalid.name"), std::runtime_error);
}

/*******************************************************************************
 * Multi Threaded Tests
 * Not testing metric OT interaction with manager OT
 ******************************************************************************/
class MetricsManagerMultiThreadedTest : public ::testing::Test
{
protected:
    std::shared_ptr<IManager> m_manager;
    std::shared_ptr<MockIConnector> m_mockIConnector;

    void SetUp() override
    {
        m_mockIConnector = std::make_shared<MockIConnector>();
        m_manager = std::make_shared<Manager>();
    }

    void TearDown() override
    {
        m_manager->disable();
        m_manager.reset();
    }

    std::shared_ptr<Manager::ImplConfig> testConfig() const
    {
        auto config = std::make_shared<Manager::ImplConfig>();
        config->indexerConnectorFactory = [connector = m_mockIConnector]()
        {
            return connector;
        };
        config->exportInterval = std::chrono::milliseconds(100);
        config->exportTimeout = std::chrono::milliseconds(33);
        config->logLevel = logging::Level::Warn;

        return config;
    }
};

TEST_F(MetricsManagerMultiThreadedTest, Configure)
{
    auto nThreads = 10;
    auto times = 100;

    for (auto iteration = 0; iteration < times; iteration++)
    {
        std::vector<std::thread> threads(nThreads);
        ThreadSynchronizer sync(nThreads);

        for (auto i = 0; i < nThreads; i++)
        {
            threads[i] = std::thread(
                [manager = m_manager, config = testConfig(), &sync]()
                {
                    sync.waitForAll();
                    ASSERT_NO_THROW(manager->configure(config));
                });
        }

        sync.waitNotifyAll();

        for (auto& thread : threads)
        {
            thread.join();
        }
    }
}

TEST_F(MetricsManagerMultiThreadedTest, Enable)
{
    auto nThreads = 100;
    auto times = 10;
    m_manager->configure(testConfig());

    for (auto iteration = 0; iteration < times; iteration++)
    {
        std::vector<std::thread> threads(nThreads);
        std::vector<std::shared_ptr<bool>> results(nThreads);

        for (auto& result : results)
        {
            result = std::make_shared<bool>(false);
        }

        ThreadSynchronizer sync(nThreads);

        for (auto i = 0; i < nThreads; i++)
        {
            threads[i] = std::thread(
                [manager = m_manager, result = results[i], &sync]()
                {
                    sync.waitForAll();

                    try
                    {
                        manager->enable();
                        *result = true;
                    }
                    catch (...)
                    {
                    }
                });
        }

        sync.waitNotifyAll();

        for (auto& thread : threads)
        {
            thread.join();
        }

        // Ensure only one thread succeeded in calling enable()
        ASSERT_EQ(
            std::count_if(results.begin(), results.end(), [](const std::shared_ptr<bool>& result) { return *result; }),
            1);

        ASSERT_NO_THROW(m_manager->disable());
    }
}

TEST_F(MetricsManagerMultiThreadedTest, Disable)
{
    auto nThreads = 100;
    auto times = 10;
    m_manager->configure(testConfig());

    for (auto iteration = 0; iteration < times; iteration++)
    {
        ASSERT_NO_THROW(m_manager->enable());

        std::vector<std::thread> threads(nThreads);
        ThreadSynchronizer sync(nThreads);

        for (auto i = 0; i < nThreads; i++)
        {
            threads[i] = std::thread(
                [manager = m_manager, &sync]()
                {
                    sync.waitForAll();
                    ASSERT_NO_THROW(manager->disable());
                });
        }

        sync.waitNotifyAll();

        for (auto& thread : threads)
        {
            thread.join();
        }
    }
}

TEST_F(MetricsManagerMultiThreadedTest, Reload)
{
    auto nThreads = 10;
    auto times = 5;
    m_manager->configure(testConfig());
    m_manager->enable();

    for (auto iteration = 0; iteration < times; iteration++)
    {
        std::vector<std::thread> threads(nThreads);
        ThreadSynchronizer sync(nThreads);

        for (auto i = 0; i < nThreads; i++)
        {
            threads[i] = std::thread(
                [manager = m_manager, config = testConfig(), &sync]()
                {
                    sync.waitForAll();
                    ASSERT_NO_THROW(manager->reload(config));
                });
        }

        sync.waitNotifyAll();

        // Join all threads
        for (auto& thread : threads)
        {
            thread.join();
        }
    }
}

TEST_F(MetricsManagerMultiThreadedTest, AddMetric)
{
    auto nThreads = 100;
    auto times = 10;
    m_manager->configure(testConfig());
    m_manager->enable();

    for (auto iteration = 0; iteration < times; iteration++)
    {
        std::vector<std::thread> threads(nThreads);
        std::vector<std::shared_ptr<bool>> results(nThreads);

        // Initialize result holders
        for (auto& result : results)
        {
            result = std::make_shared<bool>(false);
        }

        ThreadSynchronizer sync(nThreads);

        for (auto i = 0; i < nThreads; i++)
        {
            threads[i] = std::thread(
                [iteration, manager = m_manager, result = results[i], &sync]()
                {
                    sync.waitForAll();
                    try
                    {
                        manager->addMetric(
                            MetricType::UINTCOUNTER, fmt::format("module.metric{}", iteration), "desc", "unit");
                        *result = true;
                    }
                    catch (...)
                    {
                    }
                });
        }

        sync.waitNotifyAll();

        for (auto& thread : threads)
        {
            thread.join();
        }

        ASSERT_EQ(
            std::count_if(results.begin(), results.end(), [](const std::shared_ptr<bool>& result) { return *result; }),
            1);
    }
}

TEST_F(MetricsManagerMultiThreadedTest, GetMetric)
{
    auto nThreads = 100;
    auto times = 10;
    m_manager->configure(testConfig());
    m_manager->enable();
    m_manager->addMetric(MetricType::UINTCOUNTER, "module.metric", "desc", "unit");

    for (auto iteration = 0; iteration < times; iteration++)
    {
        std::vector<std::thread> threads(nThreads);
        std::vector<std::shared_ptr<bool>> results(nThreads);

        // Initialize result holders
        for (auto& result : results)
        {
            result = std::make_shared<bool>(false);
        }

        ThreadSynchronizer sync(nThreads);

        for (auto i = 0; i < nThreads; i++)
        {
            threads[i] = std::thread(
                [manager = m_manager, result = results[i], &sync]()
                {
                    sync.waitForAll();
                    try
                    {
                        manager->getMetric("module.metric");
                        *result = true;
                    }
                    catch (...)
                    {
                    }
                });
        }

        sync.waitNotifyAll();

        for (auto& thread : threads)
        {
            thread.join();
        }

        ASSERT_EQ(
            std::count_if(results.begin(), results.end(), [](const std::shared_ptr<bool>& result) { return *result; }),
            nThreads);
    }
}

TEST_F(MetricsManagerMultiThreadedTest, EnableModule)
{
    auto nThreads = 100;
    auto times = 10;
    m_manager->configure(testConfig());
    m_manager->enable();
    m_manager->addMetric(MetricType::UINTCOUNTER, "module.metric", "desc", "unit");

    for (auto iteration = 0; iteration < times; iteration++)
    {
        std::vector<std::thread> threads(nThreads);
        std::vector<std::shared_ptr<bool>> results(nThreads);

        // Initialize result holders
        for (auto& result : results)
        {
            result = std::make_shared<bool>(false);
        }

        ThreadSynchronizer sync(nThreads);

        for (auto i = 0; i < nThreads; i++)
        {
            threads[i] = std::thread(
                [manager = m_manager, result = results[i], &sync]()
                {
                    sync.waitForAll();
                    try
                    {
                        manager->enableModule("module");
                        *result = true;
                    }
                    catch (...)
                    {
                    }
                });
        }

        sync.waitNotifyAll();

        for (auto& thread : threads)
        {
            thread.join();
        }

        ASSERT_EQ(
            std::count_if(results.begin(), results.end(), [](const std::shared_ptr<bool>& result) { return *result; }),
            nThreads);
    }
}

TEST_F(MetricsManagerMultiThreadedTest, DisableModule)
{
    auto nThreads = 100;
    auto times = 10;
    m_manager->configure(testConfig());
    m_manager->enable();
    m_manager->addMetric(MetricType::UINTCOUNTER, "module.metric", "desc", "unit");

    for (auto iteration = 0; iteration < times; iteration++)
    {
        std::vector<std::thread> threads(nThreads);
        std::vector<std::shared_ptr<bool>> results(nThreads);

        // Initialize result holders
        for (auto& result : results)
        {
            result = std::make_shared<bool>(false);
        }

        ThreadSynchronizer sync(nThreads);

        for (auto i = 0; i < nThreads; i++)
        {
            threads[i] = std::thread(
                [manager = m_manager, result = results[i], &sync]()
                {
                    sync.waitForAll();
                    try
                    {
                        manager->disableModule("module");
                        *result = true;
                    }
                    catch (...)
                    {
                    }
                });
        }

        sync.waitNotifyAll();

        for (auto& thread : threads)
        {
            thread.join();
        }

        ASSERT_EQ(
            std::count_if(results.begin(), results.end(), [](const std::shared_ptr<bool>& result) { return *result; }),
            nThreads);
    }
}

TEST_F(MetricsManagerMultiThreadedTest, AllSimultaneously)
{
    auto nThreads = 100;
    auto times = 10;

    struct Results
    {
        std::atomic_uint successCount = 0;
        std::atomic_uint failureCount = 0;
    };

    // 8 is the number of functions in FunctionExecutor
    std::vector<std::shared_ptr<Results>> results;
    for (auto i = 0; i < 8; i++)
    {
        results.emplace_back(std::make_shared<Results>());
    }

    FunctionExecutor funcExec(
        [manager = m_manager, config = testConfig(), res = results[0]]()
        {
            try
            {
                manager->configure(config);
                res->successCount.fetch_add(1, std::memory_order_relaxed);
            }
            catch (...)
            {
                res->failureCount.fetch_add(1, std::memory_order_relaxed);
            }
        },
        [manager = m_manager, config = testConfig(), res = results[1]]()
        {
            try
            {
                manager->reload(config);
                res->successCount.fetch_add(1, std::memory_order_relaxed);
            }
            catch (...)
            {
                res->failureCount.fetch_add(1, std::memory_order_relaxed);
            }
        },
        [manager = m_manager, res = results[2]]()
        {
            try
            {
                manager->enable();
                res->successCount.fetch_add(1, std::memory_order_relaxed);
            }
            catch (...)
            {
                res->failureCount.fetch_add(1, std::memory_order_relaxed);
            }
        },
        [manager = m_manager, res = results[3]]()
        {
            try
            {
                manager->disable();
                res->successCount.fetch_add(1, std::memory_order_relaxed);
            }
            catch (...)
            {
                res->failureCount.fetch_add(1, std::memory_order_relaxed);
            }
        },
        [manager = m_manager, res = results[4]]()
        {
            try
            {
                manager->addMetric(MetricType::UINTCOUNTER, "module.metric", "desc", "unit");
                res->successCount.fetch_add(1, std::memory_order_relaxed);
            }
            catch (...)
            {
                res->failureCount.fetch_add(1, std::memory_order_relaxed);
            }
        },
        [manager = m_manager, res = results[5]]()
        {
            try
            {
                manager->getMetric("module.metric");
                res->successCount.fetch_add(1, std::memory_order_relaxed);
            }
            catch (...)
            {
                res->failureCount.fetch_add(1, std::memory_order_relaxed);
            }
        },
        [manager = m_manager, res = results[6]]()
        {
            try
            {
                manager->enableModule("module");
                res->successCount.fetch_add(1, std::memory_order_relaxed);
            }
            catch (...)
            {
                res->failureCount.fetch_add(1, std::memory_order_relaxed);
            }
        },
        [manager = m_manager, res = results[7]]()
        {
            try
            {
                manager->disableModule("module");
                res->successCount.fetch_add(1, std::memory_order_relaxed);
            }
            catch (...)
            {
                res->failureCount.fetch_add(1, std::memory_order_relaxed);
            }
        });

    std::vector<std::thread> threads(nThreads);
    ThreadSynchronizer sync(nThreads);

    for (auto iteration = 0; iteration < times; iteration++)
    {
        sync.reset();

        for (auto i = 0; i < nThreads; i++)
        {
            threads[i] = std::thread(
                [&, i]
                {
                    sync.waitForAll();
                    funcExec.executeRandomFunction();
                });
        }

        sync.waitNotifyAll();

        for (auto& thread : threads)
        {
            thread.join();
        }
    }

    auto totalCounts = 0;
    for (auto& res : results)
    {
        totalCounts += res->successCount.load(std::memory_order_relaxed);
        totalCounts += res->failureCount.load(std::memory_order_relaxed);
    }

    ASSERT_EQ(totalCounts, nThreads * times);
}
