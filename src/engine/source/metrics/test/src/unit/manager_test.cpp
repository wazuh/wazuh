#include <metrics/manager.hpp>

#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <indexerConnector/mockiconnector.hpp>

#include "managerImpl.hpp"
#include "ot.hpp"
#include <metric/metric.hpp>

using namespace metrics;
using namespace indexerconnector::mocks;

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

    void SetUp() override
    {
        logging::testInit();
        m_mockIConnector = std::make_shared<MockIConnector>();
    }

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
        logging::testInit();
        m_mockIConnector = std::make_shared<MockIConnector>();
        m_manager = std::make_shared<Manager>();
    }

    void TearDown() override { m_manager.reset(); }

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

        // Synchronization mechanism
        std::mutex mtx;
        std::condition_variable cv;
        bool ready = false;
        int waiting_threads = 0;

        for (auto i = 0; i < nThreads; i++)
        {
            threads[i] = std::thread(
                [manager = m_manager, config = testConfig(), &mtx, &cv, &ready, &waiting_threads, nThreads]()
                {
                    // Step 1: Synchronization mechanism
                    std::unique_lock<std::mutex> lock(mtx);
                    waiting_threads++;
                    if (waiting_threads == nThreads)
                    {
                        ready = true;
                        cv.notify_all();
                    }
                    else
                    {
                        cv.wait(lock, [&ready]() { return ready; });
                    }
                    lock.unlock();

                    // Step 2: Perform the actual job (configure)
                    ASSERT_NO_THROW(manager->configure(config));
                });
        }

        // Join all threads
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

        // Initializing result holders
        for (auto& result : results)
        {
            result = std::make_shared<bool>(false);
        }

        // Synchronization mechanism
        std::mutex mtx;
        std::condition_variable cv;
        bool ready = false;
        int waiting_threads = 0;

        for (auto i = 0; i < nThreads; i++)
        {
            threads[i] = std::thread(
                [manager = m_manager, result = results[i], &mtx, &cv, &ready, &waiting_threads, nThreads]()
                {
                    // Step 1: Synchronization mechanism
                    std::unique_lock<std::mutex> lock(mtx);
                    waiting_threads++;
                    if (waiting_threads == nThreads)
                    {
                        ready = true;
                        cv.notify_all();
                    }
                    else
                    {
                        cv.wait(lock, [&ready]() { return ready; });
                    }
                    lock.unlock();

                    // Step 2: Try to enable the manager
                    try
                    {
                        manager->enable();
                        *result = true;
                    }
                    catch (...)
                    {
                        *result = false;
                    }
                });
        }

        // Join all threads
        for (auto& thread : threads)
        {
            thread.join();
        }

        // Ensure only one thread succeeded in calling enable()
        ASSERT_EQ(
            std::count_if(results.begin(), results.end(), [](const std::shared_ptr<bool>& result) { return *result; }),
            1);

        // Clean up by disabling the manager
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
        std::mutex mtx;
        std::condition_variable cv;
        bool ready = false;
        int waiting_threads = 0;

        for (auto i = 0; i < nThreads; i++)
        {
            threads[i] = std::thread(
                [manager = m_manager, &mtx, &cv, &ready, &waiting_threads, nThreads]()
                {
                    // Step 1: Synchronization mechanism
                    std::unique_lock<std::mutex> lock(mtx);
                    waiting_threads++;
                    if (waiting_threads == nThreads)
                    {
                        // Notify all threads that they can start
                        ready = true;
                        cv.notify_all();
                    }
                    else
                    {
                        // Wait until all threads are ready
                        cv.wait(lock, [&ready]() { return ready; });
                    }
                    lock.unlock();

                    // Step 2: Perform the actual job
                    ASSERT_NO_THROW(manager->disable());
                });
        }

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

        // Synchronization mechanism
        std::mutex mtx;
        std::condition_variable cv;
        bool ready = false;
        int waiting_threads = 0;

        for (auto i = 0; i < nThreads; i++)
        {
            threads[i] = std::thread(
                [manager = m_manager, config = testConfig(), &mtx, &cv, &ready, &waiting_threads, nThreads]()
                {
                    // Step 1: Synchronization mechanism
                    std::unique_lock<std::mutex> lock(mtx);
                    waiting_threads++;
                    if (waiting_threads == nThreads)
                    {
                        ready = true;
                        cv.notify_all();
                    }
                    else
                    {
                        cv.wait(lock, [&ready]() { return ready; });
                    }
                    lock.unlock();

                    // Step 2: Perform the actual job (reload)
                    ASSERT_NO_THROW(manager->reload(config));
                });
        }

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

        // Synchronization mechanism
        std::mutex mtx;
        std::condition_variable cv;
        bool ready = false;
        int waiting_threads = 0;

        for (auto i = 0; i < nThreads; i++)
        {
            threads[i] = std::thread(
                [iteration, manager = m_manager, result = results[i], &mtx, &cv, &ready, &waiting_threads, nThreads]()
                {
                    // Step 1: Synchronization mechanism
                    std::unique_lock<std::mutex> lock(mtx);
                    waiting_threads++;
                    if (waiting_threads == nThreads)
                    {
                        ready = true;
                        cv.notify_all();
                    }
                    else
                    {
                        cv.wait(lock, [&ready]() { return ready; });
                    }
                    lock.unlock();

                    // Step 2: Try to add metric
                    try
                    {
                        manager->addMetric(
                            MetricType::UINTCOUNTER, fmt::format("module.metric{}", iteration), "desc", "unit");
                        *result = true;
                    }
                    catch (...)
                    {
                        *result = false;
                    }
                });
        }

        // Join all threads
        for (auto& thread : threads)
        {
            thread.join();
        }

        // Ensure only one succeeded in adding the metric
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

        // Synchronization mechanism
        std::mutex mtx;
        std::condition_variable cv;
        bool ready = false;
        int waiting_threads = 0;

        for (auto i = 0; i < nThreads; i++)
        {
            threads[i] = std::thread(
                [manager = m_manager, result = results[i], &mtx, &cv, &ready, &waiting_threads, nThreads]()
                {
                    // Step 1: Synchronization mechanism
                    std::unique_lock<std::mutex> lock(mtx);
                    waiting_threads++;
                    if (waiting_threads == nThreads)
                    {
                        ready = true;
                        cv.notify_all();
                    }
                    else
                    {
                        cv.wait(lock, [&ready]() { return ready; });
                    }
                    lock.unlock();

                    // Step 2: Try to get metric
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

        // Join all threads
        for (auto& thread : threads)
        {
            thread.join();
        }

        // Ensure all threads succeeded in getting the metric
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

        // Synchronization mechanism
        std::mutex mtx;
        std::condition_variable cv;
        bool ready = false;
        int waiting_threads = 0;

        for (auto i = 0; i < nThreads; i++)
        {
            threads[i] = std::thread(
                [manager = m_manager, result = results[i], &mtx, &cv, &ready, &waiting_threads, nThreads]()
                {
                    // Step 1: Synchronization mechanism
                    std::unique_lock<std::mutex> lock(mtx);
                    waiting_threads++;
                    if (waiting_threads == nThreads)
                    {
                        ready = true;
                        cv.notify_all();
                    }
                    else
                    {
                        cv.wait(lock, [&ready]() { return ready; });
                    }
                    lock.unlock();

                    // Step 2: Try to enable module
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

        // Join all threads
        for (auto& thread : threads)
        {
            thread.join();
        }

        // Ensure all threads succeeded in enabling the module
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

        // Synchronization mechanism
        std::mutex mtx;
        std::condition_variable cv;
        bool ready = false;
        int waiting_threads = 0;

        for (auto i = 0; i < nThreads; i++)
        {
            threads[i] = std::thread(
                [manager = m_manager, result = results[i], &mtx, &cv, &ready, &waiting_threads, nThreads]()
                {
                    // Step 1: Synchronization mechanism
                    std::unique_lock<std::mutex> lock(mtx);
                    waiting_threads++;
                    if (waiting_threads == nThreads)
                    {
                        ready = true;
                        cv.notify_all();
                    }
                    else
                    {
                        cv.wait(lock, [&ready]() { return ready; });
                    }
                    lock.unlock();

                    // Step 2: Try to disable module
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

        // Join all threads
        for (auto& thread : threads)
        {
            thread.join();
        }

        // Ensure all threads succeeded in disabling the module
        ASSERT_EQ(
            std::count_if(results.begin(), results.end(), [](const std::shared_ptr<bool>& result) { return *result; }),
            nThreads);
    }
}
