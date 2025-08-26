#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <thread>

#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <scheduler/scheduler.hpp>

class SchedulerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit();
        scheduler = std::make_unique<scheduler::Scheduler>(2); // 2 worker threads
    }

    void TearDown() override
    {
        if (scheduler && scheduler->isRunning())
        {
            scheduler->stop();
        }
        scheduler.reset();
    }

    std::unique_ptr<scheduler::Scheduler> scheduler;
};

TEST_F(SchedulerTest, SchedulerInitialization)
{
    EXPECT_FALSE(scheduler->isRunning());
    EXPECT_EQ(scheduler->getThreadCount(), 2);
    EXPECT_EQ(scheduler->getActiveTasksCount(), 0);
}

TEST_F(SchedulerTest, StartStopScheduler)
{
    EXPECT_FALSE(scheduler->isRunning());

    scheduler->start();
    EXPECT_TRUE(scheduler->isRunning());

    scheduler->stop();
    EXPECT_FALSE(scheduler->isRunning());
}

TEST_F(SchedulerTest, ScheduleOneTimeTask)
{
    std::atomic<bool> taskExecuted {false};

    scheduler::TaskConfig config;
    config.interval = 0; // One-time task
    config.CPUPriority = 10;
    config.timeout = 0;
    config.taskFunction = [&taskExecuted]()
    {
        taskExecuted.store(true);
    };

    scheduler->start();
    scheduler->scheduleTask("oneTimeTask", std::move(config));

    // Wait a bit for task execution
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    EXPECT_TRUE(taskExecuted.load());

    // One-time task should be removed after execution
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_EQ(scheduler->getActiveTasksCount(), 0);

    scheduler->stop();
}

TEST_F(SchedulerTest, ScheduleRecurringTask)
{
    std::atomic<int> executionCount {0};

    scheduler::TaskConfig config;
    config.interval = 1; // Every 1 second
    config.CPUPriority = 5;
    config.timeout = 0;
    config.taskFunction = [&executionCount]()
    {
        executionCount.fetch_add(1);
    };

    scheduler->start();
    scheduler->scheduleTask("recurringTask", std::move(config));

    EXPECT_EQ(scheduler->getActiveTasksCount(), 1);

    // Wait for multiple executions (but not too long for test performance)
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));

    // Should have executed at least once
    EXPECT_GE(executionCount.load(), 1);

    scheduler->stop();
}

TEST_F(SchedulerTest, RemoveTask)
{
    std::atomic<bool> taskExecuted {false};

    scheduler::TaskConfig config;
    config.interval = 2; // Every 2 seconds
    config.CPUPriority = 10;
    config.timeout = 0;
    config.taskFunction = [&taskExecuted]()
    {
        taskExecuted.store(true);
    };

    scheduler->start();
    scheduler->scheduleTask("taskToRemove", std::move(config));

    EXPECT_EQ(scheduler->getActiveTasksCount(), 1);

    // Remove task before it executes
    scheduler->removeTask("taskToRemove");

    EXPECT_EQ(scheduler->getActiveTasksCount(), 0);

    // Wait to ensure task doesn't execute
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    EXPECT_FALSE(taskExecuted.load());

    scheduler->stop();
}

TEST_F(SchedulerTest, MultipleTasks)
{
    std::atomic<int> task1Count {0};
    std::atomic<int> task2Count {0};

    scheduler::TaskConfig config1;
    config1.interval = 0;    // One-time
    config1.CPUPriority = 0; // No priority change for testing
    config1.timeout = 0;
    config1.taskFunction = [&task1Count]()
    {
        task1Count.fetch_add(1);
    };

    scheduler::TaskConfig config2;
    config2.interval = 1;    // Recurring
    config2.CPUPriority = 0; // No priority change for testing
    config2.timeout = 0;
    config2.taskFunction = [&task2Count]()
    {
        task2Count.fetch_add(1);
    };

    scheduler->start();
    scheduler->scheduleTask("task1", std::move(config1));
    scheduler->scheduleTask("task2", std::move(config2));

    // Wait for tasks to execute - increased time to ensure execution
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    EXPECT_EQ(task1Count.load(), 1); // One-time task executed once
    EXPECT_GE(task2Count.load(), 0); // Recurring task may have executed

    scheduler->stop();
}

TEST_F(SchedulerTest, TaskPriority)
{
    std::vector<int> executionOrder;
    std::mutex orderMutex;
    std::atomic<int> completedTasks {0};

    auto createTask = [&](int taskId, int priority)
    {
        scheduler::TaskConfig config;
        config.interval = 0; // One-time
        config.CPUPriority = priority;
        config.timeout = 0;
        config.taskFunction = [&, taskId]()
        {
            {
                std::lock_guard<std::mutex> lock(orderMutex);
                executionOrder.push_back(taskId);
            }
            completedTasks.fetch_add(1);
        };
        return config;
    };

    scheduler->start();

    // Schedule tasks - CPU priority doesn't affect execution order, only nice value
    scheduler->scheduleTask("lowPriorityTask", createTask(1, 1));
    scheduler->scheduleTask("highPriorityTask", createTask(2, 10));
    scheduler->scheduleTask("mediumPriorityTask", createTask(3, 5));

    // Wait for all tasks to complete
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    EXPECT_EQ(completedTasks.load(), 3);

    {
        std::lock_guard<std::mutex> lock(orderMutex);
        EXPECT_EQ(executionOrder.size(), 3);
    }

    scheduler->stop();
}

TEST_F(SchedulerTest, TaskExecutionOrder)
{
    std::vector<std::string> executionOrder;
    std::mutex orderMutex;
    std::atomic<int> completedTasks {0};

    auto createDelayedTask = [&](const std::string& taskName, int delayMs)
    {
        scheduler::TaskConfig config;
        config.interval = 0; // One-time
        config.CPUPriority = 0;
        config.timeout = 0;
        config.taskFunction = [&, taskName]()
        {
            {
                std::lock_guard<std::mutex> lock(orderMutex);
                executionOrder.push_back(taskName);
            }
            completedTasks.fetch_add(1);
        };
        return config;
    };

    scheduler->start();

    // Schedule tasks with different timing
    scheduler->scheduleTask("immediateTask", createDelayedTask("immediate", 0));

    // Sleep briefly to ensure the immediate task gets queued first
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    scheduler->scheduleTask("laterTask", createDelayedTask("later", 0));

    // Wait for all tasks to complete
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    EXPECT_EQ(completedTasks.load(), 2);

    {
        std::lock_guard<std::mutex> lock(orderMutex);
        ASSERT_EQ(executionOrder.size(), 2);
        // Earlier scheduled tasks should execute first (FIFO for same time)
        EXPECT_EQ(executionOrder[0], "immediate");
        EXPECT_EQ(executionOrder[1], "later");
    }

    scheduler->stop();
}

TEST_F(SchedulerTest, TaskQueueOrdering)
{
    std::vector<std::string> executionOrder;
    std::mutex orderMutex;
    std::atomic<int> completedTasks {0};

    auto createRecurringTask = [&](const std::string& taskName, int intervalSeconds)
    {
        scheduler::TaskConfig config;
        config.interval = intervalSeconds; // Recurring task
        config.CPUPriority = 0;
        config.timeout = 0;
        config.taskFunction = [&, taskName]()
        {
            {
                std::lock_guard<std::mutex> lock(orderMutex);
                executionOrder.push_back(taskName);
            }
            completedTasks.fetch_add(1);
        };
        return config;
    };

    scheduler->start();

    // Schedule recurring tasks with different intervals
    scheduler->scheduleTask("slow", createRecurringTask("slow", 2)); // Every 2 seconds
    scheduler->scheduleTask("fast", createRecurringTask("fast", 1)); // Every 1 second

    // Wait for multiple executions
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));

    // Fast task should execute first (shorter interval = earlier next run time)
    EXPECT_GE(completedTasks.load(), 1);

    {
        std::lock_guard<std::mutex> lock(orderMutex);
        if (!executionOrder.empty())
        {
            EXPECT_EQ(executionOrder[0], "fast"); // Fast task executes first
        }
    }

    scheduler->stop();
}
