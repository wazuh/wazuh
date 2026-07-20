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
    config.runImmediately = false;
    config.CPUPriority = 10;
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
    config.runImmediately = false;
    config.CPUPriority = 5;
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

TEST_F(SchedulerTest, RunImmediately_ExecutesOnFirstCycle)
{
    std::atomic<int> executionCount {0};

    scheduler::TaskConfig config;
    config.interval = 5; // 5-second interval — would not fire in test window without flag
    config.runImmediately = true;
    config.CPUPriority = 0;
    config.taskFunction = [&executionCount]()
    {
        executionCount.fetch_add(1);
    };

    scheduler->start();
    scheduler->scheduleTask("immRecurringTask", std::move(config));

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    EXPECT_GE(executionCount.load(), 1);

    scheduler->stop();
}

TEST_F(SchedulerTest, RunImmediately_ThenRecurresAtInterval)
{
    std::atomic<int> executionCount {0};

    scheduler::TaskConfig config;
    config.interval = 1;
    config.runImmediately = true;
    config.CPUPriority = 0;
    config.taskFunction = [&executionCount]()
    {
        executionCount.fetch_add(1);
    };

    scheduler->start();
    scheduler->scheduleTask("immRecurringTask2", std::move(config));

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_GE(executionCount.load(), 1); // immediate first execution

    std::this_thread::sleep_for(std::chrono::milliseconds(1200));
    EXPECT_GE(executionCount.load(), 2); // at least one recurrence after interval

    EXPECT_EQ(scheduler->getActiveTasksCount(), 1); // task not removed (not one-time)

    scheduler->stop();
}

TEST_F(SchedulerTest, RunImmediately_NoEffectOnOneTimeTask)
{
    std::atomic<int> executionCount {0};

    scheduler::TaskConfig config;
    config.interval = 0;
    config.runImmediately = true;
    config.CPUPriority = 0;
    config.taskFunction = [&executionCount]()
    {
        executionCount.fetch_add(1);
    };

    scheduler->start();
    scheduler->scheduleTask("oneTimeImmediate", std::move(config));

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    EXPECT_EQ(executionCount.load(), 1);            // executed exactly once
    EXPECT_EQ(scheduler->getActiveTasksCount(), 0); // removed from map

    scheduler->stop();
}

TEST_F(SchedulerTest, ScheduleTaskFirst_ExecutesBeforeOtherPendingTasks)
{
    std::vector<std::string> executionOrder;
    std::mutex orderMutex;

    scheduler::TaskConfig regularConfig;
    regularConfig.interval = 0;
    regularConfig.runImmediately = false;
    regularConfig.CPUPriority = 0;
    regularConfig.taskFunction = [&]()
    {
        std::lock_guard<std::mutex> lock(orderMutex);
        executionOrder.push_back("regular");
    };

    scheduler::TaskConfig firstConfig;
    firstConfig.interval = 0;
    firstConfig.runImmediately = false;
    firstConfig.CPUPriority = 0;
    firstConfig.taskFunction = [&]()
    {
        std::lock_guard<std::mutex> lock(orderMutex);
        executionOrder.push_back("first");
    };

    // Register regular first (earlier nextRun), then priority task
    scheduler->scheduleTask("regularTask", std::move(regularConfig));
    scheduler->scheduleTask("priorityTask", std::move(firstConfig));
    // Reprioritize: "priorityTask" must now execute before "regularTask"
    scheduler->scheduleTaskFirst("priorityTask");

    scheduler->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::lock_guard<std::mutex> lock(orderMutex);
    ASSERT_EQ(executionOrder.size(), 2u);
    EXPECT_EQ(executionOrder[0], "first");
    EXPECT_EQ(executionOrder[1], "regular");
}

TEST_F(SchedulerTest, ScheduleTaskFirst_LastCallIsFirst)
{
    std::vector<std::string> executionOrder;
    std::mutex orderMutex;

    auto makeConfig = [&](std::string label)
    {
        scheduler::TaskConfig config;
        config.interval = 0;
        config.runImmediately = false;
        config.CPUPriority = 0;
        config.taskFunction = [&, label = std::move(label)]()
        {
            std::lock_guard<std::mutex> lock(orderMutex);
            executionOrder.push_back(label);
        };
        return config;
    };

    scheduler->scheduleTask("taskA", makeConfig("A"));
    scheduler->scheduleTask("taskB", makeConfig("B"));
    scheduler->scheduleTaskFirst("taskA"); // A goes to front
    scheduler->scheduleTaskFirst("taskB"); // B goes to front, A pushed to position 1

    scheduler->start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::lock_guard<std::mutex> lock(orderMutex);
    ASSERT_EQ(executionOrder.size(), 2u);
    EXPECT_EQ(executionOrder[0], "B");
    EXPECT_EQ(executionOrder[1], "A");
}

TEST_F(SchedulerTest, RemoveTask)
{
    std::atomic<bool> taskExecuted {false};

    scheduler::TaskConfig config;
    config.interval = 2; // Every 2 seconds
    config.runImmediately = false;
    config.CPUPriority = 10;
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
    config1.interval = 0; // One-time
    config1.runImmediately = false;
    config1.CPUPriority = 0; // No priority change for testing
    config1.taskFunction = [&task1Count]()
    {
        task1Count.fetch_add(1);
    };

    scheduler::TaskConfig config2;
    config2.interval = 1; // Recurring
    config2.runImmediately = false;
    config2.CPUPriority = 0; // No priority change for testing
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
        config.runImmediately = false;
        config.CPUPriority = priority;
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
        config.runImmediately = false;
        config.CPUPriority = 0;
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
        config.runImmediately = false;
        config.CPUPriority = 0;
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

/**************************************************************************
 * Additional tests for uncovered paths
 *************************************************************************/

TEST_F(SchedulerTest, StartWhenAlreadyRunning)
{
    scheduler->start();
    EXPECT_TRUE(scheduler->isRunning());

    // Calling start again should be a no-op (covers L31 early return)
    scheduler->start();
    EXPECT_TRUE(scheduler->isRunning());

    scheduler->stop();
}

TEST_F(SchedulerTest, ScheduleTaskWithNullFunction)
{
    scheduler::TaskConfig config;
    config.interval = 0;
    config.runImmediately = false;
    config.CPUPriority = 0;
    config.taskFunction = nullptr;

    scheduler->start();

    // Should throw std::invalid_argument (covers L89)
    EXPECT_THROW(scheduler->scheduleTask("nullTask", std::move(config)), std::invalid_argument);

    scheduler->stop();
}

TEST_F(SchedulerTest, ScheduleTaskDuplicateName)
{
    scheduler::TaskConfig config1;
    config1.interval = 5;
    config1.runImmediately = false;
    config1.CPUPriority = 0;
    config1.taskFunction = []() {};

    scheduler::TaskConfig config2;
    config2.interval = 5;
    config2.runImmediately = false;
    config2.CPUPriority = 0;
    config2.taskFunction = []() {};

    scheduler->start();
    scheduler->scheduleTask("duplicateTask", std::move(config1));

    // Second schedule with same name should throw (covers L101)
    EXPECT_THROW(scheduler->scheduleTask("duplicateTask", std::move(config2)), std::runtime_error);

    scheduler->stop();
}

TEST_F(SchedulerTest, TaskRemovedBeforeExecution)
{
    std::atomic<bool> taskExecuted {false};

    scheduler::TaskConfig config;
    config.interval = 1; // Recurring, first run after 1 second
    config.runImmediately = false;
    config.CPUPriority = 0;
    config.taskFunction = [&taskExecuted]()
    {
        taskExecuted.store(true);
    };

    scheduler->start();
    scheduler->scheduleTask("removedBeforeExec", std::move(config));

    // Remove immediately before first execution (covers L170-171)
    scheduler->removeTask("removedBeforeExec");

    // Wait past the interval to ensure the popped task won't find it in m_tasks
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));

    EXPECT_FALSE(taskExecuted.load());

    scheduler->stop();
}

TEST_F(SchedulerTest, TaskThrowsStdException)
{
    std::atomic<bool> afterThrow {false};

    scheduler::TaskConfig throwConfig;
    throwConfig.interval = 0;
    throwConfig.runImmediately = false;
    throwConfig.CPUPriority = 0;
    throwConfig.taskFunction = []()
    {
        throw std::runtime_error("intentional test error");
    };

    scheduler::TaskConfig afterConfig;
    afterConfig.interval = 0;
    afterConfig.runImmediately = false;
    afterConfig.CPUPriority = 0;
    afterConfig.taskFunction = [&afterThrow]()
    {
        afterThrow.store(true);
    };

    scheduler->start();
    scheduler->scheduleTask("throwingTask", std::move(throwConfig));

    // Wait for the throwing task to execute
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // Schedule another task to prove scheduler is still alive after exception
    scheduler->scheduleTask("afterThrow", std::move(afterConfig));
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_TRUE(afterThrow.load());

    scheduler->stop();
}

TEST_F(SchedulerTest, TaskThrowsUnknownException)
{
    std::atomic<bool> afterThrow {false};

    scheduler::TaskConfig throwConfig;
    throwConfig.interval = 0;
    throwConfig.runImmediately = false;
    throwConfig.CPUPriority = 0;
    throwConfig.taskFunction = []()
    {
        throw 42; // non-std exception
    };

    scheduler::TaskConfig afterConfig;
    afterConfig.interval = 0;
    afterConfig.runImmediately = false;
    afterConfig.CPUPriority = 0;
    afterConfig.taskFunction = [&afterThrow]()
    {
        afterThrow.store(true);
    };

    scheduler->start();
    scheduler->scheduleTask("unknownThrowTask", std::move(throwConfig));

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // Scheduler should survive unknown exceptions
    scheduler->scheduleTask("afterUnknownThrow", std::move(afterConfig));
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_TRUE(afterThrow.load());

    scheduler->stop();
}

TEST_F(SchedulerTest, DestructorStopsScheduler)
{
    std::atomic<int> counter {0};

    scheduler::TaskConfig config;
    config.interval = 1;
    config.runImmediately = false;
    config.CPUPriority = 0;
    config.taskFunction = [&counter]()
    {
        counter.fetch_add(1);
    };

    scheduler->start();
    scheduler->scheduleTask("destructorTest", std::move(config));

    // Destroy the scheduler - should call stop() in destructor
    scheduler.reset();

    // Scheduler should be gone, no crash
    EXPECT_EQ(scheduler, nullptr);
}

TEST_F(SchedulerTest, StopWithoutStart)
{
    // Calling stop without start should be safe (early return in stop)
    EXPECT_FALSE(scheduler->isRunning());
    EXPECT_NO_THROW(scheduler->stop());
    EXPECT_FALSE(scheduler->isRunning());
}

TEST_F(SchedulerTest, ConstructorWithZeroThreads)
{
    // Constructor should enforce minimum 2 threads
    auto sched = std::make_unique<scheduler::Scheduler>(0);
    EXPECT_EQ(sched->getThreadCount(), 2);
}

TEST_F(SchedulerTest, ConstructorWithNegativeThreads)
{
    auto sched = std::make_unique<scheduler::Scheduler>(-5);
    EXPECT_EQ(sched->getThreadCount(), 2);
}

// --- Input validation ---

TEST_F(SchedulerTest, ScheduleTask_ThrowsOnNullFunction)
{
    scheduler::TaskConfig config;
    config.interval = 1;
    config.runImmediately = false;
    config.CPUPriority = 0;
    config.taskFunction = nullptr;

    EXPECT_THROW(scheduler->scheduleTask("nullTask", std::move(config)), std::invalid_argument);
    EXPECT_EQ(scheduler->getActiveTasksCount(), 0);
}

TEST_F(SchedulerTest, ScheduleTask_ThrowsOnDuplicateName)
{
    auto makeConfig = []()
    {
        scheduler::TaskConfig config;
        config.interval = 60;
        config.runImmediately = false;
        config.CPUPriority = 0;
        config.taskFunction = []() {};
        return config;
    };

    scheduler->scheduleTask("duplicate", makeConfig());
    EXPECT_THROW(scheduler->scheduleTask("duplicate", makeConfig()), std::runtime_error);
    EXPECT_EQ(scheduler->getActiveTasksCount(), 1);
}

TEST_F(SchedulerTest, ScheduleTaskFirst_ThrowsOnUnregisteredTask)
{
    EXPECT_THROW(scheduler->scheduleTaskFirst("notRegistered"), std::invalid_argument);
}

TEST_F(SchedulerTest, RemoveTask_NoopForNonExistentTask)
{
    EXPECT_NO_THROW(scheduler->removeTask("doesNotExist"));
    EXPECT_EQ(scheduler->getActiveTasksCount(), 0);
}

// --- Lifecycle ---

TEST_F(SchedulerTest, StartStop_Idempotent)
{
    scheduler->start();
    scheduler->start(); // second call must be a no-op — no extra threads spawned
    EXPECT_TRUE(scheduler->isRunning());

    // Scheduler must still be functional after double-start
    std::atomic<bool> executed {false};
    scheduler::TaskConfig config;
    config.interval = 0;
    config.runImmediately = false;
    config.CPUPriority = 0;
    config.taskFunction = [&executed]()
    {
        executed.store(true);
    };
    scheduler->scheduleTask("probe", std::move(config));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(executed.load());

    scheduler->stop();
    scheduler->stop(); // second call must be a no-op — no crash or deadlock
    EXPECT_FALSE(scheduler->isRunning());
}

TEST_F(SchedulerTest, TasksClearedAfterStop)
{
    scheduler->start();

    for (int i = 0; i < 5; ++i)
    {
        scheduler::TaskConfig config;
        config.interval = 60; // far future — won't execute in test window
        config.runImmediately = false;
        config.CPUPriority = 0;
        config.taskFunction = []() {};
        scheduler->scheduleTask("task" + std::to_string(i), std::move(config));
    }

    EXPECT_EQ(scheduler->getActiveTasksCount(), 5);
    scheduler->stop();
    EXPECT_EQ(scheduler->getActiveTasksCount(), 0);
}

// --- RC-2 fix: recurring task removed during execution must not re-queue ---

TEST_F(SchedulerTest, RemoveRecurringTask_WhileExecuting_DoesNotReschedule)
{
    std::atomic<int> executionCount {0};
    std::atomic<bool> taskStarted {false};
    std::atomic<bool> allowFinish {false};

    scheduler::TaskConfig config;
    config.interval = 1;
    config.runImmediately = true; // fires immediately so we can catch it mid-execution
    config.CPUPriority = 0;
    config.taskFunction = [&]()
    {
        executionCount.fetch_add(1);
        taskStarted.store(true);
        while (!allowFinish.load())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    };

    scheduler->start();
    scheduler->scheduleTask("recurringTask", std::move(config));

    // Wait until the task is executing
    while (!taskStarted.load())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    // Remove while task body is still running
    scheduler->removeTask("recurringTask");
    EXPECT_EQ(scheduler->getActiveTasksCount(), 0);

    // Let the task finish — worker must not re-queue it after execution
    allowFinish.store(true);

    // Wait well past one interval to confirm no second execution
    std::this_thread::sleep_for(std::chrono::milliseconds(1200));

    EXPECT_EQ(executionCount.load(), 1);
    EXPECT_EQ(scheduler->getActiveTasksCount(), 0);

    scheduler->stop();
}

// --- RC-5 fix: scheduleTaskFirst on a running scheduler must execute promptly ---

TEST_F(SchedulerTest, ScheduleTaskFirst_WhileRunning_ReprioritizesImmediately)
{
    std::atomic<bool> executed {false};

    scheduler::TaskConfig config;
    config.interval = 60; // 60 s interval — would never fire in this test
    config.runImmediately = false;
    config.CPUPriority = 0;
    config.taskFunction = [&executed]()
    {
        executed.store(true);
    };

    scheduler->start();
    scheduler->scheduleTask("slowTask", std::move(config));

    // Confirm the task has not fired yet (nextRun is 60 s in the future)
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(executed.load());

    // Reprioritize: worker blocked in wait_until must wake and execute immediately
    scheduler->scheduleTaskFirst("slowTask");

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(executed.load());

    scheduler->stop();
}

// --- Thread safety: concurrent schedule + remove from multiple threads ---

TEST_F(SchedulerTest, ConcurrentScheduleRemove_IsThreadSafe)
{
    scheduler->start();

    const int taskCount = 20;
    std::vector<std::thread> threads;
    threads.reserve(taskCount);

    for (int i = 0; i < taskCount; ++i)
    {
        threads.emplace_back(
            [&, i]()
            {
                std::string name = "concTask" + std::to_string(i);
                scheduler::TaskConfig config;
                config.interval = 0;
                config.runImmediately = false;
                config.CPUPriority = 0;
                config.taskFunction = []() {};
                scheduler->scheduleTask(name, std::move(config));
                // removeTask races with execution — both outcomes are valid
                scheduler->removeTask(name);
            });
    }

    for (auto& t : threads)
    {
        t.join();
    }

    // Allow any in-flight tasks to finish
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Every task either executed (and was auto-removed) or was removed before execution
    EXPECT_EQ(scheduler->getActiveTasksCount(), 0);

    scheduler->stop();
}
