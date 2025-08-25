#ifndef _SCHEDULER_HPP
#define _SCHEDULER_HPP

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <scheduler/ischeduler.hpp>

namespace scheduler
{

/**
 * @brief Internal representation of a scheduled task
 */
struct ScheduledTask
{
    std::string name;                              ///< Unique task identifier
    TaskConfig config;                             ///< Task configuration (interval, priority, function)
    std::chrono::steady_clock::time_point nextRun; ///< Next scheduled execution time
    bool isOneTime;                                ///< True if task should run only once

    /**
     * @brief Creates a new scheduled task with the given name and configuration.
     * @param taskName Unique name for the task
     * @param taskConfig Configuration for task execution
     */
    ScheduledTask(std::string&& taskName, TaskConfig&& taskConfig)
        : name(std::move(taskName))
        , config(std::move(taskConfig))
        , isOneTime(config.interval == 0)
    {
        nextRun = [&]() -> std::chrono::steady_clock::time_point
        {
            if (isOneTime)
            {
                return std::chrono::steady_clock::now();
            }
            return std::chrono::steady_clock::now() + std::chrono::seconds(config.interval);
        }();
    }

    /**
     * @brief Update the next execution time for recurring tasks
     * @note Only applies to recurring tasks (interval > 0)
     */
    void updateNextRun()
    {
        if (!isOneTime && config.interval > 0)
        {
            nextRun = std::chrono::steady_clock::now() + std::chrono::seconds(config.interval);
        }
    }
};

/**
 * @brief Comparator for task priority queue ordering, ensuring chronological execution
 */
struct TaskComparator
{
    /**
     * @brief Compare two scheduled tasks for priority ordering.
     * @details Returns true if lhs should be executed after rhs (lower priority).
     * Earlier execution times have higher priority in the queue.
     *
     * @param lhs Left-hand side task for comparison
     * @param rhs Right-hand side task for comparison
     * @return true if lhs has lower priority than rhs, false otherwise
     */
    bool operator()(const std::shared_ptr<ScheduledTask>& lhs, const std::shared_ptr<ScheduledTask>& rhs) const
    {
        return lhs->nextRun > rhs->nextRun;
    }
};

/**
 * @brief Multi-threaded task scheduler implementation
 * @details Concrete implementation of IScheduler that provides:
 *          - Multi-threaded task execution with configurable thread pool
 *          - Priority-based task scheduling using time-ordered queue
 *          - CPU priority management for individual tasks
 *          - Support for both one-time and recurring tasks
 *          - Thread-safe operations for concurrent access
 *
 * The scheduler uses a producer-consumer pattern where:
 * - Main thread(s) add tasks to the queue via scheduleTask()
 * - Worker threads consume tasks from the priority queue for execution
 * - Tasks are automatically rescheduled if they are recurring
 * @note All operations are thread-safe
 */
class Scheduler : public IScheduler
{
public:
    /**
     * @brief Constructor
     * @details Creates a new scheduler with the specified number of worker threads.
     *          The scheduler is created in stopped state and must be started explicitly.
     *
     * @param threads Number of worker threads to create (minimum 1)
     * @note If threads <= 0, exactly 1 thread will be created
     */
    Scheduler(int threads = 1);

    /**
     * @brief Destructor
     * @details Automatically stops the scheduler and cleans up all resources.
     *          Waits for all worker threads to complete before destruction.
     */
    ~Scheduler();

    /**
     * @brief Start the scheduler
     *
     * @note This operation is idempotent - calling start() on an already running
     *       scheduler has no effect
     * @note This method is thread-safe
     */
    void start();

    /**
     * @brief Stop the scheduler
     * @details Gracefully stops all worker threads and clears the task queue.
     *          Currently executing tasks are allowed to complete.
     *
     * @note This operation is idempotent - calling stop() on a stopped scheduler
     *       has no effect
     * @note This method blocks until all worker threads have terminated
     * @note This method is thread-safe
     */
    void stop();

    /**
     * @brief Check if the scheduler is currently running
     *
     * @return true if the scheduler is running and can execute tasks, false otherwise
     * @note This method is thread-safe
     */
    bool isRunning() const;

    // Implementation of IScheduler interface

    /**
     * @copydoc IScheduler::scheduleTask
     */
    void scheduleTask(std::string_view taskName, TaskConfig&& config) override;


    /**
     * @copydoc IScheduler::removeTask
     */
    void removeTask(std::string_view taskName) override;

    /**
     * @copydoc IScheduler::getActiveTasksCount
     */
    std::size_t getActiveTasksCount() const override;


    /**
     * @copydoc IScheduler::getThreadCount
     */
    std::size_t getThreadCount() const override;

private:
    /**
     * @brief Main worker thread function
     * @details Implements the main execution loop for worker threads.
     *          Continuously processes tasks from the priority queue until
     *          the scheduler is stopped.
     *
     * @note This method runs in each worker thread
     * @note Handles task timing, execution, and rescheduling
     */
    void workerThread();

    /**
     * @brief Execute a single task, logging any exceptions.
     * @param task The task to execute
     *
     * @note Sets and restores CPU priority around task execution
     */
    void executeTask(const ScheduledTask& task);

    /**
     * @brief Set CPU priority for the current thread
     * @details Changes the nice value (CPU priority) for the calling thread.
     *          Lower values indicate higher priority.
     *
     * @param cpuPriority Nice value to set (-20 to 19)
     *
     * @note Values are clamped to the valid range [-20, 19]
     * @note Logs warnings if priority setting fails
     * @see setpriority(2) and nice(1) for details.
     */
    void setCurrentThreadPriority(int cpuPriority);

    std::atomic<bool> m_running;        ///< Scheduler running state flag
    std::vector<std::thread> m_workers; ///< Worker thread pool

    mutable std::mutex m_tasksMutex;                                         ///< Mutex protecting the tasks map
    std::unordered_map<std::string, std::shared_ptr<ScheduledTask>> m_tasks; ///< Active tasks by name

    mutable std::mutex m_queueMutex; ///< Mutex protecting the task queue
    std::priority_queue<std::shared_ptr<ScheduledTask>, std::vector<std::shared_ptr<ScheduledTask>>, TaskComparator>
        m_taskQueue;                          ///< Priority queue for task execution ordering
    std::condition_variable m_queueCondition; ///< Condition variable for queue notifications

    int m_numThreads; ///< Number of worker threads
};

} // namespace scheduler

#endif // _SCHEDULER_HPP
