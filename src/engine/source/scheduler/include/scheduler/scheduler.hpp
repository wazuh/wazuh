#ifndef _SCHEDULER_HPP
#define _SCHEDULER_HPP

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <scheduler/ischeduler.hpp>

namespace scheduler
{
/**
 * @brief Thread-safe priority queue for scheduled tasks
 * @details Implements a thread-safe priority queue using a sorted list and
 *          condition variables for synchronization.
 *
 * Tasks are ordered by their next execution time, with earlier times having
 * higher priority. The queue supports blocking pop operations and safe
 * shutdown.
 *
 * @note All operations are thread-safe
 */
class TaskQueue
{
public:
    /**
     * @brief Internal task representation for the queue
     */
    struct TaskItem
    {
        std::string name;
        TaskConfig config;
        std::chrono::steady_clock::time_point nextRun;
        bool isOneTime;

        TaskItem(std::string taskName,
                 TaskConfig taskConfig,
                 std::chrono::steady_clock::time_point runTime,
                 bool oneTime)
            : name(std::move(taskName))
            , config(std::move(taskConfig))
            , nextRun(runTime)
            , isOneTime(oneTime)
        {
        }

        // Copy and move constructors for thread safety
        TaskItem(const TaskItem& other)
            : name(other.name)
            , config(other.config)
            , nextRun(other.nextRun)
            , isOneTime(other.isOneTime)
        {
        }

        TaskItem(TaskItem&& other) noexcept
            : name(std::move(other.name))
            , config(std::move(other.config))
            , nextRun(other.nextRun)
            , isOneTime(other.isOneTime)
        {
        }

        TaskItem& operator=(const TaskItem& other)
        {
            if (this != &other)
            {
                name = other.name;
                config = other.config;
                nextRun = other.nextRun;
                isOneTime = other.isOneTime;
            }
            return *this;
        }

        TaskItem& operator=(TaskItem&& other) noexcept
        {
            if (this != &other)
            {
                name = std::move(other.name);
                config = std::move(other.config);
                nextRun = other.nextRun;
                isOneTime = other.isOneTime;
            }
            return *this;
        }
    };

private:
    mutable std::mutex m_mutex;           ///< Protects queue access
    std::list<TaskItem> m_tasks;          ///< Sorted list of tasks
    std::condition_variable m_condition;  ///< Condition variable for signaling
    std::atomic<bool> m_shutdown {false}; ///< Shutdown flag

    /**
     * @brief Helper function to find insertion position (maintains sorted order)
     */
    std::list<TaskItem>::iterator findInsertionPos(const std::chrono::steady_clock::time_point& nextRun)
    {
        return std::lower_bound(m_tasks.begin(),
                                m_tasks.end(),
                                nextRun,
                                [](const TaskItem& item, const std::chrono::steady_clock::time_point& time)
                                { return item.nextRun < time; });
    }

public:
    /**
     * @brief Constructor
     */
    TaskQueue() = default;

    /**
     * @brief Destructor - automatically shuts down
     */
    ~TaskQueue() { shutdown(); }

    /**
     * @brief Add a task to the queue
     */
    void push(const TaskItem& task)
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (!m_shutdown)
            {
                auto pos = findInsertionPos(task.nextRun);
                m_tasks.insert(pos, task);
            }
        }
        m_condition.notify_one();
    }

    /**
     * @brief Get a task from the queue (blocking)
     * @return TaskItem or empty if shutdown
     */
    std::optional<TaskItem> pop()
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_condition.wait(lock, [this] { return !m_tasks.empty() || m_shutdown; });

        if (m_shutdown && m_tasks.empty())
        {
            return std::nullopt;
        }

        if (!m_tasks.empty())
        {
            // DEEP COPY to avoid data races
            TaskItem item = m_tasks.front(); // Copy constructor
            m_tasks.pop_front();
            return item;
        }

        return std::nullopt;
    }

    /**
     * @brief Check if queue is empty
     */
    bool empty() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_tasks.empty();
    }

    /**
     * @brief Get number of tasks in queue
     */
    std::size_t size() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_tasks.size();
    }

    /**
     * @brief Shutdown the queue (releases all waiting threads)
     */
    void shutdown()
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_shutdown = true;
        }
        m_condition.notify_all();
    }

    /**
     * @brief Clear all tasks from queue
     */
    void clear()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_tasks.clear();
    }
};
;

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
     * @brief Copy constructor
     */
    ScheduledTask(const ScheduledTask& other)
        : name(other.name)
        , config(other.config)
        , nextRun(other.nextRun)
        , isOneTime(other.isOneTime)
    {
    }

    /**
     * @brief Copy assignment operator
     */
    ScheduledTask& operator=(const ScheduledTask& other)
    {
        if (this != &other)
        {
            name = other.name;
            config = other.config;
            nextRun = other.nextRun;
            isOneTime = other.isOneTime;
        }
        return *this;
    }

    /**
     * @brief Move constructor
     */
    ScheduledTask(ScheduledTask&& other) noexcept
        : name(std::move(other.name))
        , config(std::move(other.config))
        , nextRun(std::move(other.nextRun))
        , isOneTime(other.isOneTime)
    {
    }

    /**
     * @brief Move assignment operator
     */
    ScheduledTask& operator=(ScheduledTask&& other) noexcept
    {
        if (this != &other)
        {
            name = std::move(other.name);
            config = std::move(other.config);
            nextRun = std::move(other.nextRun);
            isOneTime = other.isOneTime;
        }
        return *this;
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
 * @brief Multi-threaded task scheduler implementation
 * @details Thread-safe queue:
 *          - Uses custom TaskQueue instead of std::priority_queue + mutex
 *          - Employs semaphores for coordination instead of condition_variable
 *          - Separates task management from execution queue
 *
 * The scheduler uses a producer-consumer pattern where:
 * - Main thread(s) add tasks to the thread-safe queue via scheduleTask()
 * - Worker threads consume tasks from the queue for execution
 * - Tasks are automatically rescheduled if they are recurring
 * @note All operations are completely thread-safe without race conditions
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
    ~Scheduler() noexcept;

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
     * @details Implements the main execution loop for worker threads using
     *          the thread-safe queue. Continuously processes tasks until shutdown.
     *
     * @note This method runs in each worker thread
     * @note Uses semaphore-based coordination to avoid condition_variable issues
     */
    void workerThread();

    /**
     * @brief Execute a single task, logging any exceptions.
     * @param task The task to execute
     *
     * @note Sets and restores CPU priority around task execution
     */
    void executeTask(const TaskQueue::TaskItem& task);

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

    TaskQueue m_taskQueue; ///< Thread-safe priority queue for task execution
    int m_numThreads;      ///< Number of worker threads
};

} // namespace scheduler

#endif // _SCHEDULER_HPP
