#ifndef _SCHEDULER_HPP
#define _SCHEDULER_HPP

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace scheduler
{

struct TaskConfig
{
    std::size_t interval;               // in seconds, 0 means run once
    int CPUPriority;                    // niceValue, lower means more priority (-20 to 19)
    int IO_Priority;                    // IO priority, higher means more priority
    int timeout;                        // in seconds, 0 means no timeout, for future use.
    std::function<void()> taskFunction; // The function to run
};

struct ScheduledTask
{
    std::string name;
    TaskConfig config;
    std::chrono::steady_clock::time_point nextRun;
    bool isOneTime;

    ScheduledTask(std::string&& taskName, TaskConfig&& taskConfig)
        : name(std::move(taskName))
        , config(std::move(taskConfig))
        , isOneTime(config.interval == 0)
    {
        // Schedule one-time tasks to run immediately, recurring tasks with a small delay
        if (isOneTime)
        {
            nextRun = std::chrono::steady_clock::now();
        }
        else
        {
            nextRun = std::chrono::steady_clock::now() + std::chrono::seconds(config.interval);
        }
    }

    void updateNextRun()
    {
        if (!isOneTime && config.interval > 0)
        {
            nextRun = std::chrono::steady_clock::now() + std::chrono::seconds(config.interval);
        }
    }
};

// Custom comparator for priority queue to compare shared_ptr<ScheduledTask>
struct TaskComparator
{
    bool operator()(const std::shared_ptr<ScheduledTask>& lhs, const std::shared_ptr<ScheduledTask>& rhs) const
    {
        // Earlier time has higher priority (min-heap behavior for time)
        return lhs->nextRun > rhs->nextRun;
    }
};

class Scheduler
{
public:
    Scheduler(int threads = 1);
    ~Scheduler();

    // Start and stop the scheduler
    void start();
    void stop();
    bool isRunning() const;

    // Schedule a task to run at a specific interval, 0 means run once
    void scheduleTask(std::string_view taskName, TaskConfig&& config);
    void removeTask(std::string_view taskName);

    // Get statistics
    std::size_t getActiveTasksCount() const;
    std::size_t getThreadCount() const;

private:
    void workerThread();
    void executeTask(const ScheduledTask& task);
    void setCurrentThreadPriority(int cpuPriority, int ioPriority);

    std::atomic<bool> m_running;
    std::vector<std::thread> m_workers;

    mutable std::mutex m_tasksMutex;
    std::unordered_map<std::string, std::shared_ptr<ScheduledTask>> m_tasks;

    mutable std::mutex m_queueMutex;
    std::priority_queue<std::shared_ptr<ScheduledTask>, std::vector<std::shared_ptr<ScheduledTask>>, TaskComparator>
        m_taskQueue;
    std::condition_variable m_queueCondition;

    int m_numThreads;
};

} // namespace scheduler

#endif // _SCHEDULER_HPP
