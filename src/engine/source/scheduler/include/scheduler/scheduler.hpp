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
        nextRun = [&]() -> std::chrono::steady_clock::time_point
        {
            if (isOneTime)
            {
                return std::chrono::steady_clock::now();
            }
            return std::chrono::steady_clock::now() + std::chrono::seconds(config.interval);
        }();
    }

    void updateNextRun()
    {
        if (!isOneTime && config.interval > 0)
        {
            nextRun = std::chrono::steady_clock::now() + std::chrono::seconds(config.interval);
        }
    }
};

struct TaskComparator
{
    bool operator()(const std::shared_ptr<ScheduledTask>& lhs, const std::shared_ptr<ScheduledTask>& rhs) const
    {
        // Earlier time has higher priority
        return lhs->nextRun > rhs->nextRun;
    }
};

class Scheduler : public IScheduler
{
public:
    Scheduler(int threads = 1);
    ~Scheduler();

    void start();
    void stop();
    bool isRunning() const;

    // Implementation of IScheduler interface
    void scheduleTask(std::string_view taskName, TaskConfig&& config) override;
    void removeTask(std::string_view taskName) override;

    std::size_t getActiveTasksCount() const override;
    std::size_t getThreadCount() const override;

private:
    void workerThread();
    void executeTask(const ScheduledTask& task);
    void setCurrentThreadPriority(int cpuPriority);

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
