#include <algorithm>
#include <iostream>
#include <pthread.h>
#include <sched.h>
#include <stdexcept>

#include <sys/resource.h>

#include <base/logging.hpp>
#include <base/process.hpp>
#include <scheduler/scheduler.hpp>

namespace scheduler
{

Scheduler::Scheduler(int threads)
    : m_running(false)
    , m_numThreads(std::max(1, threads))
{
}

Scheduler::~Scheduler()
{
    stop();
}

void Scheduler::start()
{
    if (m_running.load())
    {
        return;
    }
    LOG_DEBUG("Starting scheduler with %d threads...", m_numThreads);

    m_running.store(true);

    // Start worker threads
    m_workers.reserve(m_numThreads);
    for (int i = 0; i < m_numThreads; ++i)
    {
        m_workers.emplace_back(&Scheduler::workerThread, this);
    }

    LOG_INFO("Scheduler started");
}

void Scheduler::stop()
{
    LOG_DEBUG("Stopping scheduler...");
    if (!m_running.load())
    {
        return;
    }

    m_running.store(false);

    // Wake up all waiting threads
    m_queueCondition.notify_all();

    // Join worker threads
    for (auto& worker : m_workers)
    {
        if (worker.joinable())
        {
            worker.join();
        }
    }

    m_workers.clear();

    // Clear remaining tasks
    std::lock_guard<std::mutex> queueLock(m_queueMutex);
    while (!m_taskQueue.empty())
    {
        m_taskQueue.pop();
    }

    LOG_INFO("Scheduler stopped");
}

bool Scheduler::isRunning() const
{
    return m_running.load();
}

void Scheduler::scheduleTask(std::string_view taskName, TaskConfig&& config)
{
    if (!config.taskFunction)
    {
        throw std::invalid_argument("Task function cannot be null");
    }

    // Create task
    std::string name(taskName);
    auto task = std::make_shared<ScheduledTask>(std::move(name), std::move(config));

    // No support for duplicate task names
    {
        std::lock_guard<std::mutex> lock(m_tasksMutex);
        if (m_tasks.find(task->name) != m_tasks.end())
        {
            throw std::runtime_error("Task with name '" + task->name + "' already exists");
        }
        m_tasks[task->name] = task;
    }

    // Add to execution queue
    {
        std::lock_guard<std::mutex> queueLock(m_queueMutex);
        m_taskQueue.push(task);
    }

    m_queueCondition.notify_one();
}

void Scheduler::removeTask(std::string_view taskName)
{
    std::lock_guard<std::mutex> lock(m_tasksMutex);

    std::string name(taskName);
    auto it = m_tasks.find(name);
    if (it != m_tasks.end())
    {
        m_tasks.erase(it);
    }
}

std::size_t Scheduler::getActiveTasksCount() const
{
    std::lock_guard<std::mutex> lock(m_tasksMutex);
    return m_tasks.size();
}

std::size_t Scheduler::getThreadCount() const
{
    return m_numThreads;
}

void Scheduler::workerThread()
{
    while (m_running.load())
    {
        std::shared_ptr<ScheduledTask> task;

        {
            std::unique_lock<std::mutex> lock(m_queueMutex);

            // Wait for a task to be available or for shutdown
            m_queueCondition.wait(lock, [this] { return !m_running.load() || !m_taskQueue.empty(); });

            if (!m_running.load())
            {
                break;
            }

            if (m_taskQueue.empty())
            {
                continue;
            }

            // Get the next task (Highest priority = earliest nextRun)
            task = m_taskQueue.top();

            // Check if it's time to execute
            auto now = std::chrono::steady_clock::now();
            if (task->nextRun > now)
            {
                // Task is not ready yet, wait for it, or wake up on new tasks or shutdown
                auto waitTime = task->nextRun - now;
                if (waitTime > std::chrono::milliseconds(1))
                {
                    m_queueCondition.wait_for(lock, waitTime);
                }
                // Don't remove task from queue, just continue the loop
                continue;
            }
            LOG_DEBUG("Task '%s' is due for execution", task->name);
            m_taskQueue.pop();
        }

        // Check if task still exists (might have been removed)
        {
            std::lock_guard<std::mutex> tasksLock(m_tasksMutex);
            if (m_tasks.find(task->name) == m_tasks.end())
            {
                LOG_DEBUG("Task '%s' was removed before execution", task->name.c_str());
                continue;
            }
        }

        // Execute the task
        executeTask(*task);

        // Reschedule if it's a recurring task, otherwise remove it
        if (!task->isOneTime && task->config.interval > 0)
        {
            LOG_DEBUG("Rescheduling task '%s' to run at %lld",
                      task->name,
                      std::chrono::duration_cast<std::chrono::seconds>(task->nextRun.time_since_epoch()).count());
            task->updateNextRun();
            std::lock_guard<std::mutex> queueLock(m_queueMutex);
            m_taskQueue.push(task);
            m_queueCondition.notify_one();

        }
        else
        {
            std::lock_guard<std::mutex> tasksLock(m_tasksMutex);
            m_tasks.erase(task->name);
        }
    }
}

void Scheduler::executeTask(const ScheduledTask& task)
{
    if (task.config.taskFunction == nullptr)
    {
        return;
    }

    try
    {
        // Set thread priority before executing task
        if (task.config.CPUPriority != 0)
        {
            setCurrentThreadPriority(task.config.CPUPriority);
        }

        task.config.taskFunction();
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("Error executing task '%s': %s", task.name.c_str(), e.what());
    }
    catch (...)
    {
        LOG_WARNING("Unknown error executing task '%s'", task.name.c_str());
    }

    // Restore default priority
    if (task.config.CPUPriority != 0)
    {
        setCurrentThreadPriority(0);
    }
}

void Scheduler::setCurrentThreadPriority(int cpuPriority)
{
    // Just in case, clamp the value to valid nice range
    int niceValue = cpuPriority;
    niceValue = std::max(-20, std::min(19, niceValue));

    if (setpriority(PRIO_PROCESS, 0, niceValue) != 0)
    {
        LOG_WARNING("Failed to set thread CPU priority to %d", niceValue);
    }
    LOG_DEBUG("Set thread CPU priority to %d", niceValue);
}

} // namespace scheduler
