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

Scheduler::~Scheduler() noexcept
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

}

void Scheduler::stop()
{
    if (!m_running.load())
    {
        return;
    }

    LOG_DEBUG("Stopping scheduler...");

    m_running.store(false);

    // Shutdown the thread-safe queue to wake up all waiting threads
    m_taskQueue.shutdown();

    // Join worker threads
    for (auto& worker : m_workers)
    {
        if (worker.joinable())
        {
            worker.join();
        }
    }

    m_workers.clear();

    // Clear task queue and task map
    m_taskQueue.clear();
    {
        std::lock_guard<std::mutex> tasksLock(m_tasksMutex);
        m_tasks.clear();
    }
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

    // Add to execution queue using the thread-safe queue
    // Convert ScheduledTask to TaskItem
    TaskQueue::TaskItem taskItem(task->name, task->config, task->nextRun, task->isOneTime);
    m_taskQueue.push(taskItem);
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
    // Set thread name
    base::process::setThreadName("sched-worker");

    while (m_running.load())
    {
        // Try to get a task from the thread-safe queue (with blocking)
        auto taskItem = m_taskQueue.pop();

        // If no task (shutdown signal), exit the loop
        if (!taskItem.has_value())
        {
            break;
        }

        const auto& task = taskItem.value();

        // Check if it's time to execute
        auto now = std::chrono::steady_clock::now();
        if (task.nextRun > now)
        {
            // Task is not ready yet, put it back
            m_taskQueue.push(task);

            // Sleep for a short time to avoid busy waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        // Check if task still exists in task map (might have been removed)
        {
            std::lock_guard<std::mutex> tasksLock(m_tasksMutex);
            if (m_tasks.find(task.name) == m_tasks.end())
            {
                LOG_DEBUG("Task '%s' was removed before execution", task.name.c_str());
                continue;
            }
        }

        LOG_DEBUG("Executing task '%s'", task.name.c_str());

        // Execute the task
        executeTask(task);

        // Reschedule if it's a recurring task, otherwise remove it from task map
        if (!task.isOneTime && task.config.interval > 0)
        {
            LOG_DEBUG("Rescheduling recurring task '%s'", task.name.c_str());

            // Create updated task with new next run time
            auto updatedTask = task; // Copy the task
            // Update next run time manually since TaskItem doesn't have updateNextRun anymore
            updatedTask.nextRun = std::chrono::steady_clock::now() + std::chrono::seconds(task.config.interval);

            // Add back to queue
            m_taskQueue.push(updatedTask);
        }
        else
        {
            // One-time task, remove from task map
            std::lock_guard<std::mutex> tasksLock(m_tasksMutex);
            m_tasks.erase(task.name);
            LOG_DEBUG("Removed one-time task '%s' after execution", task.name.c_str());
        }
    }
}

void Scheduler::executeTask(const TaskQueue::TaskItem& task)
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
