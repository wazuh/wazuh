#include <algorithm>
#include <iostream>
#include <pthread.h>
#include <sched.h>
#include <scheduler/scheduler.hpp>
#include <stdexcept>
#include <sys/resource.h>

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
            // Task is ready to execute
            m_taskQueue.pop();
        }

        // Check if task still exists (might have been removed)
        {
            std::lock_guard<std::mutex> tasksLock(m_tasksMutex);
            if (m_tasks.find(task->name) == m_tasks.end())
            {
                continue; // Task was removed
            }
        }

        // Execute the task
        executeTask(*task);

        // Reschedule if it's a recurring task
        if (!task->isOneTime && task->config.interval > 0)
        {
            task->updateNextRun();

            std::lock_guard<std::mutex> queueLock(m_queueMutex);
            m_taskQueue.push(task);
            m_queueCondition.notify_one();
        }
        else
        {
            // Remove one-time task after execution
            std::lock_guard<std::mutex> tasksLock(m_tasksMutex);
            m_tasks.erase(task->name);
        }
    }
}

void Scheduler::executeTask(const ScheduledTask& task)
{
    try
    {
        // Set thread priority before executing task
        if (task.config.CPUPriority != 0 || task.config.IO_Priority != 0)
        {
            setCurrentThreadPriority(task.config.CPUPriority, task.config.IO_Priority);
        }

        // Execute the task function
        if (task.config.taskFunction)
        {
            task.config.taskFunction();
        }
    }
    catch (const std::exception& e)
    {
        // Log error (in a real implementation, you'd use proper logging)
        std::cerr << "Error executing task '" << task.name << "': " << e.what() << std::endl;
    }
    catch (...)
    {
        std::cerr << "Unknown error executing task '" << task.name << "'" << std::endl;
    }

    // Reset thread priority
    if (task.config.CPUPriority != 0 || task.config.IO_Priority != 0)
    {
        setCurrentThreadPriority(0, 0);
    }
}

void Scheduler::setCurrentThreadPriority(int cpuPriority, int ioPriority)
{
    try
    {
        // Set CPU priority (nice value)
        if (cpuPriority != 0)
        {
            // Just in case, clamp the value to valid nice range
            int niceValue = cpuPriority;
            niceValue = std::max(-20, std::min(19, niceValue));

            if (setpriority(PRIO_PROCESS, 0, niceValue) != 0)
            {
                // Handle error if needed - could log here
            }
        }

        // Set I/O priority (ionice)
        // Note: This requires ioprio_set system call which is Linux-specific
        // For now, we'll skip this but it can be implemented if needed
        if (ioPriority != 0)
        {
            // TODO: Implement ioprio_set if I/O priority is critical
        }
    }
    catch (...)
    {
        // Ignore priority setting errors - task should still execute
    }
}

} // namespace scheduler
