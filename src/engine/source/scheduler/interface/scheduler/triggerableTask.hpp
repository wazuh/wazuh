// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _SCHEDULER_TRIGGERABLE_TASK_HPP
#define _SCHEDULER_TRIGGERABLE_TASK_HPP

#include <cstddef>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>

#include <base/logging.hpp>

#include <scheduler/ischeduler.hpp>

namespace scheduler
{

/**
 * @brief A scheduler task that also runs when asked to.
 *
 * Runs on its interval like any recurring task and, in between, whenever @ref trigger is called.
 * Runs never overlap, and a request is never lost: one that arrives while the work is running
 * makes it run once more right after, and any other is served by a one-time run of its own, put at
 * the front of the queue. Every request is therefore answered by a run that started after it.
 * Without an interval the task runs only when triggered.
 */
class TriggerableTask final
{
public:
    /**
     * @brief Describe the task. Nothing is scheduled until @ref start or @ref trigger.
     *
     * @param scheduler The scheduler that runs it.
     * @param name Task name, unique in the scheduler; requests run as `<name>/request-<n>`.
     * @param interval Seconds between runs; 0 = only when triggered.
     * @param cpuPriority Nice value of the runs.
     * @param work What a run does. Exceptions are logged and do not stop later runs.
     */
    TriggerableTask(std::weak_ptr<IScheduler> scheduler,
                    std::string name,
                    std::size_t interval,
                    int cpuPriority,
                    std::function<void()> work)
        : m_scheduler(std::move(scheduler))
        , m_state(std::make_shared<State>())
        , m_interval(interval)
        , m_cpuPriority(cpuPriority)
    {
        m_state->name = std::move(name);
        m_state->work = std::move(work);
    }

    /**
     * @brief Register the recurring task; its first run is one interval from now. A no-op without
     *        an interval. Call @ref trigger as well for a run right away.
     *
     * @throws std::exception whatever the scheduler throws (e.g. a duplicate name).
     */
    void start()
    {
        if (m_interval == 0)
        {
            return;
        }
        lockScheduler()->scheduleTask(m_state->name, config(m_interval, false));
    }

    /**
     * @brief Run as soon as possible. Never blocks and never throws.
     */
    void trigger() noexcept
    {
        std::string requestName;
        {
            std::lock_guard<std::mutex> lock {m_state->mutex};
            if (m_state->running)
            {
                m_state->rerun = true;
                return;
            }
            if (m_state->queued)
            {
                return; // A request run that has not started yet covers this one.
            }
            m_state->queued = true;
            requestName = m_state->name + "/request-" + std::to_string(++m_state->requests);
        }

        try
        {
            const auto scheduler = lockScheduler();
            scheduler->scheduleTask(requestName, config(0, true));
            try
            {
                scheduler->scheduleTaskFirst(requestName);
            }
            catch (const std::exception&)
            {
                // Already picked up by a worker, or already finished: nothing left to move.
            }
        }
        catch (const std::exception& e)
        {
            {
                std::lock_guard<std::mutex> lock {m_state->mutex};
                m_state->queued = false;
            }
            LOG_WARNING("[Scheduler] Task '{}' could not be queued: {}", m_state->name, e.what());
        }
    }

private:
    struct State
    {
        std::string name;
        std::function<void()> work;
        std::mutex mutex;
        bool running {false};     ///< A run is executing the work.
        bool rerun {false};       ///< A request arrived during that run.
        bool queued {false};      ///< A request run is scheduled and has not started.
        std::size_t requests {0}; ///< Request runs scheduled so far; names them uniquely.
    };

    /// One scheduler execution: the work, then once more for every request that arrived meanwhile.
    /// An execution that finds another one running leaves the work to it.
    static void run(const std::shared_ptr<State>& state)
    {
        {
            std::lock_guard<std::mutex> lock {state->mutex};
            if (state->running)
            {
                state->rerun = true;
                return;
            }
            state->running = true;
            state->queued = false;
            state->rerun = false;
        }

        while (true)
        {
            try
            {
                state->work();
            }
            catch (const std::exception& e)
            {
                LOG_ERROR("[Scheduler] Task '{}' failed: {}", state->name, e.what());
            }
            catch (...)
            {
                // Anything escaping here would leave `running` set, and every later run and request
                // would then do nothing until a restart.
                LOG_ERROR("[Scheduler] Task '{}' failed with an unknown exception", state->name);
            }

            std::lock_guard<std::mutex> lock {state->mutex};
            if (!state->rerun)
            {
                state->running = false;
                return;
            }
            state->rerun = false;
        }
    }

    TaskConfig config(std::size_t interval, bool runImmediately) const
    {
        return TaskConfig {interval, runImmediately, m_cpuPriority, [state = m_state]() { run(state); }};
    }

    std::shared_ptr<IScheduler> lockScheduler() const
    {
        auto scheduler = m_scheduler.lock();
        if (!scheduler)
        {
            throw std::runtime_error("the scheduler is gone");
        }
        return scheduler;
    }

    std::weak_ptr<IScheduler> m_scheduler;
    std::shared_ptr<State> m_state;
    std::size_t m_interval;
    int m_cpuPriority;
};

} // namespace scheduler

#endif // _SCHEDULER_TRIGGERABLE_TASK_HPP
