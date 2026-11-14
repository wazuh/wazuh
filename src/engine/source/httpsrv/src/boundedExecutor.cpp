// SPDX-License-Identifier: AGPL-3.0-or-later
#include <httpsrv/boundedExecutor.hpp>

#include <algorithm>
#include <exception>

#include <base/logging.hpp>

namespace httpsrv
{

BoundedExecutor::BoundedExecutor(std::string name, std::size_t threads, std::size_t capacity)
    : m_name {std::move(name)}
    , m_capacity {std::max<std::size_t>(1, capacity)}
{
    const auto count = std::max<std::size_t>(1, threads);
    m_workers.reserve(count);
    for (std::size_t i = 0; i < count; ++i)
    {
        m_workers.emplace_back([this] { workerLoop(); });
    }
}

BoundedExecutor::~BoundedExecutor()
{
    join();
}

void BoundedExecutor::join()
{
    std::size_t stillRunning {0};
    {
        std::lock_guard lock {m_mutex};
        m_admissionOpen = false;
        m_stopping = true;
        stillRunning = m_running;
    }
    m_workAvailable.notify_all();

    if (stillRunning != 0)
    {
        LOG_WARNING(
            "[{}] Waiting for {} request handler(s) that outlived the shutdown deadline.", m_name, stillRunning);
    }
    for (auto& worker : m_workers)
    {
        if (worker.joinable())
        {
            worker.join();
        }
    }

    // Jobs that were never run must still be answered.
    std::deque<Job> leftovers;
    {
        std::lock_guard lock {m_mutex};
        leftovers.swap(m_queue);
    }
    for (auto& job : leftovers)
    {
        if (job.reject)
        {
            job.reject();
        }
    }
}

BoundedExecutor::Submit BoundedExecutor::trySubmit(Job job)
{
    {
        std::lock_guard lock {m_mutex};
        if (!m_admissionOpen)
        {
            return Submit::Closed;
        }
        if (m_queue.size() >= m_capacity)
        {
            return Submit::Full;
        }
        m_queue.push_back(std::move(job));
    }
    m_workAvailable.notify_one();
    return Submit::Accepted;
}

void BoundedExecutor::closeAdmission()
{
    std::lock_guard lock {m_mutex};
    if (m_admissionOpen)
    {
        m_admissionOpen = false;
        m_completedSinceClose = 0;
    }
}

BoundedExecutor::DrainReport BoundedExecutor::drainUntil(std::chrono::steady_clock::time_point deadline)
{
    closeAdmission();

    DrainReport report;
    std::deque<Job> unstarted;
    {
        std::unique_lock lock {m_mutex};
        m_idle.wait_until(lock, deadline, [this] { return m_queue.empty() && m_running == 0; });
        report.completed = m_completedSinceClose;
        report.abandoned = m_running;
        unstarted.swap(m_queue);
    }

    report.rejected = unstarted.size();
    for (auto& job : unstarted)
    {
        if (job.reject)
        {
            job.reject();
        }
    }
    return report;
}

std::size_t BoundedExecutor::depth() const
{
    std::lock_guard lock {m_mutex};
    return m_queue.size();
}

std::size_t BoundedExecutor::running() const
{
    std::lock_guard lock {m_mutex};
    return m_running;
}

void BoundedExecutor::workerLoop()
{
    for (;;)
    {
        Job job;
        {
            std::unique_lock lock {m_mutex};
            m_workAvailable.wait(lock, [this] { return m_stopping || !m_queue.empty(); });
            if (m_queue.empty())
            {
                return; // stopping and nothing left to run
            }
            job = std::move(m_queue.front());
            m_queue.pop_front();
            ++m_running;
        }

        try
        {
            job.run();
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("[{}] A job escaped with an exception: {}", m_name, e.what());
        }
        catch (...)
        {
            LOG_ERROR("[{}] A job escaped with an unknown exception.", m_name);
        }

        {
            std::lock_guard lock {m_mutex};
            --m_running;
            if (!m_admissionOpen)
            {
                ++m_completedSinceClose;
            }
        }
        m_idle.notify_all();
    }
}

} // namespace httpsrv
