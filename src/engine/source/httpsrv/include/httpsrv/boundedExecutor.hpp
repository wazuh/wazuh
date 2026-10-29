// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _HTTPSRV_BOUNDED_EXECUTOR_HPP
#define _HTTPSRV_BOUNDED_EXECUTOR_HPP

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace httpsrv
{

/**
 * @brief A fixed pool of worker threads draining a bounded FIFO of jobs.
 *
 * The server's I/O threads must never block, so every request becomes a job here. The queue is
 * bounded so overload is refused at submission (the caller answers 503) instead of growing without
 * limit. Shutdown is two-step: closeAdmission() refuses new jobs while the queue keeps draining,
 * then drainUntil() waits for the queue to empty up to a deadline; jobs that have not started by
 * then are rejected (their reject() runs) and jobs still running are reported as abandoned.
 *
 * Workers are always joined by the destructor, even when a job outlived the deadline: a job may
 * still be using objects its owner is about to destroy, so detaching it would trade a slow stop
 * for a use-after-free.
 */
class BoundedExecutor
{
public:
    /**
     * @brief A unit of work. `run` executes it; `reject` answers it when it will never run.
     */
    struct Job
    {
        std::function<void()> run;
        std::function<void()> reject;
    };

    enum class Submit
    {
        Accepted, ///< Queued.
        Full,     ///< The queue is at capacity.
        Closed    ///< Admission is closed (shutting down).
    };

    struct DrainReport
    {
        std::size_t completed {0}; ///< Jobs that ran to completion during the drain.
        std::size_t rejected {0};  ///< Jobs that had not started at the deadline.
        std::size_t abandoned {0}; ///< Jobs still running at the deadline.
    };

    /**
     * @param name Name used in log lines.
     * @param threads Number of workers (at least 1).
     * @param capacity Maximum number of queued (not yet running) jobs (at least 1).
     */
    BoundedExecutor(std::string name, std::size_t threads, std::size_t capacity);
    ~BoundedExecutor();

    BoundedExecutor(const BoundedExecutor&) = delete;
    BoundedExecutor& operator=(const BoundedExecutor&) = delete;

    /**
     * @brief Queues a job if there is room and admission is open.
     */
    Submit trySubmit(Job job);

    /**
     * @brief Refuses every later submission; queued jobs keep running.
     */
    void closeAdmission();

    /**
     * @brief Waits until the queue is empty and no job runs, or until @p deadline.
     *
     * At the deadline, queued jobs are removed and their reject() runs on the calling thread.
     * Implies closeAdmission().
     */
    DrainReport drainUntil(std::chrono::steady_clock::time_point deadline);

    std::size_t depth() const;   ///< Queued jobs.
    std::size_t running() const; ///< Jobs being executed.

private:
    void workerLoop();

    std::string m_name;
    std::size_t m_capacity;
    mutable std::mutex m_mutex;
    std::condition_variable m_workAvailable;
    std::condition_variable m_idle;
    std::deque<Job> m_queue;
    std::size_t m_running {0};
    std::size_t m_completedSinceClose {0};
    bool m_admissionOpen {true};
    bool m_stopping {false};
    std::vector<std::thread> m_workers;
};

} // namespace httpsrv

#endif // _HTTPSRV_BOUNDED_EXECUTOR_HPP
