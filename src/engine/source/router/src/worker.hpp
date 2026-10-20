// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef ROUTER_WORKER_HPP
#define ROUTER_WORKER_HPP

#include <atomic>
#include <functional>
#include <memory>
#include <thread>

#include <fastmetrics/slidingWindowRate.hpp>
#include <fastqueue/iqueue.hpp>
#include <rawevtindexer/iraweventindexer.hpp>

#include <router/iapi.hpp>
#include <router/types.hpp>

#include "environmentBuilder.hpp"
#include "iworker.hpp"
#include "router.hpp"
#include "tester.hpp"

namespace router
{

class RouterWorker : public IWorker<IRouter>
{
private:
    std::shared_ptr<IRouter> m_router;                               ///< The router instance
    std::atomic_bool m_isRunning;                                    ///< Flag to know if the worker is running
    std::thread m_thread;                                            ///< The thread for the worker
    std::shared_ptr<fastqueue::IQueue<IngestEvent>> m_rQueue;        ///< The router queue
    std::shared_ptr<raweventindexer::IRawEventIndexer> m_rawIndexer; ///< Raw indexer used in worker drain path
    std::shared_ptr<fastmetrics::SlidingWindowRate> m_epsRate;       ///< EPS rate shared across all workers

public:
    /**
     * @brief Construct a new Worker object
     *
     */
    RouterWorker(std::shared_ptr<EnvironmentBuilder> envBuilder,
                 decltype(m_rQueue) rQueue,
                 std::shared_ptr<raweventindexer::IRawEventIndexer> rawIndexer,
                 const std::shared_ptr<fastmetrics::SlidingWindowRate>& epsRate)
        : m_router(std::make_shared<Router>(envBuilder))
        , m_isRunning(false)
        , m_rQueue(rQueue)
        , m_rawIndexer(rawIndexer)
        , m_epsRate(epsRate)
    {
        if (!m_rQueue)
        {
            throw std::logic_error("Invalid queue for the router worker");
        }
    }

    ~RouterWorker() { stop(); }

    /**
     * @copydoc IWorker::start
     */
    void start() override;

    /**
     * @copydoc IWorker::stop
     */
    void stop() override;

    /**
     * @brief Get the router associated with the worker.
     * @return A constant reference to the shared pointer of the tester.
     */
    std::shared_ptr<IRouter> get() const override { return m_router; }
};

} // namespace router

#endif // ROUTER_WORKER_HPP
