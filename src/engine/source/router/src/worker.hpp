#ifndef ROUTER_WORKER_HPP
#define ROUTER_WORKER_HPP

#include <atomic>
#include <functional>
#include <memory>
#include <thread>

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

public:
    /**
     * @brief Construct a new Worker object
     *
     */
    RouterWorker(std::shared_ptr<EnvironmentBuilder> envBuilder,
                 decltype(m_rQueue) rQueue,
                 std::shared_ptr<raweventindexer::IRawEventIndexer> rawIndexer)
        : m_router(std::make_shared<Router>(envBuilder))
        , m_isRunning(false)
        , m_rQueue(rQueue)
        , m_rawIndexer(rawIndexer)
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

class TesterWorker : public IWorker<ITester>
{
private:
    std::shared_ptr<ITester> m_tester;                            ///< The tester instance
    std::atomic_bool m_isRunning;                                 ///< Flag to know if the worker is running
    std::thread m_thread;                                         ///< The thread for the worker
    std::shared_ptr<fastqueue::IQueue<test::EventTest>> m_tQueue; ///< The tester queue

public:
    /**
     * @brief Construct a new Worker object
     *
     */
    TesterWorker(std::shared_ptr<EnvironmentBuilder> envBuilder, decltype(m_tQueue) tQueue)
        : m_tester(std::make_shared<Tester>(envBuilder))
        , m_isRunning(false)
        , m_thread()
        , m_tQueue(tQueue)
    {
        if (!m_tQueue)
        {
            throw std::logic_error("Invalid queue for the tester worker");
        }
    }

    ~TesterWorker() { stop(); }

    /**
     * @copydoc IWorker::start
     */
    void start() override;

    /**
     * @copydoc IWorker::stop
     */
    void stop() override;

    /**
     * @brief Get the tester associated with the worker.
     * @return A constant reference to the shared pointer of the tester.
     */
    std::shared_ptr<ITester> get() const override { return m_tester; }
};

} // namespace router

#endif // ROUTER_WORKER_HPP
