#ifndef ROUTER_WORKER_HPP
#define ROUTER_WORKER_HPP

#include <atomic>
#include <memory>
#include <thread>

#include <queue/iqueue.hpp>

#include <router/types.hpp>

#include "environmentBuilder.hpp"
#include "iworker.hpp"
#include "router.hpp"
#include "tester.hpp"

namespace router
{

constexpr auto WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 100000;
constexpr auto WAIT_EPS_TIMEOUT_MSEC = 1;

class Worker : public IWorker
{
private:
    std::shared_ptr<IRouter> m_router; ///< The router instance
    std::shared_ptr<ITester> m_tester; ///< The tester instance
    std::atomic_bool m_isRunning;      ///< Flag to know if the worker is running
    std::thread m_thread;              ///< The thread for the worker

    std::shared_ptr<base::queue::iQueue<base::Event>> m_rQueue;     ///< The router queue
    std::shared_ptr<base::queue::iQueue<test::QueueType>> m_tQueue; ///< The tester queue

public:
    /**
     * @brief Construct a new Worker object
     *
     */
    Worker(std::shared_ptr<EnvironmentBuilder> envBuilder,
           std::shared_ptr<base::queue::iQueue<base::Event>> rQueue,
           std::shared_ptr<base::queue::iQueue<test::QueueType>> tQueue)
        : m_router(std::make_shared<Router>(envBuilder))
        , m_tester(std::make_shared<Tester>(envBuilder))
        , m_isRunning(false)
        , m_thread()
        , m_rQueue(rQueue)
        , m_tQueue(tQueue)
    {
        if (!m_rQueue || !m_tQueue)
        {
            throw std::logic_error("Invalid queues for the worker");
        }
    }

    ~Worker() { stop(); }

    /**
     * @copydoc IWorker::start
     */
    void start(const EpsLimit& epsLimit) override;

    /**
     * @copydoc IWorker::stop
     */
    void stop() override;

    const std::shared_ptr<IRouter>& getRouter() const { return m_router; }
    const std::shared_ptr<ITester>& getTester() const { return m_tester; }
};

} // namespace router

#endif // ROUTER_WORKER_HPP
