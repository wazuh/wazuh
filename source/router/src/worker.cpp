#include "worker.hpp"

#include <base/logging.hpp>

namespace router
{

void Worker::start(const EpsLimit& epsLimit)
{
    if (m_isRunning)
    {
        return;
    }

    m_isRunning = true;
    m_thread = std::thread(
        [this, epsLimit, getLambdaName = logging::getLambdaName(__FUNCTION__, "routerWorkerThread")]()
        {
            std::size_t tID = std::hash<std::thread::id> {}(std::this_thread::get_id());
            const auto functionName = getLambdaName.c_str();
            LOG_DEBUG_L(functionName, "Router Worker {} started", tID);
            while (m_isRunning)
            {
                // Process test queue
                test::QueueType testEvent {};
                if (m_tQueue->tryPop(testEvent) && testEvent != nullptr)
                {
                    auto& [event, opt, callback] = *testEvent;
                    auto output = m_tester->ingestTest(std::move(event), opt);
                    try
                    {
                        callback(std::move(output));
                    }
                    catch (const std::exception& e)
                    {
                        LOG_ERROR_L(functionName, "Error when executing API callback: ", e.what());
                    }
                }

                // Process production queue
                base::Event event {};
                if (!epsLimit() && m_rQueue->waitPop(event, WAIT_DEQUEUE_TIMEOUT_USEC) && event != nullptr)
                {
                    m_router->ingest(std::move(event));
                }
            }
            LOG_DEBUG_L(functionName, "Router Worker {} finished", tID);
        });
}

void Worker::stop()
{
    if (!m_isRunning)
    {
        return;
    }

    m_isRunning = false;
    if (m_thread.joinable())
    {
        m_thread.join();
    }
}
}; // namespace router
