#include "worker.hpp"

#include <base/logging.hpp>
#include <base/process.hpp>

namespace router
{

void RouterWorker::start()
{
    if (m_isRunning)
    {
        return;
    }

    m_isRunning = true;
    m_thread = std::thread(
        [this, functionName = logging::getLambdaName(__FUNCTION__, "routerWorkerThread")]()
        {
            std::size_t tID = std::hash<std::thread::id> {}(std::this_thread::get_id());
            LOG_DEBUG_L(functionName.c_str(), "Router Worker {} started", tID);

            base::process::setThreadName("ORProd-" + std::to_string(tID));

            while (m_isRunning)
            {
                // Process production queue
                if (!m_epsLimit())
                {
                    base::Event event {};
                    if (m_rQueue->waitPop(event, WAIT_DEQUEUE_TIMEOUT_USEC) && event != nullptr)
                    {
                        m_router->ingest(std::move(event));
                    }
                }
                else
                {
                    // If EPS limit is reached, wait for a while before processing the next event
                    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_EPS_TIMEOUT_MSEC));
                }
            }
            LOG_DEBUG_L(functionName.c_str(), "Router Worker {} finished", tID);
        });
}

void RouterWorker::stop()
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

void TesterWorker::start()
{
    if (m_isRunning)
    {
        return;
    }

    m_isRunning = true;
    m_thread = std::thread(
        [this, functionName = logging::getLambdaName(__FUNCTION__, "testerWorkerThread")]()
        {
            std::size_t tID = std::hash<std::thread::id> {}(std::this_thread::get_id());
            LOG_DEBUG_L(functionName.c_str(), "Tester Worker {} started", tID);

            base::process::setThreadName("ORTester-" + std::to_string(tID));

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
                        LOG_ERROR_L(functionName.c_str(), "Error when executing API callback: ", e.what());
                    }
                }
                else
                {
                    // Wait for a while before processing the next event
                    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_EPS_TIMEOUT_MSEC));
                }
            }
            LOG_DEBUG_L(functionName.c_str(), "Tester Worker {} finished", tID);
        });
}

void TesterWorker::stop()
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
