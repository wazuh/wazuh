#include "worker.hpp"

#include <logging/logging.hpp>

namespace router
{

void Worker::start()
{
    if (m_isRunning)
    {
        return;
    }

    m_isRunning = true;
    m_thread = std::thread(
        [this]()
        {
            std::size_t tID = std::hash<std::thread::id> {}(std::this_thread::get_id());
            LOG_DEBUG("Router Worker {} started", tID);
            while (m_isRunning)
            {
                // Process test queue
                test::QueueType testEvent {};
                if (m_tQueue->tryPop(testEvent) && testEvent != nullptr)
                {
                    auto& [event, opt, callback] = *testEvent;
                    auto output = m_tester->ingestTest(std::move(event), opt);
                    callback(std::move(output)); // Change to response or error
                }

                // Process production queue
                base::Event event {};
                if (m_rQueue->waitPop(event, WAIT_DEQUEUE_TIMEOUT_USEC) && event != nullptr)
                {
                    m_router->ingest(std::move(event));
                }
            }
            LOG_DEBUG("Router Worker {} finished", tID);
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