#include "worker.hpp"

#include <base/eventParser.hpp>
#include <base/logging.hpp>
#include <base/process.hpp>
#include <base/utils/timeUtils.hpp>
#include <rawevtindexer/iraweventindexer.hpp>

namespace router
{

namespace
{
std::string makeRawIndexPayload(const IngestEvent& queuedEvent, const std::string& timestamp)
{
    json::Json rawDoc(*queuedEvent.first);
    rawDoc.setString(timestamp, "/@timestamp");
    rawDoc.setString(queuedEvent.second, "/event/original");
    return rawDoc.str();
}
} // namespace

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
            const std::size_t tID = std::hash<std::thread::id> {}(std::this_thread::get_id());
            LOG_DEBUG_L(functionName.c_str(), "Router Worker {} started", tID);

            base::process::setThreadName("ORProd-" + std::to_string(tID));

            while (m_isRunning)
            {
                IngestEvent queuedEvent {};
                if (!m_rQueue->waitPop(queuedEvent, fastqueue::WAIT_DEQUEUE_TIMEOUT_USEC))
                {
                    continue;
                }

                // Sentinel used to wake up workers (e.g. test path)
                if (queuedEvent.first == nullptr || queuedEvent.second.empty())
                {
                    continue;
                }

                try
                {
                    const auto timestamp = base::utils::time::getCurrentISO8601();

                    // Raw indexing (now throttled by queue drain)
                    if (m_rawIndexer && m_rawIndexer->isEnabled())
                    {
                        m_rawIndexer->index(makeRawIndexPayload(queuedEvent, timestamp));
                    }

                    // Parse + route to pipeline
                    auto event = base::eventParsers::parseLegacyEvent(queuedEvent.second, *queuedEvent.first);
                    event->setString(timestamp, "/@timestamp");
                    m_router->ingest(std::move(event));
                    // TODO: Log metrics
                }
                catch (const std::exception& e)
                {
                    LOG_ERROR_L(functionName.c_str(), "Failed processing queued event in router worker: {}", e.what());
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
                test::EventTest testEvent {};
                if (m_tQueue->waitPop(testEvent, fastqueue::WAIT_DEQUEUE_TIMEOUT_USEC) && testEvent != nullptr)
                {
                    auto& [event, opt, callback] = *testEvent;
                    auto output = m_tester->ingestTest(std::move(event), opt);
                    try
                    {
                        callback(std::move(output));
                    }
                    catch (const std::exception& e)
                    {
                        LOG_ERROR_L(functionName.c_str(), "Error when executing API callback: {}", e.what());
                    }
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
