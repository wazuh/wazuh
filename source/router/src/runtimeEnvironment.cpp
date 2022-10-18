#include <router/runtimeEnvironment.hpp>

#include "base/parseEvent.hpp"
#include <logging/logging.hpp>
#include <rxbk/rxFactory.hpp>
#include <utils/getExceptionStack.hpp>

namespace router
{
constexpr auto WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 1000000;

std::optional<base::Error>
RuntimeEnvironment::build(std::shared_ptr<builder::Builder> builder)
{
    if (m_isRunning)
    {
        return base::Error {"RuntimeEnvironment is already running"};
    }

    if (m_environments.size() > 0)
    {
        return base::Error {"RuntimeEnvironment is already built"};
    }

    try
    {
        // Build the environment serially, avoid duplicate errors
        for (std::size_t i = 0; i < m_numThreads; ++i)
        {
            m_environments.emplace_back(builder->buildEnvironment(m_asset));
        }
    }
    catch (std::exception& e)
    {
        return base::Error {fmt::format(
            "Error building environment [{}]: {}", m_asset, utils::getExceptionStack(e))};
    }

    return std::nullopt;
}

std::optional<base::Error> RuntimeEnvironment::run(std::shared_ptr<concurrentQueue> queue)
{
    if (m_isRunning)
    {
        return base::Error {"RuntimeEnvironment is already running"};
    }

    if (m_environments.empty())
    {
        return base::Error {"Environment is not builed"};
    }

    m_isRunning = true;

    for (std::size_t i = 0; i < m_numThreads; ++i)
    {
        m_threads.emplace_back(
            [this, i, queue]()
            {
                auto controller = rxbk::buildRxPipeline(m_environments[i]);

                // Thread loop
                while (m_isRunning)
                {
                    std::string event;

                    if (queue->wait_dequeue_timed(event, WAIT_DEQUEUE_TIMEOUT_USEC))
                    {
                        try
                        {
                            auto result = base::result::makeSuccess(
                                base::parseEvent::parseOssecEvent(event));
                            controller.ingestEvent(
                                std::make_shared<base::result::Result<base::Event>>(
                                    std::move(result)));
                        }
                        catch (const std::exception& e)
                        {
                            WAZUH_LOG_ERROR(
                                "An error ocurred while parsing a message: [{}]",
                                e.what());
                        }
                    }
                }

                WAZUH_LOG_DEBUG("Thread [{}-{}] environment finished", i, m_asset);
            });
    }

    WAZUH_LOG_DEBUG("RuntimeEnvironment [{}] started", m_asset);
    return std::nullopt;
}

void RuntimeEnvironment::stop()
{
    if (!m_isRunning)
    {
        WAZUH_LOG_DEBUG("RuntimeEnvironment is not running");
        return;
    }

    m_isRunning = false;

    for (auto& thread : m_threads)
    {
        thread.join();
    }

    m_threads.clear();

    WAZUH_LOG_DEBUG("RuntimeEnvironment [{}] stopped", m_asset);
}

} // namespace router
