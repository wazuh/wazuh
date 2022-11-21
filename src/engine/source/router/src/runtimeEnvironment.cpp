#include <router/runtimeEnvironment.hpp>

#include "base/parseEvent.hpp"
#include <logging/logging.hpp>
#include <rxbk/rxFactory.hpp>
#include <utils/getExceptionStack.hpp>

// TODO: Refactor how we handle queue flooding and environments down
std::atomic_bool g_envDown {true};

namespace router
{
constexpr auto WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 1000000;

std::optional<base::Error>
RuntimeEnvironment::build(std::shared_ptr<builder::Builder> builder)
{
    if (m_isRunning)
    {
        return base::Error {
            "Engine runtime environment: Environment is already running."};
    }

    if (m_environments.size() > 0)
    {
        return base::Error {"Engine runtime environment: Environment is already built"};
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
        return base::Error {
            "Engine runtime environment: Environment is already running."};
    }

    if (m_environments.empty())
    {
        return base::Error {"Engine runtime environment: Environment is not build."};
    }

    m_isRunning = true;
    g_envDown.store(false);

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
                            WAZUH_LOG_ERROR("Engine runtime environment: An error "
                                            "ocurred while parsing a message: \"{}\"",
                                            e.what());
                        }
                    }
                }

                WAZUH_LOG_DEBUG(
                    "Engine runtime environment: Thread [{}-{}] environment finished.",
                    i,
                    m_asset);
            });
    }

    WAZUH_LOG_DEBUG("Engine runtime environment: Environment \"{}\" started.", m_asset);
    return std::nullopt;
}

void RuntimeEnvironment::stop()
{
    if (!m_isRunning)
    {
        WAZUH_LOG_DEBUG("Engine runtime environment: Environment is not running.");
        return;
    }

    m_isRunning = false;
    g_envDown.store(true);

    for (auto& thread : m_threads)
    {
        thread.join();
    }

    m_threads.clear();

    WAZUH_LOG_DEBUG("Engine runtime environment: Environment \"{}\" stopped.", m_asset);
}

} // namespace router
