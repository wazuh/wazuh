#include <router/router.hpp>

#include <asset.hpp>
#include <rxbk/rxFactory.hpp>

namespace router
{
constexpr auto WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 1000000;

std::optional<base::Error> Router::addRoute(const json::Json& jsonDefinition)
{

    try
    {
        std::vector<base::Expression> threadExpressions(m_numThreads);
        std::shared_ptr<builder::Asset> route {nullptr};
        for (std::size_t i = 0; i < m_numThreads; ++i)
        {
            route = std::make_shared<builder::Asset>(jsonDefinition, builder::Asset::Type::ROUTE, m_registry);
            threadExpressions[i] = route->getExpression();
        }
        std::string name = route->m_name;
        {
            std::unique_lock lock {m_mutexRoutes};
            m_routes.insert(std::make_pair(name, std::move(threadExpressions)));
        }
    }
    catch (const std::exception& e)
    {
        return base::Error {e.what()};
    }
    return std::nullopt;
}

std::vector<base::Expression> Router::getExpression()
{
    std::shared_lock lock {m_mutexRoutes};
    if (m_routes.empty())
    {
        return {};
    }

    std::vector<base::Expression> routerThreads;
    routerThreads.reserve(m_numThreads);

    for (std::size_t i = 0; i < m_numThreads; ++i)
    {
        std::vector<base::Expression> routes(m_routes.size());
        std::transform(m_routes.begin(), m_routes.end(), routes.begin(), [i](auto& route) { return route.second[i]; });
        routerThreads[i] = base::Chain::create("router thread " + std::to_string(i), routes);
    }
    return routerThreads;
}

std::vector<std::string> Router::getRouteNames()
{
    std::shared_lock lock {m_mutexRoutes};
    std::vector<std::string> names {};
    names.reserve(m_routes.size());
    std::transform(
        m_routes.begin(), m_routes.end(), std::back_inserter(names), [](auto& route) { return route.first; });
    return names;
}

std::optional<base::Error> Router::run(std::shared_ptr<concurrentQueue> queue)
{
    std::shared_lock lock {m_mutexRoutes};
    if (m_isRunning.load())
    {
        return base::Error {"The router is already running"};
    }
    if (m_routes.empty())
    {
        return base::Error {"No routes to run"};
    }

    std::unordered_set<std::string> assetNames {};
    for (const auto& route : m_routes)
    {
        assetNames.insert(route.first);
    }

    const auto exp = getExpression();
    m_isRunning.store(true);

    for (std::size_t i = 0; i < m_numThreads; ++i)
    {
        m_threads.emplace_back(
            [this, queue, i, expression = exp[i], assetNames]()
            {
                auto controller = rxbk::buildRxPipeline(expression, assetNames);
                while (m_isRunning.load())
                {
                    base::Event event {};
                    if (queue->wait_dequeue_timed(event, WAIT_DEQUEUE_TIMEOUT_USEC))
                    {
                        auto result = base::result::makeSuccess(event);
                        controller.ingestEvent(std::make_shared<base::result::Result<base::Event>>(std::move(result)));
                    }
                }

                WAZUH_LOG_DEBUG("Thread [{}] router finished.", i);
            });
    };

    return std::nullopt;
}

void Router::stop()
{
    // TODO ADD mechanism to wait for all threads to finish
    if (!m_isRunning.load())
    {
        return;
    }
    m_isRunning.store(false);
    for (auto& thread : m_threads)
    {
        thread.join();
    }
    m_threads.clear();

    WAZUH_LOG_DEBUG("Router stopped.");
}

} // namespace router
