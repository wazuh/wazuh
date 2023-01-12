#include <router/router.hpp>

#include <asset.hpp>
#include <registry.hpp>

namespace router
{
std::optional<base::Error> Router::addRoute(const json::Json& jsonDefinition)
{

    try
    {
        std::vector<base::Expression> threadExpressions(m_threads);
        std::shared_ptr<builder::Asset> route {nullptr};
        for (std::size_t i = 0; i < m_threads; ++i)
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
    std::lock_guard lock {m_mutexRoutes};

    std::vector<base::Expression> routerThreads;
    routerThreads.reserve(m_threads);

    for (std::size_t i = 0; i < m_threads; ++i)
    {
        std::vector<base::Expression> routes(m_routes.size());
        std::transform(m_routes.begin(), m_routes.end(), routes.begin(), [i](auto& route) { return route.second[i]; });
        routerThreads[i] = base::Chain::create("router thread " + std::to_string(i), routes);
    }
    return routerThreads;
}

std::vector<std::string> Router::getRouteNames()
{
    std::lock_guard lock {m_mutexRoutes};
    std::vector<std::string> names {};
    names.reserve(m_routes.size());
    std::transform(
        m_routes.begin(), m_routes.end(), std::back_inserter(names), [](auto& route) { return route.first; });
    return names;
}

} // namespace router
