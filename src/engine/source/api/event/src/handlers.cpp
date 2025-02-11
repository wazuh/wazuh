#include <api/event/handlers.hpp>

// TODO add metrics
// TODO add fallback file for events that could not be parsed ??

namespace api::event::handlers
{
adapter::RouteHandler pushEvent(const std::shared_ptr<::router::IRouterAPI>& orchestrator,
                                ProtolHandler protocolHandler)
{
    return [weakOrchestrator = std::weak_ptr(orchestrator), protocolHandler](const auto& req, auto& res)
    {
        auto orchestrator = weakOrchestrator.lock();
        if (!orchestrator)
        {
            res.status = httplib::StatusCode::InternalServerError_500;
            return;
        }

        std::queue<base::Event> events;
        try
        {
            events = protocolHandler(std::string(req.body));
        }
        catch (const std::exception& e)
        {
            // Silenty ignore invalid events as per the spec
            res.status = httplib::StatusCode::OK_200;
            return;
        }

        while (!events.empty())
        {
            orchestrator->postEvent(std::move(events.front()));
            events.pop();
        }

        res.status = httplib::StatusCode::OK_200;
    };
}
} // namespace api::event::handlers
