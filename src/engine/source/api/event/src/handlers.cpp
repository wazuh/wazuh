#include <api/event/handlers.hpp>
#include <base/logging.hpp>

// TODO add metrics
// TODO add fallback file for events that could not be parsed ??

namespace api::event::handlers
{
adapter::RouteHandler pushEvent(const std::shared_ptr<::router::IRouterAPI>& orchestrator,
                                ProtolHandler protocolHandler,
                                const std::shared_ptr<::archiver::IArchiver>& archiver)
{
    return [lambdaName = logging::getLambdaName(__FUNCTION__, "apiHandler"),
            weakOrchestrator = std::weak_ptr(orchestrator),
            archiver,
            protocolHandler](const auto& req, auto& res)
    {
        LOG_TRACE_L(lambdaName.c_str(), fmt::format("Recieved request {}", req.body));

        auto orchestrator = weakOrchestrator.lock();
        if (!orchestrator)
        {
            LOG_ERROR_L(lambdaName.c_str(), "Recieved request but orchestrator is not available");
            res.status = httplib::StatusCode::InternalServerError_500;
            res.set_content("{\"error\": \"Internal server error\", \"code\": 500}", "application/json");
            return;
        }

        archiver->archive(std::string(req.body));

        std::queue<base::Event> events;
        try
        {
            events = protocolHandler(std::string(req.body));
        }
        catch (const std::exception& e)
        {
            LOG_ERROR_L(lambdaName.c_str(), "Failed to parse request: '{}'", e.what());
            res.status = httplib::StatusCode::BadRequest_400;
            res.set_content(fmt::format("{{\"error\": \"{}\", \"code\": 400}}", e.what()), "application/json");
            return;
        }

        while (!events.empty())
        {
            LOG_TRACE_L(lambdaName.c_str(), "Posting event to orchestrator: {}", events.front()->str());
            orchestrator->postEvent(std::move(events.front()));
            events.pop();
        }

        res.status = httplib::StatusCode::OK_200;
    };
}
} // namespace api::event::handlers
