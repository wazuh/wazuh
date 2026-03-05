#include <api/event/handlers.hpp>
#include <api/event/ndJsonParser.hpp>
#include <base/logging.hpp>

namespace api::event::handlers
{
adapter::RouteHandler pushEvent(const std::shared_ptr<::router::IRouterAPI>& orchestrator,
                                const std::shared_ptr<::archiver::IArchiver>& archiver)
{
    auto lambdaName = logging::getLambdaName(__FUNCTION__, "apiHandler");
    auto weakOrchestrator = std::weak_ptr(orchestrator);

    return [lambdaName = std::move(lambdaName),
            weakOrchestrator = std::move(weakOrchestrator),
            weakArchiver = std::weak_ptr(archiver)](const auto& req, auto& res)
    {
        LOG_TRACE_L(lambdaName.c_str(), fmt::format("Received request {}", req.body));

        auto orchestratorRef = weakOrchestrator.lock();
        if (!orchestratorRef)
        {
            LOG_ERROR_L(lambdaName.c_str(), "Received request but orchestrator is not available");
            res.status = httplib::StatusCode::InternalServerError_500;
            res.set_content("{\"error\": \"Internal server error\", \"code\": 500}", "application/json");
            return;
        }

        // Archive the batch, stripping trailing newline to prevent blank lines between batches.

        if (auto archiverRef = weakArchiver.lock(); archiverRef)
        {
            std::string_view batchToArchive = req.body;
            if (!batchToArchive.empty() && batchToArchive.back() == '\n')
            {
                batchToArchive.remove_suffix(1);
            }
            archiverRef->archive(batchToArchive);
        }

        try
        {
            protocol::EventHook enqueueHook = [orchestratorRef](router::IngestEvent&& ingestEvent)
            {
                orchestratorRef->postEvent(std::move(ingestEvent));
            };

            protocol::parseNDJson(req.body, enqueueHook);
        }
        catch (const std::exception& e)
        {
            LOG_ERROR_L(lambdaName.c_str(), "Failed to parse request: '{}'", e.what());
            res.status = httplib::StatusCode::BadRequest_400;
            res.set_content(fmt::format("{{\"error\": \"{}\", \"code\": 400}}", e.what()), "application/json");
            return;
        }

        res.status = httplib::StatusCode::OK_200;
    };
}
} // namespace api::event::handlers
