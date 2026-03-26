#include <api/event/handlers.hpp>
#include <api/event/ndJsonParser.hpp>
#include <base/logging.hpp>
#include <fastmetrics/registry.hpp>

namespace api::event::handlers
{
adapter::RouteHandler pushEvent(const std::shared_ptr<::router::IRouterAPI>& orchestrator,
                                const std::shared_ptr<::archiver::IArchiver>& archiver)
{
    auto lambdaName = logging::getLambdaName(__FUNCTION__, "apiHandler");
    auto weakOrchestrator = std::weak_ptr(orchestrator);

    // Cache metric pointers (one-time map lookup)
    auto bytesReceivedCounter = fastmetrics::manager().getOrCreateCounter("server.bytes.received");
    auto eventsReceivedCounter = fastmetrics::manager().getOrCreateCounter("server.events.received");

    return [lambdaName = std::move(lambdaName),
            weakOrchestrator = std::move(weakOrchestrator),
            weakArchiver = std::weak_ptr(archiver),
            bytesReceivedCounter,
            eventsReceivedCounter](const auto& req, auto& res)
    {
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

        // Track bytes received (entire HTTP body size)
        bytesReceivedCounter->add(req.body.size());

        try
        {
            protocol::EventHook enqueueHook =
                [orchestratorRef, eventsReceivedCounter](router::IngestEvent&& ingestEvent)
            {
                eventsReceivedCounter->add(1);
                orchestratorRef->postEvent(std::move(ingestEvent));
            };

            protocol::parseNDJson(req.body, enqueueHook);
        }
        catch (const std::exception& e)
        {
            LOG_WARNING_L(lambdaName.c_str(), "Failed to parse request: '{}'", e.what());
            res.status = httplib::StatusCode::BadRequest_400;
            res.set_content(fmt::format("{{\"error\": \"{}\", \"code\": 400}}", e.what()), "application/json");
            return;
        }

        res.status = httplib::StatusCode::OK_200;
    };
}
} // namespace api::event::handlers
