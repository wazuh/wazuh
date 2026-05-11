#include <api/event/handlers.hpp>
#include <api/event/ndJsonParser.hpp>
#include <base/logging.hpp>
#include <fastmetrics/registry.hpp>

namespace api::event::handlers
{
adapter::RouteHandler pushEvent(const std::shared_ptr<::router::IRouterAPI>& orchestrator,
                                const std::shared_ptr<::dumper::IDumper>& dumper)
{
    auto lambdaName = logging::getLambdaName(__FUNCTION__, "apiHandler");
    auto weakOrchestrator = std::weak_ptr(orchestrator);

    // Cache metric pointers (one-time map lookup)
    auto bytesReceivedCounter = fastmetrics::manager().getOrCreateCounter(fastmetrics::names::SERVER_BYTES_RECEIVED);
    auto eventsReceivedCounter = fastmetrics::manager().getOrCreateCounter(fastmetrics::names::SERVER_EVENTS_RECEIVED);

    return [lambdaName = std::move(lambdaName),
            weakOrchestrator = std::move(weakOrchestrator),
            weakDump = std::weak_ptr(dumper),
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

        // Dump the batch, stripping trailing newline to prevent blank lines between batches.

        if (auto dumpRef = weakDump.lock(); dumpRef)
        {
            std::string_view batchToDump = req.body;
            if (!batchToDump.empty() && batchToDump.back() == '\n')
            {
                batchToDump.remove_suffix(1);
            }
            dumpRef->dump(batchToDump);
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
