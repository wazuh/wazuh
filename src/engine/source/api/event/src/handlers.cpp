#include <array>

#include <api/event/handlers.hpp>
#include <api/event/ndJsonParser.hpp>
#include <base/eventParser.hpp>
#include <base/json.hpp>
#include <base/logging.hpp>
#include <base/utils/timeUtils.hpp>

namespace api::event::handlers
{
adapter::RouteHandler pushEvent(const std::shared_ptr<::router::IRouterAPI>& orchestrator,
                                const std::shared_ptr<::archiver::IArchiver>& archiver,
                                const std::shared_ptr<::raweventindexer::IRawEventIndexer>& rawIndexer)
{
    auto lambdaName = logging::getLambdaName(__FUNCTION__, "apiHandler");
    auto weakOrchestrator = std::weak_ptr(orchestrator);

    protocol::EventHook rawIndexingHook = [rawIndexer](const json::Json& header, std::string_view rawEvent)
    {
        // Build raw JSON as a merge:
        // {
        //   "@timestamp": "<current time in ISO8601>"
        //   <header fields at root>,
        //   "event": { "original": "<raw event>" }
        // }
        json::Json rawDoc(header);
        rawDoc.setString(base::utils::time::getCurrentISO8601(), "/@timestamp");
        rawDoc.setString(rawEvent, "/event/original");
        rawIndexer->index(rawDoc.str());
    };

    protocol::EventHook orchestratorHook = [weakOrchestrator](const json::Json& header, std::string_view rawEvent)
    {
        auto orchestratorRef = weakOrchestrator.lock();
        if (!orchestratorRef)
        {
            throw std::runtime_error {"orchestrator is not available"};
        }

        base::Event ev = base::eventParsers::parseLegacyEvent(rawEvent, header);
        orchestratorRef->postEvent(std::move(ev));
    };

    return [lambdaName = std::move(lambdaName),
            weakOrchestrator = std::move(weakOrchestrator),
            archiver,
            rawIndexer,
            rawIndexingHook = std::move(rawIndexingHook),
            orchestratorHook = std::move(orchestratorHook)](const auto& req, auto& res)
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

        // Archive the batch, stripping trailing newline to prevent blank lines between batches.
        std::string_view batchToArchive = req.body;
        if (!batchToArchive.empty() && batchToArchive.back() == '\n')
        {
            batchToArchive.remove_suffix(1);
        }
        archiver->archive(batchToArchive);

        // ---- Parse batch and invoke hooks (single pass) ----
        try
        {
            const bool rawEnabled = rawIndexer && rawIndexer->isEnabled();
            protocol::EventHooks hooks = {rawEnabled ? rawIndexingHook : protocol::EventHook {}, orchestratorHook};
            protocol::parseNDJson(req.body, hooks);
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
