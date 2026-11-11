// SPDX-License-Identifier: AGPL-3.0-or-later
#include <api/event/handlers.hpp>
#include <api/event/identityWarningGate.hpp>

#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>

#include <api/event/ndJsonParser.hpp>
#include <base/json.hpp>
#include <base/logging.hpp>

#include <fastmetrics/registry.hpp>

namespace api::event::handlers
{
namespace
{
/// Minimum time between two WARNING lines about rejected batches.
constexpr auto REJECTED_BATCH_LOG_WINDOW = std::chrono::seconds(60);

/**
 * @brief Logs the first rejected batch, then at most one per window with the count suppressed since the previous
 * line (the same policy as the router's malformed-event WARNING). Shared by the server's I/O threads.
 */
class RejectedBatchLog
{
public:
    /// @return The number of rejections suppressed since the previous logged one when this one must be logged,
    /// std::nullopt when it must be suppressed.
    std::optional<std::uint64_t> record()
    {
        const auto now = std::chrono::steady_clock::now();
        std::lock_guard lock {m_mutex};
        if (m_hasLogged && now - m_lastLog < REJECTED_BATCH_LOG_WINDOW)
        {
            ++m_suppressed;
            return std::nullopt;
        }

        const auto suppressed = m_suppressed;
        m_suppressed = 0;
        m_lastLog = now;
        m_hasLogged = true;
        return suppressed;
    }

private:
    std::mutex m_mutex;
    std::chrono::steady_clock::time_point m_lastLog {};
    bool m_hasLogged {false};
    std::uint64_t m_suppressed {0};
};
} // namespace

adapter::RouteHandler pushEvent(const std::shared_ptr<::router::IRouterAPI>& orchestrator,
                                const std::shared_ptr<::dumper::IDumper>& dumper,
                                std::shared_ptr<agentcache::AgentMetadataCache> agentMetadataCache)
{
    auto lambdaName = logging::getLambdaName(__FUNCTION__, "apiHandler");
    auto weakOrchestrator = std::weak_ptr(orchestrator);

    // Cache metric pointers (one-time map lookup)
    auto bytesReceivedCounter = fastmetrics::manager().getOrCreateCounter(fastmetrics::names::SERVER_BYTES_RECEIVED);
    auto eventsReceivedCounter = fastmetrics::manager().getOrCreateCounter(fastmetrics::names::SERVER_EVENTS_RECEIVED);
    auto rejectedBatchLog = std::make_shared<RejectedBatchLog>();

    auto identityRejectedCounter =
        fastmetrics::manager().getOrCreateCounter(fastmetrics::names::AGENT_CACHE_REJECTED_IDENTITY);
    auto identityWarningGate = std::make_shared<IdentityWarningGate>();

    return [lambdaName = std::move(lambdaName),
            weakOrchestrator = std::move(weakOrchestrator),
            weakDump = std::weak_ptr(dumper),
            agentMetadataCache = std::move(agentMetadataCache),
            bytesReceivedCounter,
            eventsReceivedCounter,
            identityRejectedCounter,
            identityWarningGate,
            rejectedBatchLog](const auto& req, auto& res)
    {
        auto orchestratorRef = weakOrchestrator.lock();
        if (!orchestratorRef)
        {
            LOG_ERROR_L(lambdaName.c_str(), "[API::Event] Received request but orchestrator is not available");
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

        const auto carrierCount = req.get_header_value_count("X-Wazuh-Agent-Id");
        const std::string agentId = carrierCount == 1 ? req.get_header_value("X-Wazuh-Agent-Id")
                                                      : (carrierCount == 0 ? "<missing>" : "<repeated>");
        const auto badRequest = [&res](std::string_view message)
        {
            json::Json body;
            body.setString(message, "/error");
            body.setInt(400, "/code");
            res.status = httplib::StatusCode::BadRequest_400;
            res.set_content(body.str(), "application/json");
        };

        try
        {
            if (carrierCount != 1)
            {
                throw agentcache::IdentityError {
                    fmt::format(protocol::PARSER_ERROR_MSG, "Expected exactly one X-Wazuh-Agent-Id header")};
            }
            if (!agentcache::isCanonicalAgentId(agentId))
            {
                throw agentcache::IdentityError {
                    fmt::format(protocol::PARSER_ERROR_MSG, "X-Wazuh-Agent-Id must be canonical")};
            }
            protocol::EventHook enqueueHook =
                [orchestratorRef, eventsReceivedCounter](router::IngestEvent&& ingestEvent)
            {
                eventsReceivedCounter->add(1);
                orchestratorRef->postEvent(std::move(ingestEvent));
            };

            protocol::parseNDJson(req.body, agentId, enqueueHook, agentMetadataCache);
        }
        catch (const agentcache::IdentityError& e)
        {
            identityRejectedCounter->add(1);
            if (identityWarningGate->allow(std::chrono::steady_clock::now()))
            {
                json::Json context;
                context.setString(std::string_view(agentId).substr(0, 64), "/agent_id");
                LOG_WARNING_L(lambdaName.c_str(), "[API::Event] Identity rejected {}: {}", context.str(), e.what());
            }
            badRequest(e.what());
            return;
        }
        catch (const std::exception& e)
        {
            if (const auto suppressed = rejectedBatchLog->record(); suppressed)
            {
                json::Json context;
                context.setString(std::string_view(agentId).substr(0, 64), "/agent_id");
                if (*suppressed == 0)
                {
                    LOG_WARNING_L(
                        lambdaName.c_str(), "[API::Event] Failed to parse request {}: '{}'", context.str(), e.what());
                }
                else
                {
                    LOG_WARNING_L(lambdaName.c_str(),
                                  "[API::Event] Failed to parse request {}: '{}' ({} more requests rejected since the "
                                  "previous report)",
                                  context.str(),
                                  e.what(),
                                  *suppressed);
                }
            }
            badRequest(e.what());
            return;
        }

        res.status = httplib::StatusCode::OK_200;
    };
}
} // namespace api::event::handlers
