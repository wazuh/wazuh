/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "upgradeApi.hpp"

#include "taskManagerLog.hpp"

#include <json.hpp>

#include <utility>

namespace
{
    using namespace wazuh::uds_http;
    using namespace task_manager::upgrade;

    void send(const std::shared_ptr<IHttpResponder>& responder, const std::string& body)
    {
        if (responder)
        {
            responder->send(HttpResponse::json(200, body));
        }
    }
} // namespace

namespace task_manager::upgrade
{
    UpgradeApi::UpgradeApi(UpgradeService& service, std::function<Timestamp()> clock, const bool enabled)
        : m_service {service}
        , m_clock {std::move(clock)}
        , m_enabled {enabled}
    {
    }

    void UpgradeApi::handleUpgrade(std::shared_ptr<const HttpRequest> request,
                                   std::shared_ptr<IHttpResponder> responder)
    {
        handle(request, responder, false);
    }

    void UpgradeApi::handleUpgradeCustom(std::shared_ptr<const HttpRequest> request,
                                         std::shared_ptr<IHttpResponder> responder)
    {
        handle(request, responder, true);
    }

    void UpgradeApi::handle(const std::shared_ptr<const HttpRequest>& request,
                            const std::shared_ptr<IHttpResponder>& responder,
                            const bool custom)
    {
        try
        {
            if (!request)
            {
                send(responder, buildFailureResponse(UpgradeError::ParsingError, {}));
                return;
            }

            // `=`, never braces: `auto b {json::parse(...)}` selects nlohmann's initializer-list
            // constructor and yields the ARRAY [value], which then fails is_object() and would turn
            // every well-formed request into a parse error.
            const auto body = nlohmann::json::parse(request->body, nullptr, false);
            if (body.is_discarded())
            {
                send(responder, buildFailureResponse(UpgradeError::ParsingError, {}));
                return;
            }

            const auto now {m_clock ? m_clock() : 0};

            UpgradeService::ParsedRequest parsed;
            std::vector<int> agentIds;

            if (custom)
            {
                auto result {parseUpgradeCustomRequest(body, now)};
                if (!result.ok())
                {
                    send(responder, buildFailureResponse(result.failure.error, result.failure.message));
                    return;
                }
                agentIds = result.value->agentIds;
                parsed = std::move(*result.value);
            }
            else
            {
                auto result {parseUpgradeRequest(body, now)};
                if (!result.ok())
                {
                    send(responder, buildFailureResponse(result.failure.error, result.failure.message));
                    return;
                }
                agentIds = result.value->agentIds;
                parsed = std::move(*result.value);
            }

            if (!m_enabled)
            {
                // Explicit refusal rather than an unbound socket -- see the header. UnknownError
                // ("Upgrade procedure could not start") maps to 1827, which the Server API surfaces
                // as an internal error, the same class the retired connect failure produced.
                send(responder, buildUniformResponse(UpgradeError::UnknownError, agentIds));
                return;
            }

            if (!m_service.submit(std::move(parsed), responder))
            {
                // Shed. Error 4 per agent, which the Server API answers by halving the chunk and
                // retrying -- the backpressure a 503 would ask for, in a dialect it already speaks.
                LOGFN_WARN(
                    upgradeLogFn(), "Refusing an upgrade request for %zu agents: the queue is full.", agentIds.size());
                send(responder, buildUniformResponse(UpgradeError::TaskManagerCommunication, agentIds));
            }

            // On success the responder now belongs to the service and is answered from its pool.
        }
        catch (const std::exception& exception)
        {
            LOGFN_ERROR(upgradeLogFn(), "Unhandled error admitting an upgrade request: %s", exception.what());
            send(responder, buildFailureResponse(UpgradeError::UnknownError, {}));
        }
        catch (...)
        {
            LOGFN_ERROR(upgradeLogFn(), "Unhandled non-standard error admitting an upgrade request");
            send(responder, buildFailureResponse(UpgradeError::UnknownError, {}));
        }
    }
} // namespace task_manager::upgrade
