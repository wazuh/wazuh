/*
 * Wazuh remoted module - WPK download authorizer backed by the task manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "taskManagerWpkAuthorizer.hpp"

#include "common/logThrottle.hpp"
#include "downstream/IDownstreamClient.hpp"
#include "downstream/asioUdsHttpClient.hpp"
#include "json.hpp"
#include "loggerHelper.h"

#include <exception>
#include <utility>

namespace remoted::endpoints
{
    namespace
    {
        constexpr auto WPK_AUTHORIZER_LOGTAG {"wazuh-manager-remoted:endpoints"};

        /// The task manager route that answers whether an agent has an open upgrade task for a WPK.
        constexpr auto WPK_AUTHORIZATION_ROUTE {"/v1/tasks/wpk-authorization"};

        const LogFn& logFn()
        {
            static const LogFn instance {LogFn {WPK_AUTHORIZER_LOGTAG}.compose("wpk-authorizer")};
            return instance;
        }

        remoted::common::LogThrottle& connectFailThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& timeoutThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& ioErrorThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& protocolErrorThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& internalErrorThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        void warnProtocolError(const char* what, int status)
        {
            if (const auto throttle = protocolErrorThrottle().record())
            {
                LOGFN_WARN(logFn(),
                           "Task manager gave an unusable WPK authorization answer (%s, HTTP %d): %llu error(s) %s.",
                           what,
                           status,
                           throttle.total,
                           throttle.period().c_str());
            }
        }

        void warnInternalError(const char* what)
        {
            if (const auto throttle = internalErrorThrottle().record())
            {
                LOGFN_WARN(logFn(),
                           "WPK authorization failed internally (%s): %llu error(s) %s.",
                           what,
                           throttle.total,
                           throttle.period().c_str());
            }
        }

        WpkAuthorization classify(remoted::downstream::DownstreamError error,
                                  const remoted::downstream::DownstreamResponse& response,
                                  uint32_t limitMs,
                                  const std::string& socketPath)
        {
            using remoted::downstream::DownstreamError;

            if (error == DownstreamError::ConnectTimeout || error == DownstreamError::WriteTimeout ||
                error == DownstreamError::ResponseTimeout)
            {
                if (const auto throttle = timeoutThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "Task manager WPK authorization timeout (%s, deadline=%u ms): %llu timeout(s) %s.",
                               remoted::downstream::toString(error),
                               limitMs,
                               throttle.total,
                               throttle.period().c_str());
                }
                return WpkAuthorization::Unavailable;
            }

            if (error == DownstreamError::Connect)
            {
                if (const auto throttle = connectFailThrottle().record())
                {
                    LOGFN_ERROR(logFn(),
                                "Failed to reach the task manager socket at %s: %llu failure(s) %s.",
                                socketPath.c_str(),
                                throttle.total,
                                throttle.period().c_str());
                }
                return WpkAuthorization::Unavailable;
            }

            if (error != DownstreamError::None)
            {
                if (const auto throttle = ioErrorThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "Task manager I/O error (%s): %llu error(s) %s.",
                               remoted::downstream::toString(error),
                               throttle.total,
                               throttle.period().c_str());
                }
                return WpkAuthorization::Unavailable;
            }

            // Exactly 200: a `null` under any other status is not a denial.
            if (response.status != 200)
            {
                warnProtocolError("unexpected status", response.status);
                return WpkAuthorization::Unavailable;
            }

            const auto json = nlohmann::json::parse(response.body, nullptr, false);
            if (json.is_discarded() || !json.is_object())
            {
                warnProtocolError("not a JSON object", response.status);
                return WpkAuthorization::Unavailable;
            }

            const auto taskId = json.find("task_id");
            if (taskId == json.end())
            {
                warnProtocolError("no task_id", response.status);
                return WpkAuthorization::Unavailable;
            }
            if (taskId->is_null())
            {
                return WpkAuthorization::Denied;
            }
            if (taskId->is_string() && !taskId->get_ref<const std::string&>().empty())
            {
                return WpkAuthorization::Granted;
            }

            warnProtocolError("task_id is neither null nor a non-empty string", response.status);
            return WpkAuthorization::Unavailable;
        }

        const char* decisionName(WpkAuthorization decision)
        {
            switch (decision)
            {
                case WpkAuthorization::Granted: return "granted";
                case WpkAuthorization::Denied: return "denied";
                case WpkAuthorization::Unavailable: break;
            }
            return "unavailable";
        }
    } // namespace

    TaskManagerWpkAuthorizer::TaskManagerWpkAuthorizer(std::string taskSocketPath,
                                                       uint32_t deadlineMs,
                                                       uint32_t connectTimeoutMs)
        : m_taskSocketPath {std::move(taskSocketPath)}
        , m_deadlineMs {deadlineMs}
        , m_connectTimeoutMs {connectTimeoutMs}
    {
        remoted::downstream::DownstreamConfig clientConfig;
        clientConfig.connectTimeoutMs = static_cast<int>(m_connectTimeoutMs);
        clientConfig.writeTimeoutMs = static_cast<int>(m_deadlineMs);
        clientConfig.responseTimeoutMs = static_cast<int>(m_deadlineMs);
        clientConfig.ioThreads = 1;

        m_client = std::make_unique<remoted::downstream::AsioUdsHttpClient>(clientConfig);
        m_client->start();
    }

    TaskManagerWpkAuthorizer::~TaskManagerWpkAuthorizer()
    {
        stop();
    }

    void TaskManagerWpkAuthorizer::stop() noexcept
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        if (m_stopped)
        {
            return;
        }
        m_stopped = true;
        m_client->stop();
        // Destroying the client frees the sessions still queued on it, and with them the responders
        // their callbacks hold, while the HTTP server they belong to is still alive.
        m_client.reset();
    }

    void TaskManagerWpkAuthorizer::authorize(const std::string& agentId,
                                             const std::string& wpkFile,
                                             std::function<void(WpkAuthorization)> done) const
    {
        // Shared so the synchronous fallback below can still reach `done` if sendAsync() throws
        // after taking its callback.
        auto callback = std::make_shared<std::function<void(WpkAuthorization)>>(std::move(done));
        bool sent {false};

        try
        {
            const nlohmann::json payload {{"agent_id", agentId}, {"wpk_file", wpkFile}};
            const auto body = std::make_shared<const std::string>(payload.dump());

            remoted::downstream::DownstreamRequest request;
            request.socketPath = m_taskSocketPath;
            request.method = remoted::http::Method::Post;
            request.path = WPK_AUTHORIZATION_ROUTE;
            request.contentType = "application/json";
            request.body = *body;
            request.responseTimeoutMs = static_cast<int>(m_deadlineMs);

            // Runs on the client's I/O thread, whose loop ends on any escaping exception.
            auto onComplete = [this, callback, agentId, wpkFile](remoted::downstream::DownstreamError error,
                                                                 remoted::downstream::DownstreamResponse response)
            {
                auto decision {WpkAuthorization::Unavailable};
                try
                {
                    const auto limitMs = error == remoted::downstream::DownstreamError::ConnectTimeout
                                             ? m_connectTimeoutMs
                                             : m_deadlineMs;
                    decision = classify(error, response, limitMs, m_taskSocketPath);
                    LOGFN_DEBUG2(logFn(),
                                 "Task manager %s WPK '%s' for agent '%s'.",
                                 decisionName(decision),
                                 wpkFile.c_str(),
                                 agentId.c_str());
                }
                catch (const std::exception& e)
                {
                    warnInternalError(e.what());
                }
                catch (...)
                {
                    warnInternalError("non-standard exception");
                }

                try
                {
                    (*callback)(decision);
                }
                catch (const std::exception& e)
                {
                    warnInternalError(e.what());
                }
                catch (...)
                {
                    warnInternalError("non-standard exception");
                }
            };

            std::lock_guard<std::mutex> lock {m_mutex};
            if (!m_stopped)
            {
                m_client->sendAsync(std::move(request), body, std::move(onComplete));
                sent = true;
            }
        }
        catch (const std::exception& e)
        {
            warnInternalError(e.what());
        }
        catch (...)
        {
            warnInternalError("non-standard exception");
        }

        if (!sent)
        {
            (*callback)(WpkAuthorization::Unavailable);
        }
    }
} // namespace remoted::endpoints
