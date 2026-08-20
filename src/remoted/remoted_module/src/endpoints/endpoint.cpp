/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 27, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "endpoint.hpp"

#include "common/logThrottle.hpp"
#include "loggerHelper.h"

#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

namespace
{

    constexpr auto ENDPOINT_LOGTAG {"wazuh-manager-remoted:endpoints"};

    // One shared instance rather than a per-call temporary: this runs on EVERY rejected request.
    // loggerHelper.h stays out of endpoint.hpp, which the tests include transitively.
    const LogFn& logFn()
    {
        static const LogFn instance {ENDPOINT_LOGTAG};
        return instance;
    }

    /**
     * @brief Whether a rejection is the operator's problem or the client's.
     *
     * The distinction drives the log level, and it matters for more than tidiness: an
     * unauthenticated peer fully controls how many rejections it triggers, so logging every one of
     * them at WARN would be a log-amplification vector against wazuh-manager.log -- and a bad MAC from an
     * internet scanner is noise, not a finding. Those go to DEBUG2 (visible with remoted.debug=2
     * when someone is actually diagnosing a client).
     *
     * The operator-actionable ones are promoted to a throttled WARN because their *cause* is on the
     * manager side even though a client pulls the trigger.
     */
    enum class RejectionKind
    {
        ClientFault,   ///< Malformed/unauthenticated request. DEBUG2, unthrottled.
        ClockSkew,     ///< Timestamp outside the accepted window -> auth_max_request_age/_future_skew.
        BodyTooLarge,  ///< Over the authenticated-body cap -> auth_max_body_size.
        UnusableKey,   ///< The agent exists but its client.keys key does not decode.
        AgentMismatch, ///< An authenticated agent claimed a different agent's id (security signal).
    };

    RejectionKind classify(remoted::auth::AuthError err)
    {
        switch (err)
        {
            case remoted::auth::AuthError::ExpiredRequest:
            case remoted::auth::AuthError::FutureRequest: return RejectionKind::ClockSkew;
            case remoted::auth::AuthError::BodyTooLarge: return RejectionKind::BodyTooLarge;
            case remoted::auth::AuthError::MissingKey: return RejectionKind::UnusableKey;
            case remoted::auth::AuthError::PayloadAgentMismatch: return RejectionKind::AgentMismatch;
            default: return RejectionKind::ClientFault;
        }
    }

    // One throttle per operator-actionable condition. Function-local statics: endpoint.cpp has no
    // object to hang them off, and these are process-wide conditions anyway.
    void logRejection(remoted::auth::AuthError err, int status, std::string_view agentContext)
    {
        using remoted::common::LogThrottle;
        static LogThrottle clockSkewThrottle;
        static LogThrottle bodyTooLargeThrottle;
        static LogThrottle unusableKeyThrottle;
        static LogThrottle agentMismatchThrottle;

        // NOTE: every argument below must stay allocation-free (literals and integers only). This
        // function runs on every rejected request, and LOGFN_DEBUG2's guard does NOT currently
        // suppress argument evaluation (Log::GLOBAL_LOG_LEVEL is 0 and setLogLevel() is never
        // called), so anything built here is paid for even when the line is dropped downstream.
        switch (classify(err))
        {
            case RejectionKind::ClockSkew:
                if (const auto d = clockSkewThrottle.record())
                {
                    LOGFN_WARN(logFn(),
                               "Rejected %llu request(s) in the last %d s whose timestamp fell outside the accepted "
                               "window (%s). Check clock synchronization between the agents and the manager; the "
                               "window is set by 'auth_max_request_age' and 'auth_max_future_skew'.",
                               static_cast<unsigned long long>(d.total),
                               LogThrottle::kDefaultWindowSeconds,
                               remoted::auth::toString(err));
                }
                break;

            case RejectionKind::BodyTooLarge:
                if (const auto d = bodyTooLargeThrottle.record())
                {
                    LOGFN_WARN(logFn(),
                               "Rejected %llu request(s) with 413 in the last %d s: the body exceeded the "
                               "authenticated-body cap. Consider increasing the value of 'auth_max_body_size'.",
                               static_cast<unsigned long long>(d.total),
                               LogThrottle::kDefaultWindowSeconds);
                }
                break;

            case RejectionKind::UnusableKey:
                if (const auto d = unusableKeyThrottle.record())
                {
                    LOGFN_WARN(logFn(),
                               "Rejected %llu request(s) in the last %d s from agent(s) whose key could not be used: "
                               "the key column in client.keys did not decode to a 16, 24 or 32-byte AES key. "
                               "Re-enroll the affected agent(s).",
                               static_cast<unsigned long long>(d.total),
                               LogThrottle::kDefaultWindowSeconds);
                }
                break;

            case RejectionKind::AgentMismatch:
                if (const auto d = agentMismatchThrottle.record())
                {
                    // Security-relevant: the request's MAC verified, so this is a legitimately
                    // authenticated agent submitting a batch attributed to a different agent id.
                    LOGFN_WARN(logFn(),
                               "Rejected %llu authenticated request(s) in the last %d s whose payload claimed a "
                               "different agent id than the one that signed them (authenticated agent '%.*s').",
                               static_cast<unsigned long long>(d.total),
                               LogThrottle::kDefaultWindowSeconds,
                               static_cast<int>(agentContext.size()),
                               agentContext.data());
                }
                break;

            case RejectionKind::ClientFault:
                // Client-driven and unthrottled, hence DEBUG2 rather than WARN. toString() returns a
                // static literal, so this stays allocation-free.
                LOGFN_DEBUG2(logFn(), "Rejected request: %s (HTTP %d).", remoted::auth::toString(err), status);
                break;
        }
    }
} // namespace

namespace remoted::endpoints
{

    HttpResponse errorResponseFor(remoted::auth::AuthError err, std::string_view agentContext)
    {
        const auto pe = remoted::auth::publicErrorFor(err);

        // Log the PRE-collapse reason. publicErrorFor() deliberately folds seven distinct
        // credential failures into one generic 401 so a client cannot tell which check failed --
        // but that also destroyed the distinction for the operator, since nothing logged it. This
        // is the single funnel every client-visible auth rejection passes through, so one call here
        // covers all of them.
        logRejection(err, pe.status, agentContext);

        std::string body {R"({"error":")"};
        body += pe.message; // static, quote/backslash-free messages
        body += R"(","code":)";
        body += std::to_string(pe.status);
        body += "}";
        return remoted::http::HttpResponse::json(pe.status, std::move(body));
    }

} // namespace remoted::endpoints
