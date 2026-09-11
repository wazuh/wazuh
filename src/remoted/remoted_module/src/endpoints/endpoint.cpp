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

    // The process-wide rejection counter set (see installAuthRejectMetrics() in endpoint.hpp for
    // why this is a function-local static rather than threaded state). Default-constructed it is
    // the null object that counts nothing, so a process/test that never installs pays a null
    // check per REJECTION and nothing else.
    remoted::endpoints::AuthRejectMetrics& authRejectMetrics()
    {
        static remoted::endpoints::AuthRejectMetrics instance;
        return instance;
    }

    /// Bumps the one remoted.auth.reject.* counter @p err maps to. Its own switch, NOT
    /// classify(): the log folds by who-must-act (ClientFault spans four causes), the metrics
    /// keep the causes apart -- that separation is the whole point of the family.
    void countRejection(remoted::auth::AuthError err)
    {
        const auto& m = authRejectMetrics();
        const auto& counter = [&m, err]() -> const std::shared_ptr<wazuh::metrics::ICounter>&
        {
            switch (err)
            {
                case remoted::auth::AuthError::UnknownAgent: return m.unknownAgent;
                case remoted::auth::AuthError::InvalidSignature: return m.invalidSignature;
                case remoted::auth::AuthError::InvalidToken: return m.badToken;
                case remoted::auth::AuthError::IdentityMismatch: return m.identityMismatch;
                case remoted::auth::AuthError::StaleToken: return m.clockSkew;
                case remoted::auth::AuthError::MissingKey: return m.unusableKey;
                case remoted::auth::AuthError::AddressNotAllowed: return m.addressNotAllowed;
                case remoted::auth::AuthError::EnrollmentKeyUnavailable: return m.enrollmentKey;
                case remoted::auth::AuthError::PayloadAgentMismatch: return m.payloadMismatch;
                case remoted::auth::AuthError::BodyTooLarge: return m.bodyTooLarge;
                case remoted::auth::AuthError::UnsupportedContentEncoding:
                case remoted::auth::AuthError::MalformedContentEncoding: return m.badEncoding;
                // MissingProtocolVersion, UnsupportedProtocolVersion, MissingAuthorization,
                // MalformedAuthorization -- and, defensively, None (errorResponseFor() is never
                // called with it).
                default: return m.malformed;
            }
        }();
        if (counter)
        {
            counter->add();
        }
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
        ClientFault,              ///< Malformed/unauthenticated request. DEBUG2, unthrottled.
        ClockSkew,                ///< Token outside the accepted window -> jwt_max_age / jwt_clock_skew.
        BodyTooLarge,             ///< Over the authenticated-body cap -> auth_max_body_size.
        UnusableKey,              ///< The agent exists but its client.keys key does not decode.
        AgentMismatch,            ///< An authenticated agent claimed a different agent's id (security signal).
        EnrollmentKeyUnavailable, ///< /enroll's Password mode: etc/authd.pass unavailable, or HKDF
                                  ///< unavailable manager-wide. Deliberately NOT UnusableKey -- there
                                  ///< is no agent and no client.keys entry yet to "re-enroll".
    };

    RejectionKind classify(remoted::auth::AuthError err)
    {
        switch (err)
        {
            case remoted::auth::AuthError::StaleToken: return RejectionKind::ClockSkew;
            case remoted::auth::AuthError::BodyTooLarge: return RejectionKind::BodyTooLarge;
            case remoted::auth::AuthError::MissingKey: return RejectionKind::UnusableKey;
            case remoted::auth::AuthError::EnrollmentKeyUnavailable: return RejectionKind::EnrollmentKeyUnavailable;
            case remoted::auth::AuthError::PayloadAgentMismatch: return RejectionKind::AgentMismatch;
            // Already reported by AuthMiddleware's own throttled WARN, which names the agent id and
            // the peer address (neither reaches this funnel). Kept at DEBUG2 to avoid a second line.
            case remoted::auth::AuthError::AddressNotAllowed: return RejectionKind::ClientFault;
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
        static LogThrottle enrollmentKeyUnavailableThrottle;

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
                               "Rejected %llu request(s) in the last %d s whose token fell outside the accepted "
                               "time window (%s). Check clock synchronization between the agents and the manager; "
                               "the window is set by 'jwt_max_age' and 'jwt_clock_skew' (remoted internal options).",
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
                               "the key column in client.keys did not decode to the 32-byte key the bearer profile "
                               "requires (64 lowercase hex chars). "
                               "Re-enroll the affected agent(s).",
                               static_cast<unsigned long long>(d.total),
                               LogThrottle::kDefaultWindowSeconds);
                }
                break;

            case RejectionKind::EnrollmentKeyUnavailable:
                if (const auto d = enrollmentKeyUnavailableThrottle.record())
                {
                    LOGFN_WARN(logFn(),
                               "Rejected %llu Password-mode /enroll request(s) in the last %d s: the enrollment "
                               "password key is unavailable (etc/authd.pass is missing, unreadable, invalid, or -- "
                               "on a cluster worker -- not yet synced from the master). Password-mode enrollment "
                               "will keep failing until it becomes available; this is NOT an agent credential "
                               "problem, so re-enrolling will not fix it.",
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

    void installAuthRejectMetrics(AuthRejectMetrics metrics)
    {
        authRejectMetrics() = std::move(metrics);
    }

    HttpResponse errorResponseFor(remoted::auth::AuthError err, std::string_view agentContext)
    {
        const auto pe = remoted::auth::publicErrorFor(err);

        // Log AND count the PRE-collapse reason. publicErrorFor() deliberately folds every
        // distinct credential failure into one generic 401 so a client cannot tell which check
        // failed -- but that also destroyed the distinction for the operator, since nothing
        // logged it. This is the single funnel every client-visible auth rejection passes
        // through, so one call here covers all of them.
        logRejection(err, pe.status, agentContext);
        countRejection(err);

        std::string body {R"({"error":")"};
        body += pe.message; // static, quote/backslash-free messages
        body += R"(","code":)";
        body += std::to_string(pe.status);
        body += "}";
        auto response = remoted::http::HttpResponse::json(pe.status, std::move(body));
        if (pe.status == 401)
        {
            // RFC 6750 §3: a 401 to a bearer-protected resource carries the challenge. Uniform for
            // every credential failure (it names the scheme, never the reason) and absent from the
            // non-credential 400/413/415, which are not authentication failures.
            response.headers.emplace_back("WWW-Authenticate", "Bearer");
        }
        return response;
    }

} // namespace remoted::endpoints
