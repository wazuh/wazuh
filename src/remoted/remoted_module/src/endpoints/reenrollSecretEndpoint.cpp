/*
 * Wazuh remoted module - POST /enroll/secret endpoint
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "reenrollSecretEndpoint.hpp"

#include "common/logThrottle.hpp"
#include "json.hpp"
#include "loggerHelper.h"

#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace remoted::endpoints::reenrollsecret
{
    namespace
    {
        constexpr auto REENROLL_SECRET_ENDPOINT_LOGTAG {"wazuh-manager-remoted:reenroll-secret-endpoint"};

        const LogFn& logFn()
        {
            static const LogFn instance {REENROLL_SECRET_ENDPOINT_LOGTAG};
            return instance;
        }

        remoted::common::LogThrottle& authdErrorThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& authdUnavailableThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::http::HttpResponse errorJson(int status, std::string_view code)
        {
            std::string body = R"({"error":")";
            body.append(code);
            body.append(R"("})");
            return remoted::http::HttpResponse::json(status, std::move(body));
        }

        /// authd's business codes, by the answer the agent needs. Everything here is retryable
        /// except 9026, which is not an error of this request at all -- see mapAuthdResult().
        remoted::http::HttpResponse errorForAuthdCode(int code)
        {
            switch (code)
            {
                case 9030: // a rotation for that agent is already accepted and not yet persisted
                    return errorJson(409, "reenroll_in_progress");
                case 9031: // authd could not journal the credential it was about to hand out, so it
                           // handed out none. Nothing is wrong with the request.
                    return errorJson(503, "identity_unrecorded");
                case 9015: // a worker was asked to do what only the master can
                case 9016: // the worker -> master forward failed
                    return errorJson(503, "master_unreachable");
                default: return errorJson(500, "authd_error");
            }
        }

        remoted::http::HttpResponse mapAuthdResult(const remoted::enrollment::AuthdResult& result,
                                                   remoted::enrollment::ReenrollSecretMetrics& metrics,
                                                   std::string_view agentId)
        {
            if (result.errorCode == 0)
            {
                // An empty secret on a success is a malformed answer, not a partial one: this verb
                // exists only to produce a secret, so there is no "an older authd sent none" case
                // to tolerate here (unlike /enroll, where the field is genuinely optional). Treated
                // as no clean answer, which is what it is, rather than answering 200 with nothing.
                if (result.reenrollSecret.empty())
                {
                    remoted::enrollment::incSecretAuthdUnavailable(metrics);
                    LOGFN_WARN(logFn(),
                               "authd accepted the secret request for agent '%.*s' but answered without one.",
                               static_cast<int>(agentId.size()),
                               agentId.data());
                    return errorJson(503, "authd_unavailable");
                }

                remoted::enrollment::incSecretIssued(metrics);
                nlohmann::json j;
                // authd's own spelling of the id, not the request's: it is the id the row was
                // written under, and the agent stores the pair verbatim.
                j["id"] = result.id.empty() ? std::string {agentId} : result.id;
                j["reenroll_secret"] = result.reenrollSecret;
                return remoted::http::HttpResponse::json(200, j.dump());
            }

            if (result.errorCode > 0)
            {
                if (result.errorCode == 9030)
                {
                    remoted::enrollment::incSecretRejectedInProgress(metrics);
                }
                else
                {
                    remoted::enrollment::incSecretAuthdError(metrics);
                }

                // 9026 is the one code that is not this route's to dress up: authd folds "no such
                // agent" and "no row in global.db yet" into it, and both mean the identity the
                // bearer proved is not one authd can act on. That is an authentication outcome, so
                // it takes the same 401 -- same envelope, same WWW-Authenticate challenge, same
                // remoted.auth.reject.unknown_agent cell -- the gateway itself would have produced
                // had client.keys lost the agent one moment earlier. The row-not-rebuilt-yet case
                // (wm_database mirrors client.keys asynchronously) lands here too, and the agent
                // simply retries on its next start.
                // 9032 joins it for the same reason, one step further along: the bearer verified
                // against a key that is no longer the agent's, which authd -- the only node whose
                // keystore is authoritative -- is the one to notice. Same 401 envelope, because
                // from the agent's side the answer is the same ("the credential you presented is
                // not current"), and a legitimate agent that has just rotated asks again with the
                // key it now holds. Deliberately NOT a distinct public code: telling a caller
                // apart "wrong agent" from "right agent, superseded key" tells it which half of a
                // stale replica it is talking to, which is a probe this route need not offer.
                if (result.errorCode == 9026 || result.errorCode == 9032)
                {
                    return remoted::endpoints::errorResponseFor(remoted::auth::AuthError::UnknownAgent, agentId);
                }

                if (const auto throttle = authdErrorThrottle().record())
                {
                    LOGFN_DEBUG1(logFn(),
                                 "authd rejected %llu /enroll/secret request(s) in the last %d s "
                                 "(last code=%d: %s).",
                                 throttle.total,
                                 remoted::common::LogThrottle::kDefaultWindowSeconds,
                                 result.errorCode,
                                 result.message.c_str());
                }

                return errorForAuthdCode(result.errorCode);
            }

            // A negative errorCode (kAuthdRequestNotSentErrorCode or kAuthdOutcomeUnknownErrorCode)
            // covers an unreachable authd, a timeout, a malformed reply AND a full AuthdClient
            // queue -- all of them "the bridge got no clean answer", all of them retryable, none of
            // them the agent's fault.
            remoted::enrollment::incSecretAuthdUnavailable(metrics);
            if (const auto throttle = authdUnavailableThrottle().record())
            {
                LOGFN_WARN(logFn(),
                           "%llu /enroll/secret request(s) got no clean answer from authd in the last %d s "
                           "(last: %s). Is authd running and reachable at its local socket?",
                           throttle.total,
                           remoted::common::LogThrottle::kDefaultWindowSeconds,
                           result.message.c_str());
            }
            return errorJson(503, "authd_unavailable");
        }

    } // namespace

    remoted::http::HttpResponse rateLimitedResponse()
    {
        return errorJson(429, "rate_limited");
    }

    remoted::endpoints::AuthenticatedHandler makeHandler(remoted::enrollment::AuthdClient& authdClient,
                                                         remoted::enrollment::ReenrollSecretMetrics& metrics,
                                                         remoted::metrics::EndpointHttpMetrics httpMetrics)
    {
        return [&authdClient, &metrics, httpMetrics = std::move(httpMetrics)](
                   std::shared_ptr<const remoted::auth::AuthenticatedRequest> authReq,
                   std::shared_ptr<remoted::http::IHttpResponder> responder)
        {
            // Wrapped once, at handler entry, so the status accounting covers the answer authd's
            // callback delivers on a pool thread as well as the ones sent from here -- the same
            // reason /enroll wraps (see enrollmentEndpoint.cpp). The 429s never reach this: the
            // gate answers them itself, before authentication.
            responder = std::make_shared<remoted::metrics::MeteredResponder>(std::move(responder), httpMetrics);

            // The body is not read at all: this request has no arguments, and the one thing that
            // could be in it -- an agent id -- must never come from there (RNF-1). `{}` and an
            // empty body are equally acceptable, and anything else is ignored rather than refused,
            // so a future field is not a breaking change for an older manager.
            remoted::enrollment::AuthdSecretRequest request;
            request.id = authReq->agentId;
            // The id says WHO; this says WITH WHICH KEY (#39315). remoted authenticates against its
            // own copy of client.keys, which on a worker is a replica that can lag the master by a
            // sync interval -- so without this, a key the master has already rotated away from
            // still authenticates here, and authd, seeing only an id, would mint a fresh secret for
            // the CURRENT identity and hand it to the holder of the superseded key. authd compares
            // this against its own entry under the same lock that guards the mint.
            request.keyFingerprint = authReq->keyFingerprint;

            authdClient.issueReenrollSecret(
                std::move(request),
                [responder, &metrics, agentId = authReq->agentId](remoted::enrollment::AuthdResult result)
                { responder->send(mapAuthdResult(result, metrics, agentId)); });
        };
    }

} // namespace remoted::endpoints::reenrollsecret
