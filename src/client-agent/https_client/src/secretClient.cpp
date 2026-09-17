/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "secretClient.hpp"

#include "clockSkew.hpp"
#include "jwtSigner.hpp"
#include "keyProvider.hpp"
#include "requestTarget.hpp"

#include <utility>

SecretClient::SecretClient(const ModuleConfig& config, IHttpPerformer& performer, const IFsProbe& fsProbe,
                           IClock& clock, LogFn logFn)
    : m_config(config)
    , m_performer(performer)
    , m_fsProbe(fsProbe)
    , m_clock(clock)
    , m_logFn(std::move(logFn))
{
}

HttpResponse SecretClient::fetch()
{
    if (!m_config.validateTransport(m_fsProbe, m_logFn))
    {
        HttpResponse response;
        response.status = TransportStatus::TlsFail;
        return response;
    }

    HttpResponse response = performOnce();

    // One-shot 401 grace-retry, the same one EnrollClient runs and for the same reason (#38440's
    // self-correction): a 401 here is either a key the manager no longer accepts or an agent whose
    // wall clock is outside the manager's time policy, and the response alone cannot tell them
    // apart. This is NOT a general retry -- the bootstrap deliberately makes one attempt per start
    // -- it is the correction that makes that one attempt meaningful. Without it a skewed agent is
    // answered 401 on every start for ever: each start builds a fresh zero-offset clock, so nothing
    // it learns survives, and unlike ordinary traffic (whose long-lived facade clock is corrected
    // by the first 401 it sees) this call would never carry a usable timestamp at all.
    if (response.httpCode == 401 && correctClockIfSkewed(response))
    {
        response = performOnce();
    }

    return response;
}

bool SecretClient::correctClockIfSkewed(const HttpResponse& response)
{
    // Same decision, same noise floor and same single implementation RetrySender and EnrollClient
    // use (clockSkew.hpp): three copies of that constant are three things that have to change
    // together, and the one that is missed is the one nobody notices.
    const auto delta = correctClockFromServerDate(m_clock, response.serverDateSeconds);

    if (delta == 0)
    {
        return false; // No Date, or inside the floor: the 401 is a dead key, not the clock.
    }

    LOGFN_INFO(m_logFn,
               "https_client: clock skew of %lld s detected against the manager's response "
               "(Date header) while requesting the re-enrollment secret; correcting the signing "
               "timestamp and retrying once.",
               static_cast<long long>(delta));
    return true;
}

HttpResponse SecretClient::performOnce()
{
    // The REQUEST profile (`wazuh-agent+jwt`), not the enroll one: this is a plain authenticated
    // endpoint, and the manager's AuthMiddleware would reject a `wazuh-enroll+jwt` here -- a `kid`
    // in that profile means "enrollment token or re-enrolling agent", which is a different claim
    // than "I am agent 001 and here is proof". Built per call rather than shared with the facade's
    // signer: this runs standalone, off the client's own threads, and holds no state worth keeping.
    ConfigKeyProvider keyProvider {m_config.agentKeyHex};
    const JwtSigner signer {m_config.agentId, keyProvider};
    const auto headers = signer.sign(m_clock.wallSeconds());

    if (!headers)
    {
        // The key is not a usable 32-byte profile key, or the agent id is not numeric. Nothing is
        // sent: an unsigned request would simply be answered 401, and reporting "nothing reached
        // the manager" is both truthful and what the caller's retry logic reads.
        LOGFN_ERROR(m_logFn, "https_client: could not mint the bearer for POST /enroll/secret.");
        HttpResponse response;
        response.status = TransportStatus::OtherError;
        return response;
    }

    HttpRequestSpec spec;
    // Prefixed like every other endpoint (#38492): a routing matter only -- the bearer binds the
    // agent's identity, not the target, so a prefix mismatch surfaces as 404, never as 401.
    spec.target = prefixedTarget(m_config.serverEndpoint, "/enroll/secret");
    spec.method = HttpMethod::Post;
    spec.contentType = "application/json";
    spec.headers = {headers->protocolVersion, headers->authorization};
    // An empty JSON object, not an empty body: the request HAS no arguments (the agent id comes
    // from the verified bearer, never from the body), and `{}` is what the manager documents as
    // acceptable. Not compressed -- two bytes have nothing to gain and a Content-Encoding the
    // manager may refuse with 415 has something to lose.
    static constexpr char kEmptyBody[] = "{}";
    spec.body = reinterpret_cast<const uint8_t*>(kEmptyBody);
    spec.bodyLength = sizeof(kEmptyBody) - 1;
    spec.timeoutMs = m_config.requestTimeoutMs;

    return m_performer.perform(spec);
}
