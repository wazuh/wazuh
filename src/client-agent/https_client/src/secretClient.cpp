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
