/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "enrollClient.hpp"

#include "bodyCompressor.hpp"
#include "enrollSigner.hpp"
#include "requestTarget.hpp"

#include <cstdlib>
#include <utility>

namespace
{
    // Mirrors RetrySender::kSkewNoiseFloorSeconds -- kept as a separate
    // constant (not shared via a header) since the two call sites have no
    // other coupling, but the two values must stay equal: below this, a
    // Date-vs-local gap is plausibly latency/rounding, not real skew.
    constexpr std::int64_t kSkewNoiseFloorSeconds = 5;
} // namespace

EnrollClient::EnrollClient(
    const ModuleConfig& config, IHttpPerformer& performer, const IFsProbe& fsProbe, IClock& clock, LogFn logFn)
    : m_config(config)
    , m_performer(performer)
    , m_fsProbe(fsProbe)
    , m_clock(clock)
    , m_logFn(std::move(logFn))
{
}

HttpResponse EnrollClient::enroll(const std::string& bodyJson, const std::string& password)
{
    if (!m_config.validateTransport(m_fsProbe, m_logFn))
    {
        HttpResponse response;
        response.status = TransportStatus::TlsFail;
        return response;
    }

    bool allowCompression = m_config.httpsCompressionEnabled;
    HttpResponse response = performOnce(bodyJson, password, allowCompression);

    bool compressionRetried = false;
    bool authRetried = false;

    // Both one-shot retries below can fire in either order within this same
    // call (a 415's uncompressed retry can itself land a 401, and vice
    // versa), so loop until neither applies rather than checking each only
    // once -- mirrors RetrySender::send()'s identical loop.
    for (;;)
    {
        // One-shot fallback (#38465 D7/Q9): a 415 means the manager does not
        // accept Content-Encoding: zstd on /enroll. No shared CompressionGate
        // here -- this is a single pre-facade call (or a one-off re-enroll
        // call), not a persistent stream with a "for the rest of this run"
        // state to share -- so just retry once, uncompressed, within this
        // same call.
        if (response.httpCode == 415 && !compressionRetried && allowCompression)
        {
            compressionRetried = true;
            allowCompression = false;
            response = performOnce(bodyJson, password, allowCompression);
            continue;
        }

        // One-shot 401 grace-retry (#38440's self-correction, extended here):
        // a 401 in password mode can be a genuinely dead/wrong password, or a
        // clock-skewed agent whose timestamp the manager rejects as too far
        // from its own -- the response alone cannot tell them apart. Correct
        // for measurable skew (if the response carried the manager's Date)
        // and re-sign with a fresh timestamp; only a second 401 -- now on an
        // already skew-corrected clock -- reaches the caller as a real
        // authentication failure. Open mode sends no signature, so a 401
        // there cannot be a timestamp issue -- nothing to retry.
        if (response.httpCode == 401 && !authRetried && !password.empty())
        {
            authRetried = true;
            correctClockIfSkewed(response);
            response = performOnce(bodyJson, password, allowCompression);
            continue;
        }

        break;
    }

    return response;
}

void EnrollClient::correctClockIfSkewed(const HttpResponse& response)
{
    // Date is not itself authenticated (see RetrySender::correctClockIfSkewed
    // for the full trust argument, identical here): trusting it is no
    // different from trusting the 401 status/body it arrived with.
    if (response.serverDateSeconds == 0)
    {
        return; // No Date captured/parsed: nothing to measure skew against.
    }

    const auto delta =
        static_cast<std::int64_t>(response.serverDateSeconds) - static_cast<std::int64_t>(m_clock.wallSeconds());

    if (std::abs(delta) < kSkewNoiseFloorSeconds)
    {
        return; // Aligned enough: leave the clock alone, the 401 is likely a dead password.
    }

    m_clock.correctToServerTime(response.serverDateSeconds);
    LOGFN_INFO(m_logFn,
               "https_client: clock skew of %lld s detected against the manager's response "
               "(Date header) during enrollment; correcting the signing timestamp and retrying.",
               static_cast<long long>(delta));
}

HttpResponse EnrollClient::performOnce(const std::string& bodyJson, const std::string& password, bool allowCompression)
{
    const auto* bodyPtr = reinterpret_cast<const uint8_t*>(bodyJson.data());
    size_t bodyLength = bodyJson.size();
    std::vector<uint8_t> compressedBody;
    std::vector<std::string> headers;

    // Sent unconditionally in all three auth modes (#38465 Q4b/G5, confirmed
    // with the server team) -- unlike JwtSigner's identical header, this one
    // is not tied to whether a signature is computed below.
    headers.push_back("protocol-version: 1");

    if (allowCompression && bodyLength > 0)
    {
        if (auto compressed = compressBody(bodyPtr, bodyLength))
        {
            compressedBody = std::move(*compressed);
            bodyPtr = compressedBody.data();
            bodyLength = compressedBody.size();
            headers.push_back("Content-Encoding: zstd");
        }
    }

    // #38492/#38491: fold the configured endpoint into the target -- a routing
    // matter only (the manager routes on the literal wire request-target); the
    // bearer below does not bind the target, same as RetrySender::attemptOnce.
    const std::string target = prefixedTarget(m_config.serverEndpoint, "/enroll");

    // Password mode only (#38465 design): mTLS presents its credential at
    // the TLS layer (CurlPerformer::applyClientCertificate, already wired
    // through m_config), open mode sends nothing else. The `wazuh-enroll+jwt`
    // bearer binds time and a fresh jti, not the body: compressed or not, the
    // wire bytes travel under TLS and the same token accompanies them.
    if (!password.empty())
    {
        const auto signature = EnrollSigner::sign(password, m_clock.wallSeconds());

        if (signature)
        {
            headers.push_back(signature->authorization);
        }
        else
        {
            LOGFN_ERROR(m_logFn, "https_client: enrollment bearer token could not be minted.");
        }
    }

    HttpRequestSpec spec;
    spec.target = target;
    spec.contentType = "application/json";
    spec.headers = std::move(headers);
    spec.body = bodyPtr;
    spec.bodyLength = bodyLength;
    spec.timeoutMs = m_config.requestTimeoutMs;

    return m_performer.perform(spec);
}
