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
#include "jwt/jwtEnrollTokenSigner.hpp"
#include "jwt/jwtKeyDecoder.hpp"
#include "requestTarget.hpp"

#include <chrono>
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

HttpResponse EnrollClient::enroll(const std::string& bodyJson, const std::string& password,
                                  const std::string& tokenKid, const std::string& tokenKeyHex)
{
    if (!m_config.validateTransport(m_fsProbe, m_logFn))
    {
        HttpResponse response;
        response.status = TransportStatus::TlsFail;
        return response;
    }

    // A signed request either signs with the token-kid credential or with the password --
    // never neither-but-still-retriable: an open-mode 401 has nothing to correct (see the
    // retry condition below).
    const bool hasCredential = !password.empty() || (!tokenKid.empty() && !tokenKeyHex.empty());

    bool allowCompression = m_config.httpsCompressionEnabled;
    HttpResponse response = performOnce(bodyJson, password, tokenKid, tokenKeyHex, allowCompression);

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
            response = performOnce(bodyJson, password, tokenKid, tokenKeyHex, allowCompression);
            continue;
        }

        // One-shot 401 grace-retry (#38440's self-correction, extended here):
        // a 401 in a signed mode (password or token-kid) can be a genuinely
        // dead credential, or a clock-skewed agent whose timestamp the
        // manager rejects as too far from its own -- the response alone
        // cannot tell them apart. Correct for measurable skew (if the
        // response carried the manager's Date) and re-sign with a fresh
        // timestamp; only a second 401 -- now on an already skew-corrected
        // clock -- reaches the caller as a real authentication failure. Open
        // mode sends no signature, so a 401 there cannot be a timestamp
        // issue -- nothing to retry.
        if (response.httpCode == 401 && !authRetried && hasCredential)
        {
            authRetried = true;
            correctClockIfSkewed(response);
            response = performOnce(bodyJson, password, tokenKid, tokenKeyHex, allowCompression);
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

namespace
{
    /// A request that was never sent because the credential it had to carry could not be
    /// produced. httpCode stays 0, so every caller -- the retry loop here, and hc_enroll()'s
    /// `httpCode != 0` contract at the C boundary -- reads it as "nothing reached the manager",
    /// which is exactly what happened.
    HttpResponse credentialFailure()
    {
        HttpResponse response;
        response.status = TransportStatus::OtherError;
        return response;
    }
} // namespace

HttpResponse EnrollClient::performOnce(const std::string& bodyJson, const std::string& password,
                                       const std::string& tokenKid, const std::string& tokenKeyHex,
                                       bool allowCompression)
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

    // Token-kid mode takes priority over password mode: a token-based
    // enrollment must not also sign with a possibly-unrelated configured
    // authd.pass. mTLS presents its credential at the TLS layer
    // (CurlPerformer::applyClientCertificate, already wired through m_config)
    // in every mode; open mode sends nothing else. The `wazuh-enroll+jwt`
    // bearer binds time and a fresh jti, not the body: compressed or not, the
    // wire bytes travel under TLS and the same token accompanies them.
    // A credential that cannot be used aborts the request instead of falling through to send
    // it unsigned. Continuing would silently downgrade an enrollment the operator asked to
    // authenticate into an anonymous one -- and against a manager that does not require a
    // password, that downgrade succeeds rather than failing loudly with a 401.
    if (!tokenKid.empty() && !tokenKeyHex.empty())
    {
        const auto key = jwt_profile::v1::JwtKeyDecoder::decode(tokenKeyHex);

        if (!key)
        {
            LOGFN_ERROR(m_logFn, "https_client: enrollment token key is not valid hex.");
            return credentialFailure();
        }

        const auto token = jwt_profile::v1::enroll::JwtEnrollTokenSigner::signWithKid(
                               *key, std::chrono::system_clock::time_point {std::chrono::seconds {m_clock.wallSeconds()}}, tokenKid);

        if (!token)
        {
            LOGFN_ERROR(m_logFn, "https_client: enrollment token bearer could not be minted.");
            return credentialFailure();
        }

        headers.push_back("Authorization: Bearer " + *token);
    }
    else if (!password.empty())
    {
        const auto signature = EnrollSigner::sign(password, m_clock.wallSeconds());

        if (!signature)
        {
            LOGFN_ERROR(m_logFn, "https_client: enrollment bearer token could not be minted.");
            return credentialFailure();
        }

        headers.push_back(signature->authorization);
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
