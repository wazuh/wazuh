/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_RETRY_SENDER_HPP
#define _HC_RETRY_SENDER_HPP

#include "authGate.hpp"
#include "backoff.hpp"
#include "compressionGate.hpp"
#include "iHttpPerformer.hpp"
#include "iSigner.hpp"
#include "moduleLog.hpp"
#include "outcomeClassifier.hpp"
#include "stopToken.hpp"
#include "sysSeams.hpp"

#include <chrono>
#include <cstdint>

/**
 * @brief Whole-request retry loop (D9).
 *
 * Every attempt mints a fresh bearer token (new jti, iat = now; the manager
 * bounds a token's accepted age), only Retryable/BackPressure outcomes are
 * retried, back-pressure
 * defers by the larger of the server's Retry-After and the jittered backoff
 * window, and a stop request interrupts both the wait and the in-flight
 * transfer (the waiter's stop flag is wired as the abort flag).
 */
class RetrySender final
{
    public:
        struct Result
        {
            OutcomeClass outcome {OutcomeClass::Interrupted};
            HttpResponse response;
        };

        /// compressionEnabled: zstd-compress in-memory bodies (Content-Encoding:
        /// zstd). Authentication does not look at the body. File-backed
        /// bodies (/stateful) are compressed once by the caller, not here --
        /// attemptOnce() swaps in HttpRequestSpec::precompressedBodyFilePath
        /// when the caller set one and the gate currently allows compression.
        /// compressionGate (optional, shared across every RetrySender on this
        /// agent): a 415 reports here and disables compression for all six
        /// send paths for the rest of this run; send() retries once,
        /// uncompressed, on the same 415.
        /// authGate (optional): a 401 naming `unknown_agent` reports here once
        /// the gate's unknown_agent window has run out, pausing all traffic and
        /// surfacing re-enrollment once (#37828). Since #39064 the other seven
        /// classes -- and a 401 carrying no readable class -- are logged and
        /// returned unescalated instead: only a manager that says the identity
        /// is gone may cost us the identity.
        /// serverEndpoint (#38492/#38491, optional): the configured reverse-proxy
        /// path segment, already normalized (no leading/trailing '/'). When
        /// non-empty, attemptOnce() folds it into HttpRequestSpec::target
        /// (via prefixedTarget()) -- a routing matter only; the bearer token
        /// does not bind the target.
        /// unknownAgentRetryBound: how long the held credential is retried on an `unknown_agent`
        /// 401 before it reaches authGate. The window is the gate's, shared by every sender on
        /// this agent; zero (the default), or no authGate: no retry, the 401 escalates at once.
        RetrySender(IHttpPerformer& performer,
                    const ISigner& signer,
                    IClock& clock,
                    Backoff& backoff,
                    bool compressionEnabled,
                    CompressionGate* compressionGate = nullptr,
                    AuthGate* authGate = nullptr,
                    std::string serverEndpoint = {},
                    std::chrono::milliseconds unknownAgentRetryBound = std::chrono::milliseconds {0});

        /// Drain: the best-effort single send on the stop path, which must never wait.
        enum class Mode : uint8_t { Normal, Drain };

        /// spec.headers carry the non-auth headers; the auth pair is appended per
        /// attempt. AuthFail/Permanent/VersionRejected/Interrupted return
        /// immediately; the backoff resets on success. A Drain send never waits, so it does not
        /// retry an `unknown_agent` 401 either.
        Result send(const HttpRequestSpec& spec, Waiter& waiter, uint32_t maxAttempts, Mode mode = Mode::Normal);

    private:
        Result attemptOnce(const HttpRequestSpec& base);
        std::chrono::milliseconds delayFor(const Result& result);
        static bool isRetryable(OutcomeClass outcome);
        static bool isUnknownAgent(const Result& result);

        /// Retries the held credential until the gate's unknown_agent window closes, waiting on
        /// the calling stream's own waiter so a shutdown interrupts it and no other stream is
        /// held up. Sets escalate only when the window ran out on this call; a transport error
        /// returns early and leaves the window open for the next 401 to rejoin.
        Result retryUnknownAgent(const HttpRequestSpec& base, Waiter& waiter, Result result, bool& escalate);

        /// Waits until the steady clock reaches deadline. A notify() wakes Waiter::waitFor()
        /// early, so the remaining time is waited again, unless by then the gate has latched or
        /// `generation` is no longer the open window; false on a stop request.
        bool waitUntil(Waiter& waiter, std::chrono::steady_clock::time_point deadline, uint64_t generation);

        /// The k-th wait of one retry loop (a rejoin restarts at k = 0): 1, 2, 4, 8 s, then 15 s,
        /// each with equal jitter.
        std::chrono::milliseconds unknownAgentStep(uint32_t k);

        /// Measures skew from the failed attempt's response against this
        /// clock's current wallSeconds() and, if it exceeds a noise floor,
        /// pushes the correction into m_clock before the auth grace-retry
        /// mints its token. A no-op when the response carries no Date (old manager,
        /// or a proxy that stripped it) or when the measured gap is small
        /// enough to be latency/rounding rather than real skew.
        void correctClockIfSkewed(const HttpResponse& response);

        IHttpPerformer& m_performer;
        const ISigner& m_signer;
        IClock& m_clock;
        Backoff& m_backoff;
        bool m_compressionEnabled;
        CompressionGate* m_compressionGate;
        AuthGate* m_authGate;
        std::string m_serverEndpoint;
        std::chrono::milliseconds m_unknownAgentRetryBound;
        const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};
};

#endif // _HC_RETRY_SENDER_HPP
