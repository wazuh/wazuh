/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
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
#include "fileDecompressor.hpp"
#include "iHttpPerformer.hpp"
#include "iSigner.hpp"
#include "moduleLog.hpp"
#include "outcomeClassifier.hpp"
#include "stopToken.hpp"
#include "sysSeams.hpp"

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
        /// authGate (optional): a 401 from any send reports here, pausing all
        /// traffic and surfacing re-enrollment once (#37828).
        /// serverEndpoint (#38492/#38491, optional): the configured reverse-proxy
        /// path segment, already normalized (no leading/trailing '/'). When
        /// non-empty, attemptOnce() folds it into HttpRequestSpec::target
        /// (via prefixedTarget()) -- a routing matter only; the bearer token
        /// does not bind the target.
        /// decompressor (#38514, optional): when the final response of a
        /// successful send() carries Content-Encoding: zstd and the request was
        /// file-backed (HttpRequestSpec::responseFilePath set -- only /download
        /// today), send() decompresses that file in place before returning.
        /// nullptr (the default) means this stream never produces a
        /// decompression-eligible response, so send() never even checks the
        /// header for it -- the five non-download streams pass nothing here.
        RetrySender(IHttpPerformer& performer,
                    const ISigner& signer,
                    IClock& clock,
                    Backoff& backoff,
                    bool compressionEnabled,
                    CompressionGate* compressionGate = nullptr,
                    AuthGate* authGate = nullptr,
                    std::string serverEndpoint = {},
                    IFileDecompressor* decompressor = nullptr,
                    std::string spoolDir = {});

        /// spec.headers carry the non-auth headers; the auth pair is appended per
        /// attempt. AuthFail/Permanent/VersionRejected/Interrupted return
        /// immediately; the backoff resets on success. A successful, file-backed
        /// response carrying Content-Encoding: zstd is decompressed in place
        /// before returning (#38514); a malformed/truncated/over-cap frame
        /// downgrades the outcome to Permanent instead of returning Ok, so the
        /// bad file is never handed to the caller.
        Result send(const HttpRequestSpec& spec, Waiter& waiter, uint32_t maxAttempts);

    private:
        Result attemptOnce(const HttpRequestSpec& base);
        std::chrono::milliseconds delayFor(const Result& result);
        static bool isRetryable(OutcomeClass outcome);

        /// Called once, after send()'s retry loop has already settled on a transport outcome and
        /// reset/armed the backoff and auth gate accordingly -- decompression is a content-level
        /// concern, not a transport one, so it never influences either. A no-op unless this
        /// stream has a decompressor (only /download's two fetchers do), the request was
        /// file-backed, and the response actually carried Content-Encoding: zstd. On failure,
        /// downgrades result.outcome to Permanent so the bad file is never handed to the caller.
        void decompressResponseIfNeeded(const HttpRequestSpec& spec, Result& result,
                                        const std::atomic<bool>* abortFlag) const;

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
        IFileDecompressor* m_decompressor;
        std::string m_spoolDir;
        const LogFn m_logFn {HTTPS_CLIENT_LOGTAG};
};

#endif // _HC_RETRY_SENDER_HPP
