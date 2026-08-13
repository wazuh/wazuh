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
#include "cmacSigner.hpp"
#include "compressionGate.hpp"
#include "iHttpPerformer.hpp"
#include "outcomeClassifier.hpp"
#include "stopToken.hpp"
#include "sysSeams.hpp"

#include <cstdint>

/**
 * @brief Whole-request retry loop (D9).
 *
 * Every attempt is signed freshly (the 300 s CMAC window forbids reusing a
 * MAC), only Retryable/BackPressure outcomes are retried, back-pressure
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
        /// zstd) before signing, so the CMAC covers the wire bytes. File-backed
        /// bodies (/stateful) are compressed once by the caller, not here --
        /// attemptOnce() swaps in HttpRequestSpec::precompressedBodyFilePath
        /// when the caller set one and the gate currently allows compression.
        /// compressionGate (optional, shared across every RetrySender on this
        /// agent): a 415 reports here and disables compression for all six
        /// send paths for the rest of this run; send() retries once,
        /// uncompressed, on the same 415.
        /// authGate (optional): a 401 from any send reports here, pausing all
        /// traffic and surfacing re-enrollment once (#37828).
        RetrySender(IHttpPerformer& performer, const ISigner& signer, IClock& clock, Backoff& backoff,
                    bool compressionEnabled, CompressionGate* compressionGate = nullptr,
                    AuthGate* authGate = nullptr);

        /// spec.headers carry the non-auth headers; the auth pair is appended per
        /// attempt. AuthFail/Permanent/VersionRejected/Interrupted return
        /// immediately; the backoff resets on success.
        Result send(const HttpRequestSpec& spec, Waiter& waiter, uint32_t maxAttempts);

    private:
        Result attemptOnce(const HttpRequestSpec& base);
        std::chrono::milliseconds delayFor(const Result& result);
        static bool isRetryable(OutcomeClass outcome);

        IHttpPerformer& m_performer;
        const ISigner& m_signer;
        IClock& m_clock;
        Backoff& m_backoff;
        bool m_compressionEnabled;
        CompressionGate* m_compressionGate;
        AuthGate* m_authGate;
};

#endif // _HC_RETRY_SENDER_HPP
