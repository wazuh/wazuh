/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_CACERTS_CLIENT_HPP
#define _HC_CACERTS_CLIENT_HPP

#include <atomic>
#include "httpTypes.hpp"
#include "iHttpPerformer.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "sysSeams.hpp"

#include <string>

/**
 * @brief One GET /cacerts attempt.
 *
 * Serves two callers whose trust posture is opposite, and keeps the difference in the config it
 * is handed rather than deriving it here:
 *
 *  - The enrollment-token bootstrap, UNVERIFIED by definition -- there is no trust anchor yet to
 *    verify against, so the body is pin-compared before anything is trusted.
 *  - The publication refresh (#39321), VERIFIED against the anchor the agent already holds. The
 *    contract requires it: "never with verification disabled, and never via a bootstrap-style
 *    unverified fetch".
 *
 * Either way, fetching and judging the body are deliberately separate responsibilities: this
 * class performs the GET and hands the raw response back, and does not decide whether the body
 * is trusted.
 *
 * As thin as EnrollClient: one request, no retry loop, no shared
 * CompressionGate/AuthGate -- the C caller owns backoff/retry one layer up,
 * exactly like hc_enroll()'s contract.
 *
 * Decided: /cacerts is prefixed via prefixedTarget() like every other endpoint
 * (/enroll, /stateless, ...); the manager registers /cacerts under the global prefix
 * same as every other route, so this must not be treated as prefix-independent.
 */
class CacertsClient
{
    public:
        /// @param config Only the transport half is read (host, port, TLS material, timeout).
        ///        The caller owns the TLS decision and has already put it here -- this class
        ///        does not re-derive it, the same division of responsibility as EnrollClient
        ///        trusting its config's TLS matrix as-is.
        /// @param unverifiedByDesign Whether an absent verification is the point of this call
        ///        rather than a misconfiguration. Only changes how validateTransport() reports
        ///        it: the bootstrap's unverified leg is expected and logged as such, while a
        ///        refresh that somehow arrived here with verification off is the warning it
        ///        should be. Pass false for anything but the bootstrap.
        CacertsClient(const ModuleConfig& config, IHttpPerformer& performer, const IFsProbe& fsProbe, LogFn logFn,
                      bool unverifiedByDesign);

        /// @return The raw HTTP response for the caller to interpret
        ///         (validating/pin-comparing the body is a separate
        ///         component's job, not this one's). status is TlsFail and
        ///         httpCode stays 0 when the transport config itself is
        ///         invalid (fail-closed policy) -- nothing was ever sent.
        /// @param abortFlag Optional cooperative abort, normally a Waiter's stop flag. Without
        ///        one a shutdown waits out the request timeout before the thread can join.
        HttpResponse fetch(const std::atomic<bool>* abortFlag = nullptr);

    private:
        ModuleConfig m_config;
        IHttpPerformer& m_performer;
        const IFsProbe& m_fsProbe;
        LogFn m_logFn;
        bool m_unverifiedByDesign;
};

#endif // _HC_CACERTS_CLIENT_HPP
