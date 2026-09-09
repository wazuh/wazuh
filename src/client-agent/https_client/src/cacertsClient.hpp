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

#include "httpTypes.hpp"
#include "iHttpPerformer.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "sysSeams.hpp"

#include <string>

/**
 * @brief One GET /cacerts attempt.
 *
 * This is the unverified-fetch leg of the enrollment-token bootstrap design
 * (fetch /cacerts unverified -> SHA-256 the SPKI -> pin-compare against the
 * token -> reconnect verified -> /enroll): fetching and pin-comparing are
 * deliberately separate responsibilities -- this class only performs the GET
 * and hands the raw response back (a separate component owns SHA-256/pin-
 * compare) -- it does not decide whether the body is trusted.
 *
 * As thin as EnrollClient: one request, no retry loop, no shared
 * CompressionGate/AuthGate -- the C caller owns backoff/retry one layer up,
 * exactly like hc_enroll()'s contract.
 *
 * Decided: /cacerts is prefix-INDEPENDENT -- the target is the literal "/cacerts",
 * never joined with ModuleConfig::serverEndpoint via prefixedTarget() the way every
 * other endpoint (/enroll, /stateless, ...) is. Rationale: an agent bootstrapping
 * trust cannot yet know a manager's reverse-proxy prefix. Whether this is the final
 * design is the manager side's call (the token/minting spec), not this client's.
 */
class CacertsClient
{
    public:
        /// @param config Only the transport half is read (host, port, TLS
        ///        material, timeout); the caller is responsible for having
        ///        already forced verifyMode to HC_VERIFY_NONE before
        ///        constructing this -- GET /cacerts is unverified BY
        ///        DEFINITION (there is no trust anchor yet to verify
        ///        against), so this class does not re-derive that decision,
        ///        it trusts the config it was handed (same division of
        ///        responsibility as EnrollClient trusting its config's TLS
        ///        matrix as-is).
        CacertsClient(const ModuleConfig& config, IHttpPerformer& performer, const IFsProbe& fsProbe, LogFn logFn);

        /// @return The raw HTTP response for the caller to interpret
        ///         (validating/pin-comparing the body is a separate
        ///         component's job, not this one's). status is TlsFail and
        ///         httpCode stays 0 when the transport config itself is
        ///         invalid (fail-closed policy) -- nothing was ever sent.
        HttpResponse fetch();

    private:
        ModuleConfig m_config;
        IHttpPerformer& m_performer;
        const IFsProbe& m_fsProbe;
        LogFn m_logFn;
};

#endif // _HC_CACERTS_CLIENT_HPP
