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

#ifndef _HC_SECRET_CLIENT_HPP
#define _HC_SECRET_CLIENT_HPP

#include "httpTypes.hpp"
#include "iHttpPerformer.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "sysSeams.hpp"

/**
 * @brief One POST /enroll/secret attempt (issue #39315).
 *
 * The agent already has a client.keys identity and asks the manager for the per-agent
 * re-enrollment secret its enrollment never gave it -- an agent upgraded from 4.x over WPK never
 * calls /enroll, and the 1515 path never produced one. The manager mints the secret for the
 * identity the bearer proves and does NOT rotate the key, so a lost response leaves the agent
 * exactly as it was and the next start simply asks again.
 *
 * As thin as CacertsClient and EnrollClient: one request, no retry loop, no shared
 * CompressionGate/AuthGate -- the C caller owns the (single, per-start) attempt one layer up.
 *
 * **Where it differs from both**: /cacerts is unauthenticated and CacertsClient signs nothing,
 * while /enroll's bearer is the `wazuh-enroll+jwt` ENROLL profile, whose `kid` means "enrollment
 * token or re-enrolling agent". This route is a plain authenticated endpoint, so the credential is
 * the `wazuh-agent+jwt` REQUEST profile -- the same bearer the control stream presents, minted by
 * JwtSigner over the client.keys key. The enroll profile would be rejected by the manager's
 * AuthMiddleware.
 */
class SecretClient
{
    public:
        /// @param config Transport half plus the IDENTITY half (agentId/agentKeyHex): unlike
        ///        EnrollClient and CacertsClient, this call is only meaningful for an agent that
        ///        already has both.
        SecretClient(const ModuleConfig& config, IHttpPerformer& performer, const IFsProbe& fsProbe, IClock& clock,
                     LogFn logFn);

        /// @return The raw HTTP response for the caller to interpret (200 carries
        ///         {"id","reenroll_secret"}). status is TlsFail and httpCode stays 0 when the
        ///         transport config itself is invalid (fail-closed policy), and OtherError with
        ///         httpCode 0 when the bearer could not be minted -- nothing was ever sent in
        ///         either case.
        ///
        ///         At most TWO requests leave here, and only in one case: a 401 whose Date header
        ///         shows measurable clock skew is re-signed once against the corrected time (see
        ///         correctClockIfSkewed). Everything else -- 429, 503, a second 401 -- is returned
        ///         as received, because the retry that answers those is the agent's next start.
        HttpResponse fetch();

    private:
        /// Build the bearer, send one POST /enroll/secret, return whatever came back.
        HttpResponse performOnce();

        /// Apply the manager's Date to m_clock when the gap is outside the shared noise floor.
        /// @return true when a correction was applied and re-signing is therefore worth one more
        ///         request; false when the 401 cannot be explained by the clock.
        bool correctClockIfSkewed(const HttpResponse& response);

        ModuleConfig m_config;
        IHttpPerformer& m_performer;
        const IFsProbe& m_fsProbe;
        IClock& m_clock;
        LogFn m_logFn;
};

#endif // _HC_SECRET_CLIENT_HPP
