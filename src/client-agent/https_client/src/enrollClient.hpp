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

#ifndef _HC_ENROLL_CLIENT_HPP
#define _HC_ENROLL_CLIENT_HPP

#include "httpTypes.hpp"
#include "iHttpPerformer.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "sysSeams.hpp"

#include <string>

/**
 * @brief One /enroll attempt (#38465).
 *
 * A single POST, no retry loop, no shared CompressionGate/AuthGate: the C
 * side (client-agent/src/start_agent.c's w_agentd_keys_init() for first boot,
 * https_client_bridge.c's bridge_reenroll_thread() for re-enroll) already
 * owns backoff/retry one layer up, so this class just moves bytes for
 * exactly one try -- reusing CurlPerformer (via the injected IHttpPerformer)
 * for the TLS matrix and EnrollSigner for the password-mode bearer,
 * neither of which needs an agent identity that does not exist yet.
 */
class EnrollClient
{
    public:
        EnrollClient(
            const ModuleConfig& config, IHttpPerformer& performer, const IFsProbe& fsProbe, IClock& clock, LogFn logFn);

        /**
         * @param bodyJson The already-built, already-validated JSON body
         *        (enrollment.c's job on the C side; this class treats it as
         *        opaque bytes).
         * @param password Empty means no password-mode signature: the mTLS
         *        client cert (if `config` has one) or nothing at all
         *        authenticates the request instead. Both a cert and a
         *        password may be set together (#38465 Q3, confirmed with the
         *        server team): the cert authenticates the connection, the
         *        password authenticates/signs the request -- no precedence
         *        between them, no "choose a mode" logic.
         * @return The raw HTTP response for the caller (enrollment.c's
         *         w_enrollment_process_response()) to interpret. When the
         *         transport config itself is invalid (fail-closed TLS policy),
         *         status is TlsFail and httpCode stays 0 -- nothing was ever
         *         sent. A 401 in password mode gets one grace-retry: if the
         *         response carried the manager's Date and it disagrees with
         *         `clock` by more than a noise floor, the clock is corrected
         *         and the request is re-signed and resent once (#38440's
         *         self-correction, extended to /enroll) -- only a 401 that
         *         survives that retry reaches the caller.
         */
        HttpResponse enroll(const std::string& bodyJson, const std::string& password);

    private:
        HttpResponse performOnce(const std::string& bodyJson, const std::string& password, bool allowCompression);

        /// Mirrors RetrySender::correctClockIfSkewed(): a no-op unless the
        /// response carried a Date and the gap against `m_clock.wallSeconds()`
        /// exceeds the noise floor, in which case `m_clock` is corrected in
        /// place (a no-op on a plain SystemClock -- callers that want this to
        /// have any effect must inject a SkewCorrectedClock, as hc_enroll()
        /// does).
        void correctClockIfSkewed(const HttpResponse& response);

        ModuleConfig m_config;
        IHttpPerformer& m_performer;
        const IFsProbe& m_fsProbe;
        IClock& m_clock;
        LogFn m_logFn;
};

#endif // _HC_ENROLL_CLIENT_HPP
