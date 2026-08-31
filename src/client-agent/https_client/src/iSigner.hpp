/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_I_SIGNER_HPP
#define _HC_I_SIGNER_HPP

#include <ctime>
#include <optional>
#include <string>

/// The two auth headers of one attempt (#38582, the `wazuh-agent+jwt` bearer profile):
///   protocol-version: 1
///   Authorization: Bearer <compact JWS>
struct SignedHeaders
{
    std::string protocolVersion;
    std::string authorization;
};

/// Mints the credential of one attempt. The token binds the agent's identity
/// only -- not the method, target or body -- and lives 60 s from `timestamp`,
/// so callers mint one per attempt; RetrySender enforces that.
class ISigner
{
    public:
        virtual ~ISigner() = default;

        /// @param timestamp The attempt's wall clock (iat). nullopt when the
        ///        credential material is unusable (no key, bad agent id).
        virtual std::optional<SignedHeaders> sign(std::time_t timestamp) const = 0;

        /// The identity the tokens currently name: the configured agent id until
        /// hc_set_agent_identity() swaps it (a re-enroll, #38465, can hand back a
        /// new numeric id with the new key). Payloads that carry the agent id
        /// (the /stateless H line, the /stats and /config stamps) read it from
        /// here, never from the frozen ModuleConfig, so the identity moves as one
        /// with the bearer -- the manager answers 400 (PayloadAgentMismatch) to a
        /// batch whose header names an agent other than the one that signed it.
        virtual std::string agentId() const = 0;
};

#endif // _HC_I_SIGNER_HPP
