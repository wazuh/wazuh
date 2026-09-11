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

#ifndef _HC_JWT_SIGNER_HPP
#define _HC_JWT_SIGNER_HPP

#include "iSigner.hpp"
#include "keyProvider.hpp"

#include <mutex>
#include <string>

/// The agent's `wazuh-agent+jwt` bearer, minted with the SAME shared signer the
/// manager's tests use (shared_modules/utils/jwt/jwtRequestTokenSigner.hpp):
/// HS256 over exactly {alg,kid,typ} / {exp,iat,iss,jti,nbf,sub}, keyed with the
/// 32 bytes the client.keys secret decodes to. jwt-cpp is header-only, so this
/// adds no shared library to the agent.
class JwtSigner final : public ISigner
{
    public:
        JwtSigner(std::string agentId, const IKeyProvider& keyProvider);

        /// Re-enrollment (#38465) can hand back a different numeric id along
        /// with a new key -- hc_set_agent_identity() calls this so every
        /// subsequently-minted token (from whichever sender thread is active)
        /// carries it. Guarded: sign() may run concurrently from another thread.
        void setAgentId(std::string agentId);

        /// Reads the key from the provider on every call (so a swapped key is
        /// picked up immediately) and mints a fresh token: new jti, iat =
        /// timestamp, exp = iat + 60. nullopt when the key is not the 32-byte
        /// profile key or the agent id is not numeric.
        std::optional<SignedHeaders> sign(std::time_t timestamp) const override;

        /// The live id (see ISigner::agentId); guarded like setAgentId().
        std::string agentId() const override;

    private:
        mutable std::mutex m_agentIdMutex;
        std::string m_agentId;
        const IKeyProvider& m_keyProvider;
};

#endif // _HC_JWT_SIGNER_HPP
