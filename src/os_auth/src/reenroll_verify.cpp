/*
 * Wazuh authd - re-enrollment credential verification (C bridge over the shared JWT verifier)
 * Copyright (C) 2015, Wazuh Inc.
 * September 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "reenroll_verify.h"

#include "jwt/enrollKeyDerivation.hpp"
#include "jwt/jwtEnrollProfileV1.hpp"
#include "jwt/jwtEnrollTokenVerifier.hpp"
#include "jwt/jwtKeyDecoder.hpp"
#include "jwt/jwtProfileV1.hpp"
#include "jwt/jwtVerifyError.hpp"

#include <chrono>
#include <string_view>

namespace
{
    // The re-enrollment secret has exactly the agent key's shape (32 bytes as 64 lowercase hex chars,
    // shared/include/agent_validate_op.h), so the client.keys key decoder is the right parser for it:
    // same length, same alphabet, same "nothing else" rule, and it wipes the bytes on the way out.
    static_assert(jwt_profile::v1::kKeyBytes == jwt_profile::v1::enroll::kReenrollSecretBytes,
                  "the re-enrollment secret is decoded with the agent-key decoder: the sizes must match");

    jwt_profile::v1::TimePolicy policyFor(int maxAgeSec, int skewSec) noexcept
    {
        // Fail-safe, not fail-open: a window the profile does not allow falls back to its defaults, it
        // never widens. authd reads these from remoted's own internal options, which remoted validates
        // with the same bounds at startup, so this branch only guards a hand-edited struct.
        const auto policy = jwt_profile::v1::TimePolicy::tryMake(maxAgeSec, skewSec);
        return policy ? *policy : jwt_profile::v1::TimePolicy {};
    }
} // namespace

extern "C" int w_reenroll_verify(
    const char* bearer, const char* agent_id, const char* secret_hex, long now, int jwt_max_age, int jwt_clock_skew)
{
    if (bearer == nullptr || agent_id == nullptr || secret_hex == nullptr)
    {
        return W_REENROLL_INVALID;
    }

    try
    {
        const auto secret = jwt_profile::v1::JwtKeyDecoder::decode(secret_hex);
        if (!secret)
        {
            return W_REENROLL_INVALID;
        }
        const auto key = jwt_profile::v1::enroll::deriveReenrollKey(*secret);
        if (!key)
        {
            return W_REENROLL_INVALID;
        }

        const auto verdict = jwt_profile::v1::enroll::JwtEnrollTokenVerifier::verifyWithKid(
            std::string_view {bearer},
            std::string_view {agent_id},
            *key,
            policyFor(jwt_max_age, jwt_clock_skew),
            std::chrono::system_clock::time_point {std::chrono::seconds {now}});

        switch (verdict)
        {
            case jwt_profile::v1::VerifyError::None: return W_REENROLL_OK;
            case jwt_profile::v1::VerifyError::StaleToken: return W_REENROLL_STALE;
            default: return W_REENROLL_INVALID;
        }
    }
    catch (...)
    {
        return W_REENROLL_INVALID;
    }
}
