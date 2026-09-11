/*
 * Wazuh shared modules - JWT profile library
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/// @file jwtEnrollTokenVerifier.hpp
/// Verifies `wazuh-enroll+jwt` tokens (jwtEnrollProfileV1.hpp). Fail-closed, stateless, no exception
/// leaves any public function. The caller owns TLS/HTTP framing, the "password required" decision,
/// the keys' availability and the uniform 401.
///   verify()        the shared-key form: header exactly {alg, typ}; a `kid` is rejected here.
///   peekKid()       the bounded, pre-signature look at the header (issue #38993): tells whether the
///                   token carries no `kid`, an enrollment-token `kid` or an agent `kid`, so the caller
///                   can resolve the right key. Nothing peeked is trusted until verifyWithKid() passes.
///   verifyWithKid() the `kid` forms: header exactly {alg, kid, typ} with the `kid` the caller resolved,
///                   then the same signature, claim and time rules as verify().
///   precheckMessage() everything verifyWithKid() checks EXCEPT the signature -- for the one caller that
///                   does not hold the key (remoted's re-enrollment path). NOT verification: see below.

#pragma once

#include "jwt/base64Url.hpp"
#include "jwt/canonicalAgentId.hpp"
#include "jwt/jwtCompactGrammar.hpp"
#include "jwt/jwtEnrollProfileV1.hpp"
#include "jwt/jwtProfileV1.hpp"
#include "jwt/jwtVerifyError.hpp"
#include "jwt/secureBytes.hpp"
#include "jwt/strictJsonObject.hpp"

#include <array>
#include <chrono>
#include <optional>
#include <string>
#include <string_view>

namespace jwt_profile::v1::enroll
{
    class JwtEnrollTokenVerifier final
    {
    public:
        /// Which key a token asks for. The two `kid` shapes are disjoint (22 base64url chars can never
        /// be a canonical digit string and vice versa), so classification is by shape alone.
        enum class KidKind
        {
            None,  ///< header {alg, typ}: the shared password key
            Token, ///< `kid` = enrollment token id (kTokenKidChars canonical base64url chars)
            Agent  ///< `kid` = canonical agent id (re-enrollment)
        };
        struct PeekedKid
        {
            KidKind kind;
            std::string text; ///< the `kid` as written (empty for None)
        };

        /// @return VerifyError::None when the token is a valid `wazuh-enroll+jwt` for `key` at `now`.
        static VerifyError verify(std::string_view token,
                                  const SecureBytes& key,
                                  const TimePolicy& policy,
                                  std::chrono::system_clock::time_point now) noexcept
        {
            try
            {
                return verifyImpl(token, key, policy, now);
            }
            catch (...)
            {
                return VerifyError::InvalidToken;
            }
        }

        /// @brief Grammar + header only, no signature: which form is this token? nullopt when the
        /// text is not a `wazuh-enroll+jwt` at all (grammar, alg/typ, a `kid` of neither shape, any
        /// other header member), so a hostile peer cannot probe key stores with garbage.
        static std::optional<PeekedKid> peekKid(std::string_view token) noexcept
        {
            try
            {
                CompactParts parts;
                if (!splitCompact(token, parts))
                {
                    return std::nullopt;
                }
                const auto headerJson = base64UrlDecodeCanonical(parts.header64);
                if (!headerJson)
                {
                    return std::nullopt;
                }
                StrictJsonObject<2> shared;
                if (StrictJsonObject<2>::parse(kHeaderFields, *headerJson, shared))
                {
                    if (shared.str(hAlg) != kAlg || shared.str(hTyp) != kTyp)
                    {
                        return std::nullopt;
                    }
                    return PeekedKid {KidKind::None, {}};
                }
                StrictJsonObject<3> keyed;
                if (!StrictJsonObject<3>::parse(kKidHeaderFields, *headerJson, keyed) || keyed.str(kAlgIdx) != kAlg ||
                    keyed.str(kTypIdx) != kTyp)
                {
                    return std::nullopt;
                }
                const auto kind = classifyKid(keyed.str(kKidIdx));
                if (kind == KidKind::None)
                {
                    return std::nullopt;
                }
                return PeekedKid {kind, std::string {keyed.str(kKidIdx)}};
            }
            catch (...)
            {
                return std::nullopt;
            }
        }

        /// @brief Full verification of a `kid` token with the key the caller resolved for `kid`.
        /// The header must be exactly {alg, kid, typ} and carry this very `kid` (a token that names
        /// another key is InvalidToken, never verified against a key it did not ask for).
        static VerifyError verifyWithKid(std::string_view token,
                                         std::string_view kid,
                                         const SecureBytes& key,
                                         const TimePolicy& policy,
                                         std::chrono::system_clock::time_point now) noexcept
        {
            try
            {
                return verifyWithKidImpl(token, kid, key, policy, now);
            }
            catch (...)
            {
                return VerifyError::InvalidToken;
            }
        }

        /// @brief The key-independent half of verifyWithKid(): the compact grammar, the exact
        /// {alg, kid, typ} header naming this very `kid`, the exact {exp, iat, jti, nbf} claim set and
        /// the shared time rules -- everything EXCEPT the HMAC. For the one caller that cannot hold the
        /// key at all (remoted forwarding a re-enrollment bearer to authd on the master, issue #38993):
        /// it lets that node refuse, at no cost and with the same verdict, a message the key holder
        /// would refuse anyway, instead of spending an authd -- and, on a worker, a cluster -- round
        /// trip on 130 constant bytes.
        ///
        /// NOT a substitute for verifyWithKid(): whoever holds the key MUST call that instead.
        /// VerifyError::None here means "nothing that can be judged without the key is wrong with this
        /// message", never "this token is authentic" -- the signature is entirely unexamined, so the
        /// message may well be forged. Every failure it does report is one verifyWithKid() reports too,
        /// with the same value, so a caller that pre-filters answers exactly what the key holder would
        /// have answered. (Only the ORDER differs: verifyWithKid() checks the signature first, so a
        /// message that is both stale and badly signed is InvalidSignature there and StaleToken here --
        /// two answers whoever minted the message already knows, and neither says anything about the key.)
        static VerifyError precheckMessage(std::string_view token,
                                           std::string_view kid,
                                           const TimePolicy& policy,
                                           std::chrono::system_clock::time_point now) noexcept
        {
            try
            {
                CompactParts parts;
                if (!splitCompact(token, parts) || !headerNamesKid(parts, kid))
                {
                    return VerifyError::InvalidToken;
                }
                return checkClaims(parts, policy, now);
            }
            catch (...)
            {
                return VerifyError::InvalidToken;
            }
        }

    private:
        static constexpr std::array<JsonField, 2> kHeaderFields {{{"alg", false}, {"typ", false}}};
        enum HeaderIndex : std::size_t
        {
            hAlg = 0,
            hTyp = 1
        };
        static constexpr std::array<JsonField, 3> kKidHeaderFields {{{"alg", false}, {"kid", false}, {"typ", false}}};
        enum KidHeaderIndex : std::size_t
        {
            kAlgIdx = 0,
            kKidIdx = 1,
            kTypIdx = 2
        };
        static constexpr std::array<JsonField, 4> kPayloadFields {
            {{"exp", true}, {"iat", true}, {"jti", false}, {"nbf", true}}};
        enum PayloadIndex : std::size_t
        {
            pExp = 0,
            pIat = 1,
            pJti = 2,
            pNbf = 3
        };

        static KidKind classifyKid(std::string_view kid) noexcept
        {
            if (isCanonicalBase64UrlOf(kid, kTokenIdBytes))
            {
                return KidKind::Token;
            }
            if (CanonicalAgentId::parseCanonical(kid).has_value())
            {
                return KidKind::Agent;
            }
            return KidKind::None;
        }

        static VerifyError verifyImpl(std::string_view token,
                                      const SecureBytes& key,
                                      const TimePolicy& policy,
                                      std::chrono::system_clock::time_point now)
        {
            CompactParts parts;
            if (!splitCompact(token, parts))
            {
                return VerifyError::InvalidToken;
            }
            // Exact header {alg, typ}: a `kid` (either form) or anything else is rejected here.
            const auto headerJson = base64UrlDecodeCanonical(parts.header64);
            StrictJsonObject<2> header;
            if (!headerJson || !StrictJsonObject<2>::parse(kHeaderFields, *headerJson, header) ||
                header.str(hAlg) != kAlg || header.str(hTyp) != kTyp)
            {
                return VerifyError::InvalidToken;
            }
            return verifySignatureAndClaims(parts, key, policy, now);
        }

        static VerifyError verifyWithKidImpl(std::string_view token,
                                             std::string_view kid,
                                             const SecureBytes& key,
                                             const TimePolicy& policy,
                                             std::chrono::system_clock::time_point now)
        {
            CompactParts parts;
            if (!splitCompact(token, parts) || !headerNamesKid(parts, kid))
            {
                return VerifyError::InvalidToken;
            }
            return verifySignatureAndClaims(parts, key, policy, now);
        }

        /// Exact header {alg, kid, typ} naming the key the caller resolved; a shared-key header (no
        /// `kid`) or another `kid` is refused before any HMAC. Shared with precheckMessage(), so the
        /// keyed and key-independent paths can never disagree about which messages name this `kid`.
        static bool headerNamesKid(const CompactParts& parts, std::string_view kid)
        {
            const auto headerJson = base64UrlDecodeCanonical(parts.header64);
            StrictJsonObject<3> header;
            return headerJson && StrictJsonObject<3>::parse(kKidHeaderFields, *headerJson, header) &&
                   header.str(kAlgIdx) == kAlg && header.str(kTypIdx) == kTyp && header.str(kKidIdx) == kid &&
                   classifyKid(kid) != KidKind::None;
        }

        /// Signature before anything in the payload is looked at; then the exact claim set and the
        /// shared time rules. Identical for both header forms.
        static VerifyError verifySignatureAndClaims(const CompactParts& parts,
                                                    const SecureBytes& key,
                                                    const TimePolicy& policy,
                                                    std::chrono::system_clock::time_point now)
        {
            if (!verifyHs256(parts, key))
            {
                return VerifyError::InvalidSignature;
            }
            return checkClaims(parts, policy, now);
        }

        /// The exact {exp, iat, jti, nbf} claim set and the shared time rules: the half of the profile
        /// that needs no key. Reached only after the signature on every keyed path
        /// (verifySignatureAndClaims()), and on its own from precheckMessage() -- one body, so the two
        /// always answer alike.
        static VerifyError
        checkClaims(const CompactParts& parts, const TimePolicy& policy, std::chrono::system_clock::time_point now)
        {
            const auto payloadJson = base64UrlDecodeCanonical(parts.payload64);
            StrictJsonObject<4> claims;
            if (!payloadJson || !StrictJsonObject<4>::parse(kPayloadFields, *payloadJson, claims))
            {
                return VerifyError::InvalidToken;
            }
            if (const auto err = checkTimeRules(claims.num(pIat), claims.num(pNbf), claims.num(pExp), policy, now);
                err != VerifyError::None)
            {
                return err;
            }
            if (!isCanonicalBase64UrlOf(claims.str(pJti), kJtiBytes))
            {
                return VerifyError::InvalidToken;
            }
            return VerifyError::None;
        }
    };
} // namespace jwt_profile::v1::enroll
