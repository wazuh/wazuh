/*
 * Wazuh remoted module - Enrollment endpoint metrics
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENROLLMENT_METRICS_HPP
#define _REMOTED_ENROLLMENT_METRICS_HPP

#include <memory>

#include <wazuh_metrics/iManager.hpp>

namespace remoted::enrollment
{
    // The remoted.enroll.* name catalog.
    constexpr auto METRIC_ACCEPTED {"remoted.enroll.accepted"};
    constexpr auto METRIC_REJECTED_AUTH {"remoted.enroll.rejected_auth"};
    constexpr auto METRIC_REJECTED_VALIDATION {"remoted.enroll.rejected_validation"};
    constexpr auto METRIC_DISABLED {"remoted.enroll.disabled"};
    constexpr auto METRIC_AUTHD_ERROR {"remoted.enroll.authd_error"};
    constexpr auto METRIC_AUTHD_UNAVAILABLE {"remoted.enroll.authd_unavailable"};
    // The enrollment-token outcomes (issue #38993): the subset of the requests above that presented
    // an enrollment-token bearer, by what happened to the TOKEN. `accepted` is a 200 obtained with a
    // token; the four rejections are the token's state -- unknown/expired/revoked decided by remoted's
    // replica of the store (and confirmed by authd's 9022/9023 when the replica lagged), exhausted
    // decided by authd alone (9024: it owns the use counter).
    constexpr auto METRIC_TOKEN_ACCEPTED {"remoted.enroll.token.accepted"};
    constexpr auto METRIC_TOKEN_REJECTED_UNKNOWN {"remoted.enroll.token.rejected_unknown"};
    constexpr auto METRIC_TOKEN_REJECTED_EXPIRED {"remoted.enroll.token.rejected_expired"};
    constexpr auto METRIC_TOKEN_REJECTED_REVOKED {"remoted.enroll.token.rejected_revoked"};
    constexpr auto METRIC_TOKEN_REJECTED_EXHAUSTED {"remoted.enroll.token.rejected_exhausted"};
    // The re-enrollment outcomes (issue #38993): the subset of the requests above whose bearer named an
    // agent (`kid` = agent id). remoted forwards that bearer unverified, so every one of these is authd's
    // verdict on the master: `accepted` is a 200 that rotated the agent's credentials, the three rejections
    // are its 9026 (unknown agent / no secret on record), 9027 (bad signature or malformed) and 9028
    // (outside the accepted time window) -- each also lands in the remoted.auth.reject.* cell of the
    // AuthError it maps to (unknown_agent / invalid_signature / clock_skew).
    constexpr auto METRIC_REENROLL_ACCEPTED {"remoted.enroll.reenroll.accepted"};
    constexpr auto METRIC_REENROLL_REJECTED_UNKNOWN {"remoted.enroll.reenroll.rejected_unknown"};
    constexpr auto METRIC_REENROLL_REJECTED_SIGNATURE {"remoted.enroll.reenroll.rejected_signature"};
    constexpr auto METRIC_REENROLL_REJECTED_STALE {"remoted.enroll.reenroll.rejected_stale"};
    constexpr auto METRIC_REENROLL_REJECTED_IN_PROGRESS {"remoted.enroll.reenroll.rejected_in_progress"};
    // Refused by the endpoint's rate limit (endpoints/rateLimitGate.hpp) BEFORE the handler ran:
    // no body was decoded, no credential was looked at, no authd round trip was spent. It is
    // therefore in none of the outcome families above -- those describe requests that were actually
    // processed -- and only here and in remoted.http.enroll.responses.429.
    constexpr auto METRIC_RATE_LIMITED {"remoted.enroll.rate_limited"};

    // POST /enroll/secret (issue #39315): the authenticated route an agent that ALREADY holds a
    // client.keys key calls to obtain the per-agent re-enrollment secret its enrollment never gave
    // it (a 4.x agent upgraded over WPK, an agent enrolled over 1515, a row rebuilt from
    // client.keys). Its own family rather than more cells on the ones above, because none of those
    // describes it: no enrollment happens, no identity is minted, and nothing is rotated. It lives
    // under the remoted.enroll.* prefix -- and in THIS header rather than a
    // endpoints/<name>Metrics.hpp of its own (the cacerts/download precedent) -- because its
    // downstream is the shared AuthdClient, which belongs to the enrollment subsystem, and
    // remoted.enroll.* is what an operator already greps.
    constexpr auto METRIC_SECRET_ISSUED {"remoted.enroll.secret.issued"};
    constexpr auto METRIC_SECRET_REJECTED_IN_PROGRESS {"remoted.enroll.secret.rejected_in_progress"};
    constexpr auto METRIC_SECRET_AUTHD_ERROR {"remoted.enroll.secret.authd_error"};
    constexpr auto METRIC_SECRET_AUTHD_UNAVAILABLE {"remoted.enroll.secret.authd_unavailable"};
    constexpr auto METRIC_SECRET_RATE_LIMITED {"remoted.enroll.secret.rate_limited"};

    struct EnrollmentMetrics
    {
        std::shared_ptr<wazuh::metrics::ICounter> accepted;
        std::shared_ptr<wazuh::metrics::ICounter> rejectedAuth;
        std::shared_ptr<wazuh::metrics::ICounter> rejectedValidation;
        std::shared_ptr<wazuh::metrics::ICounter> disabled;
        std::shared_ptr<wazuh::metrics::ICounter> authdError;
        std::shared_ptr<wazuh::metrics::ICounter> authdUnavailable;
        std::shared_ptr<wazuh::metrics::ICounter> tokenAccepted;
        std::shared_ptr<wazuh::metrics::ICounter> tokenRejectedUnknown;
        std::shared_ptr<wazuh::metrics::ICounter> tokenRejectedExpired;
        std::shared_ptr<wazuh::metrics::ICounter> tokenRejectedRevoked;
        std::shared_ptr<wazuh::metrics::ICounter> tokenRejectedExhausted;
        std::shared_ptr<wazuh::metrics::ICounter> reenrollAccepted;
        std::shared_ptr<wazuh::metrics::ICounter> reenrollRejectedUnknown;
        std::shared_ptr<wazuh::metrics::ICounter> reenrollRejectedSignature;
        std::shared_ptr<wazuh::metrics::ICounter> reenrollRejectedStale;
        std::shared_ptr<wazuh::metrics::ICounter> reenrollRejectedInProgress;
        std::shared_ptr<wazuh::metrics::ICounter> rateLimited;
    };

    inline EnrollmentMetrics makeEnrollmentMetrics(wazuh::metrics::IManager& manager)
    {
        return EnrollmentMetrics {
            manager.getOrCreateCounter(METRIC_ACCEPTED, "Enrollment requests that succeeded", "count"),
            manager.getOrCreateCounter(METRIC_REJECTED_AUTH, "Enrollment requests rejected on authentication", "count"),
            manager.getOrCreateCounter(
                METRIC_REJECTED_VALIDATION,
                "Enrollment requests rejected on local validation (Content-Encoding/schema/version)",
                "count"),
            manager.getOrCreateCounter(METRIC_DISABLED,
                                       "Enrollment requests rejected because enrollment is administratively disabled",
                                       "count"),
            manager.getOrCreateCounter(
                METRIC_AUTHD_ERROR, "Enrollment requests rejected by authd's own business rules", "count"),
            manager.getOrCreateCounter(
                METRIC_AUTHD_UNAVAILABLE, "Enrollment requests that got no clean answer from authd", "count"),
            manager.getOrCreateCounter(
                METRIC_TOKEN_ACCEPTED, "Enrollment requests that succeeded with an enrollment token", "count"),
            manager.getOrCreateCounter(METRIC_TOKEN_REJECTED_UNKNOWN,
                                       "Enrollment-token requests rejected because the token id is unknown (never "
                                       "minted, minted without a credential, not yet synchronized to this node, or "
                                       "-- from authd -- not found or revoked)",
                                       "count"),
            manager.getOrCreateCounter(METRIC_TOKEN_REJECTED_EXPIRED,
                                       "Enrollment-token requests rejected because the token is past its expiry",
                                       "count"),
            manager.getOrCreateCounter(METRIC_TOKEN_REJECTED_REVOKED,
                                       "Enrollment-token requests rejected because the token was revoked",
                                       "count"),
            manager.getOrCreateCounter(METRIC_TOKEN_REJECTED_EXHAUSTED,
                                       "Enrollment-token requests refused by authd because the token has no uses "
                                       "left (authd owns the use counter)",
                                       "count"),
            manager.getOrCreateCounter(METRIC_REENROLL_ACCEPTED,
                                       "Re-enrollments authd accepted: the agent kept its id and got new credentials",
                                       "count"),
            manager.getOrCreateCounter(METRIC_REENROLL_REJECTED_UNKNOWN,
                                       "Re-enrollments authd refused because the agent is unknown or has no "
                                       "re-enrollment secret on record (9026)",
                                       "count"),
            manager.getOrCreateCounter(METRIC_REENROLL_REJECTED_SIGNATURE,
                                       "Re-enrollments authd refused because the bearer did not verify against the "
                                       "agent's re-enrollment secret (9027)",
                                       "count"),
            manager.getOrCreateCounter(METRIC_REENROLL_REJECTED_STALE,
                                       "Re-enrollments authd refused because the bearer was outside the accepted "
                                       "time window (9028)",
                                       "count"),
            manager.getOrCreateCounter(METRIC_REENROLL_REJECTED_IN_PROGRESS,
                                       "Re-enrollments authd refused because a rotation for that agent is already "
                                       "accepted and not yet persisted (9030): the caller retries, it does not "
                                       "re-sign",
                                       "count"),
            manager.getOrCreateCounter(METRIC_RATE_LIMITED,
                                       "Enrollment requests refused by the endpoint's rate limit "
                                       "('remote.https.enroll_rate_limit'), before any authd round trip",
                                       "count")};
    }

    /**
     * @brief POST /enroll/secret's outcome counters (issue #39315).
     *
     * Deliberately a struct of its own rather than five more members on EnrollmentMetrics: the two
     * routes share a rate-limit bucket and an authd queue, not a set of outcomes, and keeping the
     * families apart is what lets an operator tell a bootstrap wave from an enrollment wave under
     * one ceiling. Default-constructed (all null) it counts nothing, like every other struct here.
     */
    struct ReenrollSecretMetrics
    {
        std::shared_ptr<wazuh::metrics::ICounter> issued;
        std::shared_ptr<wazuh::metrics::ICounter> rejectedInProgress;
        std::shared_ptr<wazuh::metrics::ICounter> authdError;
        std::shared_ptr<wazuh::metrics::ICounter> authdUnavailable;
        std::shared_ptr<wazuh::metrics::ICounter> rateLimited;
    };

    inline ReenrollSecretMetrics makeReenrollSecretMetrics(wazuh::metrics::IManager& manager)
    {
        return ReenrollSecretMetrics {
            manager.getOrCreateCounter(METRIC_SECRET_ISSUED,
                                       "Re-enrollment secrets issued to an agent that proved possession of its "
                                       "own client.keys key (the agent's key is NOT rotated)",
                                       "count"),
            manager.getOrCreateCounter(METRIC_SECRET_REJECTED_IN_PROGRESS,
                                       "Secret requests authd refused because a rotation for that agent is "
                                       "already in flight (9030): the agent retries",
                                       "count"),
            manager.getOrCreateCounter(METRIC_SECRET_AUTHD_ERROR,
                                       "Secret requests rejected by authd's own business rules -- notably 9026, "
                                       "the agent has no row in global.db yet (wm_database rebuilds it "
                                       "asynchronously from client.keys)",
                                       "count"),
            manager.getOrCreateCounter(METRIC_SECRET_AUTHD_UNAVAILABLE,
                                       "Secret requests that got no clean answer from authd (unreachable, "
                                       "timed out, or its bounded queue full)",
                                       "count"),
            manager.getOrCreateCounter(METRIC_SECRET_RATE_LIMITED,
                                       "Secret requests refused by the rate limit SHARED with POST /enroll "
                                       "('remote.https.enroll_rate_limit'), before authentication and before "
                                       "any authd round trip",
                                       "count")};
    }

    inline void incSecretIssued(ReenrollSecretMetrics& m)
    {
        if (m.issued)
        {
            m.issued->add();
        }
    }

    inline void incSecretRejectedInProgress(ReenrollSecretMetrics& m)
    {
        if (m.rejectedInProgress)
        {
            m.rejectedInProgress->add();
        }
    }

    inline void incSecretAuthdError(ReenrollSecretMetrics& m)
    {
        if (m.authdError)
        {
            m.authdError->add();
        }
    }

    inline void incSecretAuthdUnavailable(ReenrollSecretMetrics& m)
    {
        if (m.authdUnavailable)
        {
            m.authdUnavailable->add();
        }
    }

    inline void incTokenAccepted(EnrollmentMetrics& m)
    {
        if (m.tokenAccepted)
        {
            m.tokenAccepted->add();
        }
    }

    inline void incTokenRejectedUnknown(EnrollmentMetrics& m)
    {
        if (m.tokenRejectedUnknown)
        {
            m.tokenRejectedUnknown->add();
        }
    }

    inline void incTokenRejectedExpired(EnrollmentMetrics& m)
    {
        if (m.tokenRejectedExpired)
        {
            m.tokenRejectedExpired->add();
        }
    }

    inline void incTokenRejectedRevoked(EnrollmentMetrics& m)
    {
        if (m.tokenRejectedRevoked)
        {
            m.tokenRejectedRevoked->add();
        }
    }

    inline void incTokenRejectedExhausted(EnrollmentMetrics& m)
    {
        if (m.tokenRejectedExhausted)
        {
            m.tokenRejectedExhausted->add();
        }
    }

    inline void incReenrollAccepted(EnrollmentMetrics& m)
    {
        if (m.reenrollAccepted)
        {
            m.reenrollAccepted->add();
        }
    }

    inline void incReenrollRejectedUnknown(EnrollmentMetrics& m)
    {
        if (m.reenrollRejectedUnknown)
        {
            m.reenrollRejectedUnknown->add();
        }
    }

    inline void incReenrollRejectedSignature(EnrollmentMetrics& m)
    {
        if (m.reenrollRejectedSignature)
        {
            m.reenrollRejectedSignature->add();
        }
    }

    inline void incReenrollRejectedStale(EnrollmentMetrics& m)
    {
        if (m.reenrollRejectedStale)
        {
            m.reenrollRejectedStale->add();
        }
    }

    inline void incReenrollRejectedInProgress(EnrollmentMetrics& m)
    {
        if (m.reenrollRejectedInProgress)
        {
            m.reenrollRejectedInProgress->add();
        }
    }

    inline void incAccepted(EnrollmentMetrics& m)
    {
        if (m.accepted)
        {
            m.accepted->add();
        }
    }

    inline void incRejectedAuth(EnrollmentMetrics& m)
    {
        if (m.rejectedAuth)
        {
            m.rejectedAuth->add();
        }
    }

    inline void incRejectedValidation(EnrollmentMetrics& m)
    {
        if (m.rejectedValidation)
        {
            m.rejectedValidation->add();
        }
    }

    inline void incDisabled(EnrollmentMetrics& m)
    {
        if (m.disabled)
        {
            m.disabled->add();
        }
    }

    inline void incAuthdError(EnrollmentMetrics& m)
    {
        if (m.authdError)
        {
            m.authdError->add();
        }
    }

    inline void incAuthdUnavailable(EnrollmentMetrics& m)
    {
        if (m.authdUnavailable)
        {
            m.authdUnavailable->add();
        }
    }

} // namespace remoted::enrollment

#endif // _REMOTED_ENROLLMENT_METRICS_HPP
