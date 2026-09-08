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

#ifndef REENROLL_VERIFY_H
#define REENROLL_VERIFY_H

#ifdef __cplusplus
extern "C" {
#endif

/* Verdicts of w_reenroll_verify(). */
#define W_REENROLL_OK      0
#define W_REENROLL_INVALID (-1) /* not a wazuh-enroll+jwt for this agent signed with this secret */
#define W_REENROLL_STALE   (-2) /* well-formed and correctly signed, but outside the accepted time window */

/**
 * @brief Verifies the `wazuh-enroll+jwt` bearer an agent re-enrolls with (issue #38993).
 *
 * The bearer's `kid` must be exactly @p agent_id, and its HS256 signature must verify with the key
 * HKDF-derived (label WAZUH-REENROLL-KEY) from the agent's re-enrollment secret -- the same
 * derivation and the same verifier remoted and the agent use (shared_modules/utils/jwt/), so the
 * three implementations cannot drift. remoted forwards this bearer unverified: the secret lives in the
 * master's global.db and nowhere else, which makes authd on the master the only place this can run.
 *
 * @param bearer The compact JWT (the text after `Bearer `).
 * @param agent_id The canonical agent id the request names (`kid`).
 * @param secret_hex The agent's re-enrollment secret as stored: 64 lowercase hex chars.
 * @param now Current Unix time, in seconds.
 * @param jwt_max_age Accepted token age in seconds (remoted.jwt_max_age, [1, 43200]).
 * @param jwt_clock_skew Accepted clock skew in seconds (remoted.jwt_clock_skew, [0, 43200]).
 *        An out-of-range pair falls back to the profile defaults (60 / 30) rather than widening.
 * @return W_REENROLL_OK, W_REENROLL_INVALID (grammar, another `kid`, signature, claims, a secret that is
 *         not 64 hex chars, a NULL argument) or W_REENROLL_STALE. Never throws, never logs.
 */
int w_reenroll_verify(const char *bearer, const char *agent_id, const char *secret_hex, long now, int jwt_max_age, int jwt_clock_skew);

#ifdef __cplusplus
}
#endif

#endif /* REENROLL_VERIFY_H */
