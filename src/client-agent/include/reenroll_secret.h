/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/**
 * @file reenroll_secret.h
 * @brief The agent's own re-enrollment credential, at rest (issue #39064).
 *
 * `POST /enroll` answers with a fifth field, `reenroll_secret`: 32 CSPRNG bytes as 64 lowercase
 * hex characters, the IKM of the HKDF (label WAZUH-REENROLL-KEY) that derives the
 * `wazuh-enroll+jwt` key this agent re-enrolls with. It replaces the fleet-wide etc/authd.pass as
 * the endpoint's recovery capability: narrower (it can only rotate the key of one id, it cannot
 * mint a new identity), per-agent (a stolen one is worth one endpoint, not the fleet), and rotated
 * on every enrollment.
 *
 * Stored as "<id> <secret>", not the secret alone. The bearer's `kid` is the agent's own canonical
 * id, so an agent that has lost client.keys -- the case this whole credential exists for -- still
 * has to know which id to present.
 *
 * ## Why client.keys's protection and not the trust anchor's
 *
 * #39060 gives AGENT_ANCHOR_CA ownership the `wazuh` user cannot replace, and #39064's task list
 * asks for "the same ownership treatment" here. That is not reachable, and it would buy nothing:
 *
 *   - Not reachable: the secret is rotated by every successful enrollment, and rotation happens
 *     inside the running daemon (bridge_reenroll_thread()), long after Privsep_SetUser(). The one
 *     root window on the agent -- w_agent_token_bootstrap(), before the privilege drop -- covers
 *     only the very first enrollment on the token path. A secret the daemon cannot rewrite is a
 *     secret that goes stale on the next rotation and then fails.
 *   - Buys nothing: this credential's power is exactly client.keys's power. Both rotate the key of
 *     one existing id; neither creates an identity. A process that can rewrite client.keys already
 *     owns the agent, so protecting the secret harder than the key it replaces protects nothing.
 *
 * The anchor is a different threat model: it defends against a local process that wants a
 * downgrade to an unverified transport, which is exactly why it must be out of `wazuh`'s reach.
 *
 * So: 0640, owned by the same user client.keys ends up owned by, atomic write-then-rename on
 * POSIX and a direct write on Windows -- the same platform split w_enrollment_store_key_entry()
 * keeps, and for the same reason.
 */
#ifndef REENROLL_SECRET_H
#define REENROLL_SECRET_H

#include <stddef.h>

/// Buffer size for an agent id read out of the store, including the NUL. Matches the widest id
/// OS_IsValidID() accepts (8 characters) with room to spare.
#define W_REENROLL_ID_SIZE 16

/// Buffer size for a secret read out of the store, including the NUL:
/// AGENT_REENROLL_SECRET_HEX_CHARS + 1.
#define W_REENROLL_SECRET_SIZE 65

/**
 * @brief Persists the re-enrollment credential for @p id, replacing any previous one.
 *
 * Atomic on POSIX (temp file + chmod 0640 + rename), so a crash mid-write leaves the previous
 * secret intact rather than a truncated one. Non-atomic on Windows, inherited deliberately from
 * w_enrollment_store_key_entry()'s own platform split.
 *
 * Both arguments are validated before anything is written: an id OS_IsValidID() refuses, or a
 * secret that is not exactly 64 lowercase hex characters, is a manager response this agent must
 * not act on, and writing it would leave a store that can only ever fail.
 *
 * @param id The agent's canonical id, as the manager just confirmed it.
 * @param secret The 64-hex-character secret from the response's `reenroll_secret`.
 * @return 0 on success; -1 on an invalid argument or any filesystem failure (logged).
 */
int w_reenroll_secret_store(const char* id, const char* secret);

/**
 * @brief Reads the stored credential.
 *
 * A store that is missing, empty, malformed, or holds values that no longer validate is reported
 * as simply absent (0 is never returned): there is nothing an agent can do with half a credential,
 * and treating it as absent is what makes it fall back to the enrollment token or the legacy
 * password instead of presenting a bearer nobody can verify. A malformed store is logged, since it
 * means something wrote it that should not have.
 *
 * @param id Receives the agent id; at least W_REENROLL_ID_SIZE bytes.
 * @param id_size Size of @p id.
 * @param secret Receives the secret; at least W_REENROLL_SECRET_SIZE bytes.
 * @param secret_size Size of @p secret.
 * @return 1 when a usable credential was read, 0 otherwise (both buffers are then empty).
 */
int w_reenroll_secret_load(char* id, size_t id_size, char* secret, size_t secret_size);

/**
 * @brief Overwrites and removes the store.
 *
 * Called when the manager has told us this credential is dead (`401 unknown_agent` on a
 * re-enrollment attempt): keeping it would only produce the same rejection for ever, and the agent
 * has to fall back to whatever else it has.
 *
 * The overwrite pass is best-effort by nature -- on a journalling filesystem, a copy-on-write one,
 * or any SSD doing wear levelling, the old bytes may survive somewhere the agent cannot reach. It
 * is worth doing anyway (it removes the obvious plaintext copy) but it is not an erasure
 * guarantee, and nothing here should be described as one.
 */
void w_reenroll_secret_clear(void);

#endif /* REENROLL_SECRET_H */
