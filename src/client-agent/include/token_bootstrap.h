/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/**
 * @file token_bootstrap.h
 * @brief Agent-side bootstrap from a one-shot enrollment token: read the token installed at
 *        AGENT_ENROLLMENT_TOKEN_FILE, decode it, learn the manager's CA
 *        (fetching /cacerts unverified and SPKI-pin-comparing it, or trusting an embedded CA
 *        outright), enroll fully verified against that CA, and persist it as
 *        AGENT_ANCHOR_CA -- the agent's own trust anchor from then on.
 *
 * Runs once per install, from AgentdStart() on POSIX (agentd.c) and from local_start() on
 * Windows (win_utils.c).
 */
#ifndef TOKEN_BOOTSTRAP_H
#define TOKEN_BOOTSTRAP_H

/**
 * @brief Outcome of w_agent_token_bootstrap(): whether the caller should give up or retry.
 *
 * W_TOKEN_BOOTSTRAP_DONE covers both a no-op (nothing to do: an anchor or client.keys already
 * exists, or no token file is present -- a legacy install) and a full success. Only the caller
 * can tell those apart if it needs to (checking AGENT_ANCHOR_CA/KEYS_FILE itself), because the
 * distinction has never mattered to what happens next: startup carries on either way.
 *
 * W_TOKEN_BOOTSTRAP_TRANSIENT and W_TOKEN_BOOTSTRAP_PERMANENT only ever come from an attempted
 * bootstrap that did not finish (a token file was present). PERMANENT causes -- a token that
 * fails to decode, an address it names that cannot be parsed, a fetched CA that fails the
 * token's pin, a 4xx from /cacerts or /enroll (the manager has already decided this request is
 * not going to succeed), or a local I/O failure writing the anchor/keys -- are not worth
 * retrying: the same token, dialled again, fails the same way. TRANSIENT causes -- the address
 * unreachable, a 5xx from /cacerts or /enroll, or the verified enroll's own transport failing --
 * may clear on their own, so the caller is expected to retry using the same backoff ramp
 * AgentdStart() already runs for the legacy enrollment loop (agt->enrollment.retry_delta/
 * retry_max), not to fall through to it: the legacy loop enrolls unverified, and the whole point
 * of the token path is that it never does.
 */
typedef enum {
    W_TOKEN_BOOTSTRAP_DONE = 0,
    W_TOKEN_BOOTSTRAP_TRANSIENT,
    W_TOKEN_BOOTSTRAP_PERMANENT
} w_token_bootstrap_result_t;

/**
 * @brief Runs the enrollment-token bootstrap, if one is configured and nothing has already
 *        superseded it.
 *
 * W_TOKEN_BOOTSTRAP_DONE in every case where the token path is simply not applicable:
 * AGENT_ANCHOR_CA already exists (a previous run already committed one -- the bootstrap never
 * re-fetches once an anchor is on disk), KEYS_FILE already exists (already enrolled), or
 * AGENT_ENROLLMENT_TOKEN_FILE does not exist (a legacy install with no token) -- and also when a
 * present token bootstraps fully. Any attempted bootstrap that does not fully succeed logs a
 * distinct, named merror() for whichever step failed (decode, address, /cacerts fetch, pin
 * mismatch, or the verified enroll itself), classifies it (see w_token_bootstrap_result_t), and
 * leaves nothing behind -- a later boot, or a retry within the same boot, can retry cleanly.
 *
 * @param uid The uid AgentdStart() is about to drop privileges to. The committed anchor is
 *        chowned to it so the agent can replace the anchor itself when the manager publishes a
 *        new CA bundle (#39321) -- under the sticky etc/certs only the file's owner may rename
 *        over it. client.keys is deliberately NOT chowned to it; see token_bootstrap.c's own
 *        comments on the two. Ignored on Windows, which has no privilege drop; local_start()
 *        passes 0.
 * @param gid The gid AgentdStart() is about to drop privileges to, so the committed anchor ends
 *        up group-owned by it. Ignored on Windows for the same reason, which passes 0 too.
 * @return See w_token_bootstrap_result_t.
 */
/* Largest enrollment token this agent will read, wherever it comes from. Shared so the
 * installer's --show-token and the first-boot bootstrap agree: when --show-token accepted more
 * than the bootstrap could read, a token between the two sizes passed the install and then
 * failed at the first start, with nothing at install time to warn about it. A token carrying a
 * pin is a couple of hundred bytes and one embedding a CA a few KB, so this is a sanity bound
 * rather than a tight one. */
#define W_ETOKEN_MAX_FILE_BYTES 8192

w_token_bootstrap_result_t w_agent_token_bootstrap(int uid, int gid);

#endif /* TOKEN_BOOTSTRAP_H */
