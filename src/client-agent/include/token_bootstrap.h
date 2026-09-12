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
 * Runs once, before AgentdStart()'s privilege drop: the anchor is created while still root, so
 * its ownership is fixed up (group only, see token_bootstrap.c) before the process becomes the
 * unprivileged `wazuh` user. client.keys is left at whatever the installer set it to -- see
 * token_bootstrap.c's own comment on that.
 */
#ifndef TOKEN_BOOTSTRAP_H
#define TOKEN_BOOTSTRAP_H

/**
 * @brief Runs the enrollment-token bootstrap, if one is configured and nothing has already
 *        superseded it.
 *
 * A no-op (0) in every case where the token path is simply not applicable: AGENT_ANCHOR_CA
 * already exists (a previous run already committed one -- the bootstrap never re-fetches once
 * an anchor is on disk), KEYS_FILE already exists (already enrolled), or
 * AGENT_ENROLLMENT_TOKEN_FILE does not exist (a legacy install with no token). Any attempted
 * bootstrap that does not fully succeed logs a distinct, named merror() for whichever step
 * failed (decode, address, /cacerts fetch, pin mismatch, or the verified enroll itself) and
 * leaves nothing behind -- a later boot can retry cleanly.
 *
 * Never aborts startup either way: the caller (AgentdStart()) must still give the legacy
 * password/mTLS enrollment loop its normal chance when this returns -1 or the token path was
 * never configured.
 *
 * @param uid The uid AgentdStart() is about to drop privileges to. Currently unused: neither
 *        file this function writes is chowned to it (see token_bootstrap.c's own comments on
 *        the anchor and on client.keys) -- kept for signature symmetry with AgentdStart()'s
 *        uid/gid pair.
 * @param gid The gid AgentdStart() is about to drop privileges to, so the committed anchor ends
 *        up group-owned by it.
 * @return 0 when there was nothing to do, or the bootstrap fully succeeded; -1 when a token was
 *         present and the bootstrap was attempted but failed.
 */
/* Largest enrollment token this agent will read, wherever it comes from. Shared so the
 * installer's --show-token and the first-boot bootstrap agree: when --show-token accepted more
 * than the bootstrap could read, a token between the two sizes passed the install and then
 * failed at the first start, with nothing at install time to warn about it. A token carrying a
 * pin is a couple of hundred bytes and one embedding a CA a few KB, so this is a sanity bound
 * rather than a tight one. */
#define W_ETOKEN_MAX_FILE_BYTES 8192

int w_agent_token_bootstrap(int uid, int gid);

#endif /* TOKEN_BOOTSTRAP_H */
