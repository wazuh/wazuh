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
 * @brief Agent-side enrollment from a one-shot enrollment token: decode it, learn the manager's
 *        CA (fetching /cacerts unverified and SPKI-pin-comparing it, or trusting an embedded CA
 *        outright), enroll fully verified against that CA, and persist it as AGENT_ANCHOR_CA --
 *        the agent's own trust anchor from then on.
 *
 * Two entry points, because two callers want opposite things from the same sequence:
 *
 *  - w_agent_token_bootstrap() is the first-boot path, run once per install from AgentdStart()
 *    on POSIX (agentd.c) and from local_start() on Windows (win_utils.c). It is latched: an
 *    anchor already on disk, a non-empty client.keys, or no token file each independently make
 *    it a no-op. On POSIX it runs before AgentdStart()'s privilege drop, so the files it writes
 *    are owned while still root and handed to the runtime user before the process stops being
 *    able to.
 *
 *  - w_agent_token_enroll() is the same sequence with no latches and no opinion about where the
 *    token came from or what happens to it afterwards. It is what lets an operator enroll,
 *    re-enroll or move an agent that is already installed, long after the only boot that
 *    w_agent_token_bootstrap() would have acted on.
 */
#ifndef TOKEN_BOOTSTRAP_H
#define TOKEN_BOOTSTRAP_H

#include <stdbool.h>
#include "https_client.h"

/* Largest enrollment token this agent will read, wherever it comes from. Shared so the
 * installer's --show-token and the first-boot bootstrap agree: when --show-token accepted more
 * than the bootstrap could read, a token between the two sizes passed the install and then
 * failed at the first start, with nothing at install time to warn about it.
 *
 * A token carrying a pin is a couple of hundred bytes; one embedding a CA is bounded by what
 * authd is willing to mint, which is ETOKEN_CA_MAX_BYTES (64 KiB) of PEM. That PEM is escaped
 * into JSON, where every newline costs two bytes, and the whole object is then base64url'd at
 * 4/3 -- so authd's own ceiling lands near 88 KB and this has to clear it. At 8192 it did not:
 * a six-certificate bundle, which is the largest #39321 lets a manager publish, mints cleanly
 * at roughly 9 KB and was then refused at the agent's first boot.
 *
 * Note this is NOT the manager CLI's ceiling: os_auth/src/token_cli.c caps at 16384. Since
 * #39321 that mismatch runs the safe way round -- anything --show-token will describe, an agent
 * can read -- where before it ran the other way and produced exactly the failure above. Still
 * worth reconciling. */
#define W_ETOKEN_MAX_FILE_BYTES 98304

/**
 * @brief Which step of the token enrollment failed. Each value maps to one named merror() the
 *        core has already logged, so a caller can classify the failure without re-deriving it
 *        from the log.
 */
typedef enum {
    W_TOKEN_ENROLL_OK = 0,         /**< Committed: the anchor is installed AND client.keys written */
    W_TOKEN_ENROLL_ERR_TOKEN,      /**< Undecodable token, or an `adr` outside the endpoint grammar */
    W_TOKEN_ENROLL_ERR_ANCHOR,     /**< /cacerts fetch, truncation, pin mismatch, or anchor write */
    W_TOKEN_ENROLL_ERR_CREDENTIAL, /**< The token carries a credential that could not be prepared */
    W_TOKEN_ENROLL_ERR_REQUEST,    /**< w_enrollment_build_request() refused */
    W_TOKEN_ENROLL_ERR_ENROLL,     /**< Transport failure, non-200, or a refusal by the manager */
    W_TOKEN_ENROLL_ERR_STORE,      /**< The manager accepted, but its answer could not be stored */
    W_TOKEN_ENROLL_ERR_COMMIT      /**< Enrolled, but the on-disk commit failed -- see `rolled_back` */
} w_token_enroll_status_t;

/**
 * @brief What to enroll with, and what to leave behind.
 */
typedef struct {
    /** The token TEXT, never a path: acquiring it and disposing of it belong to the caller.
     *  w_agent_token_bootstrap() reads and unlinks a file; an operator's token file is neither
     *  the core's to read nor its to delete. */
    const char *token_text;
    /** The runtime user the agent will drop to. Two files are handed to it: the re-enrollment
     *  secret, which the daemon rewrites on every rotation after that drop, and since #39321 the
     *  trust anchor, which the daemon replaces when the manager publishes a new CA bundle --
     *  under the sticky etc/certs only the file's owner may rename over it. client.keys stays
     *  root-owned. -1 means "leave ownership alone", which is what a tool running long after the
     *  install passes: there is no drop to prepare for. */
    int uid;
    /** Group for the anchor and client.keys. client.keys is left owned by root and shared with
     *  this group -- the runtime user reads it and cannot replace it; the anchor is owned by
     *  `uid` and shared with this group. -1 leaves ownership alone. */
    int gid;
    /** Snapshot whatever anchor and client.keys are already on disk, and put them back if the
     *  commit fails. agentd's first boot has nothing to snapshot and passes false; a re-enrollment
     *  over a working agent passes true, because the alternative is an agent holding the new
     *  manager's key against the old manager's anchor -- able to reach neither. */
    bool transactional;
    /** Install the trust anchor and stop, without enrolling. For a manager that rotated its CA:
     *  it refreshes what the agent verifies against while leaving the registration alone, which
     *  a full enrollment cannot do -- that always yields a new agent id. */
    bool anchor_only;
} w_token_enroll_opts_t;

/**
 * @brief What the enrollment did, for a caller that has to explain it to an operator.
 *        Fully populated on success; on failure, whatever was known before the failing step.
 */
typedef struct {
    char host[HC_MAX_HOST];          /**< Manager host the token named */
    int port;                        /**< Resolved port (1517 unless the token said otherwise) */
    char endpoint[HC_MAX_ENDPOINT];  /**< Resolved URL prefix */
    bool used_pin;                   /**< false when the token embedded the CA and nothing was fetched */
    bool had_anchor;                 /**< An anchor existed before this call */
    bool had_keys;                   /**< client.keys was non-empty before this call */
    bool anchor_changed;             /**< The committed anchor differs from what was there before */
    bool rolled_back;                /**< ERR_COMMIT only: the previous state was restored */
    /** The failure may clear on its own: no response at all, or a 5xx, from /cacerts or /enroll.
     *  Meaningless when the status is OK. It is the whole of what w_agent_token_bootstrap()
     *  needs to decide between retrying and giving up (see w_token_bootstrap_result_t); an
     *  operator driving a single attempt from a terminal has no use for it. */
    bool transient;
    /** The manager finally refused the token itself: unknown, revoked, or out of uses. Its
     *  signature verified, so this is authd's verdict on the credential rather than on the
     *  request, and re-presenting it cannot change the answer. Acted on only by the caller,
     *  which is the only party that owns the token and can dispose of it. */
    bool token_rejected;
    /** The named reason the failing step logged, verbatim. The command runs with the log's stderr
     *  echo off (main-agent-auth.c's nowDaemon()), so without this an operator is shown the
     *  failure class and not the cause -- "the CA could not be established" reads identically for
     *  an address that does not resolve and a pin that does not match, and those want opposite
     *  responses. Empty when the step logged nothing of its own. */
    char detail[256];
    char keys_backup[PATH_MAX];      /**< Non-empty only when a rollback itself failed */
    char agent_id[16];               /**< Agent id the manager assigned */
    char agent_name[256];            /**< Agent name the manager registered */
    long http_code;                  /**< Last HTTP status from /enroll */
    /** What the manager said when it refused, verbatim from the response's error.message.
     *  Empty when it did not refuse or said nothing: the reason for a refusal is the manager's
     *  to give, and repeating it is the difference between "refused" and "refused because this
     *  name is taken by an agent too new to replace". */
    char manager_message[256];
} w_token_enroll_report_t;

/**
 * @brief Enroll from an already-acquired enrollment token.
 *
 * Unconditional: it does not consult AGENT_ANCHOR_CA, client.keys or
 * AGENT_ENROLLMENT_TOKEN_FILE for permission, and it never unlinks a token. Every failed step
 * logs its own named merror() before returning.
 *
 * Requires ClientConf() to have run: w_enrollment_build_request() reads agt->enrollment.*.
 * Deliberately does NOT read client.keys, so no `key_hash` reaches the manager -- a matching
 * hash makes the manager refuse the enrollment rather than preserve the agent's id.
 *
 * @param opts What to enroll with. Must not be NULL, and opts->token_text must not be NULL.
 * @param report Filled in with what happened. May be NULL.
 * @return W_TOKEN_ENROLL_OK when the anchor and client.keys are both committed.
 */
w_token_enroll_status_t w_agent_token_enroll(const w_token_enroll_opts_t *opts,
                                             w_token_enroll_report_t *report);

/**
 * @brief A short, operator-facing sentence for a status. Never NULL.
 */
const char *w_agent_token_enroll_strerror(w_token_enroll_status_t status);

/**
 * @brief Reads an enrollment token out of a file: its first line, trimmed, bounded by
 *        W_ETOKEN_MAX_FILE_BYTES.
 *
 * Shared so the installer's token file and an operator's --token-file are read by one function
 * under one ceiling, rather than by two that can drift apart.
 *
 * @param path File to read.
 * @return Newly allocated token text the caller must free, or NULL when the file is missing,
 *         empty, or unreadable.
 */
char *w_agent_token_read_file(const char *path);

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
 * @brief Runs the first-boot enrollment-token bootstrap, if one is configured and nothing has
 *        already superseded it.
 *
 * W_TOKEN_BOOTSTRAP_DONE in every case where the token path is simply not applicable: AGENT_ANCHOR_CA
 * already exists (a previous run already committed one -- the bootstrap never re-fetches once
 * an anchor is on disk), client.keys is already non-empty (already enrolled), or
 * AGENT_ENROLLMENT_TOKEN_FILE does not exist (a legacy install with no token). The first two
 * also discard the token on their way out: it is a one-shot credential, and once either is true
 * it can never be used again.
 *
 * Each latch independently blocks a re-run, so this is not the way to re-enroll or to move an
 * agent -- w_agent_token_enroll() is, and wazuh-agent-auth is what drives it.
 *
 * @param uid The uid AgentdStart() is about to drop privileges to. The committed anchor is
 *        chowned to it so the agent can replace the anchor itself when the manager publishes a
 *        new CA bundle (#39321) -- under the sticky etc/certs only the file's owner may rename
 *        over it. client.keys is deliberately NOT chowned to it. Ignored on Windows, which has
 *        no privilege drop; local_start() passes 0.
 * @param gid The gid AgentdStart() is about to drop privileges to, so the committed anchor and
 *        client.keys end up group-owned by it and readable after the drop. client.keys stays
 *        root-owned and replaceable by nothing that runs as that user; the anchor is owned by
 *        @p uid, for the reason given above. Ignored on Windows for the same reason, which
 *        passes 0 too.
 * @return See w_token_bootstrap_result_t.
 */
w_token_bootstrap_result_t w_agent_token_bootstrap(int uid, int gid);

#endif /* TOKEN_BOOTSTRAP_H */
