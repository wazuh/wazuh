/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/**
 * @file enrollment_status.h
 * @brief The outcome of one enrollment attempt, and the policy that decides what to do about it.
 *
 * Deliberately free of dependencies, and deliberately NOT part of enrollment.h: agentd.h has to
 * name w_enroll_status_t (try_enroll_to_server() returns it) and agentd.h is included from well
 * outside client-agent -- shared/src/log_builder.c, for one. enrollment.h itself pulls in
 * https_client.h for hc_enroll_result_t, and that header lives under
 * client-agent/https_client/include, which is on the include path of only a handful of targets.
 * Splitting the enums out is what keeps the transport's header from leaking into every consumer of
 * agentd.h.
 */
#ifndef ENROLLMENT_STATUS_H
#define ENROLLMENT_STATUS_H

/**
 * @brief Outcome of parsing an /enroll response (#38465 R12, refined by #39064).
 *
 * The three authentication outcomes are separate because they need three different answers, and
 * before #39064 the agent had only one: every 401 meant "retry for ever". The manager now names
 * the failure class on every 401 (#39040), so a credential that will never work is told apart
 * from one that might work on the next attempt.
 */
typedef enum {
    W_ENROLL_OK = 0,              /**< 200: keys parsed and written to client.keys. */
    W_ENROLL_ERR_TRANSPORT,       /**< No HTTP response at all (invalid transport
                                    *   config, connect/TLS failure). */
    W_ENROLL_ERR_INVALID_REQUEST, /**< 400: malformed request. */
    W_ENROLL_ERR_AUTH_RETRY,      /**< Any 401 that is not `unknown_agent`. #39064 splits the two
                                    *   statuses by STATUS, not by how final the class sounds:
                                    *   "retry 401", because every one of these can be fixed
                                    *   without the agent doing anything -- a clock the manager
                                    *   refused (`stale_token`), a token the served node has not
                                    *   synced yet (`token_unknown`, and `token_expired` /
                                    *   `token_revoked`, which reach a 401 only from remoted's
                                    *   lagging replica), a manager that could not judge the
                                    *   credential (`enrollment_key_unavailable`), no usable
                                    *   credential presented (`invalid_request`), or a credential
                                    *   the manager refused outright (`invalid_signature`, which
                                    *   must never re-enroll but is still worth retrying: the fix
                                    *   is on the manager). Also any 401 whose class could not be
                                    *   read, which is the fail-safe reading (design §2.9 rule 3). */
    W_ENROLL_ERR_AUTH_FATAL,      /**< Nothing the agent can retry into success. From the wire that
                                    *   is a 403 and only a 403: authd's authoritative verdict on a
                                    *   bearer whose signature the manager already VERIFIED
                                    *   (9022 unknown/revoked, 9023 expired, 9024 no uses left), so
                                    *   re-signing cannot help and a new enrollment token has to be
                                    *   minted. try_enroll_to_server() also reports it for a request
                                    *   this agent could not even build, which no manager is going
                                    *   to change its mind about either. The caller must stop, not
                                    *   back off. */
    W_ENROLL_ERR_IDENTITY_GONE,   /**< 401 `unknown_agent`: the manager has no agent for the
                                    *   identity this request tried to re-enroll. On /enroll that
                                    *   class can only come from authd's 9026, which only a
                                    *   re-enrollment bearer can provoke -- a password or token
                                    *   enrollment asserts no identity -- so it means exactly one
                                    *   thing: the stored re-enrollment secret is dead. */
    W_ENROLL_ERR_DISABLED,        /**< 403 with no authd code: enrollment administratively disabled
                                    *   on the manager -- distinct from a transport
                                    *   error, do not blind-retry the same way. */
    W_ENROLL_ERR_DUPLICATE,       /**< 409: duplicate agent. */
    W_ENROLL_ERR_SERVER           /**< 500/503, or any other/malformed response. */
} w_enroll_status_t;

/** @brief What a caller that just failed an attempt should do next. */
typedef enum {
    W_ENROLL_ACTION_RETRY = 0, /**< Back off and try again; the condition may clear. */
    W_ENROLL_ACTION_STOP       /**< Retrying cannot help. Stop and leave the reason in the log. */
} w_enroll_action_t;

/**
 * @brief Turns one failed attempt's status into the policy decision, and performs the one side
 *        effect that decision implies.
 *
 * The three re-enrollment triggers the design allows (§2.9) are: no key at all, the transport's
 * `unknown_agent` latch, and an operator. Nothing here adds a fourth; this only decides whether an
 * already-started enrollment loop keeps going.
 *
 * @param status The status w_enrollment_process_response() returned.
 * @return W_ENROLL_ACTION_RETRY or W_ENROLL_ACTION_STOP. Every STOP has already logged a named
 *         error saying what an operator has to do.
 *
 * Side effect, on W_ENROLL_ERR_IDENTITY_GONE only: the dead re-enrollment secret is shredded. It
 * can only ever produce the same rejection again, and keeping it would stop the agent from falling
 * back to a credential that still works. Whether a fallback exists is what decides RETRY vs STOP
 * in that case.
 */
w_enroll_action_t w_enrollment_apply_policy(w_enroll_status_t status);

#endif /* ENROLLMENT_STATUS_H */
