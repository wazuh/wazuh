/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/**
 * @file enrollment.h
 * @brief Agent-side enrollment over HTTPS (#38465): build the /enroll JSON
 *        request and parse its response, entirely decoupled from transport.
 *
 * Replaces src/shared/src/enrollment_op.c's OSSEC-wire-protocol client. This
 * module never calls into https_client_bridge.h and knows nothing about
 * curl/HTTP -- agentd (client-agent/src/start_agent.c's try_enroll_to_server())
 * orchestrates build -> w_https_client_enroll() -> parse explicitly, so
 * validation/message-shape (here) and transport (the bridge) stay decoupled.
 */
#ifndef ENROLLMENT_H
#define ENROLLMENT_H

#include "https_client.h" /* hc_enroll_result_t */

/** @brief One built /enroll request, ready for w_https_client_enroll(). */
typedef struct w_enroll_request_t {
    char *body_json; /**< Heap-allocated JSON body. Freed by w_enroll_request_destroy(). */
    char *password;  /**< Heap-allocated password, or NULL for mTLS/open mode
                       *   (no bearer token). Freed by w_enroll_request_destroy(). */
} w_enroll_request_t;

/** @brief Outcome of parsing an /enroll response (#38465 R12). */
typedef enum {
    W_ENROLL_OK = 0,              /**< 200: keys parsed and written to client.keys. */
    W_ENROLL_ERR_TRANSPORT,       /**< No HTTP response at all (invalid transport
                                    *   config, connect/TLS failure). */
    W_ENROLL_ERR_INVALID_REQUEST, /**< 400: malformed request. */
    W_ENROLL_ERR_AUTH,            /**< 401: invalid or missing credential. */
    W_ENROLL_ERR_DISABLED,        /**< 403: enrollment administratively disabled
                                    *   on the manager -- distinct from a transport
                                    *   error, do not blind-retry the same way. */
    W_ENROLL_ERR_DUPLICATE,       /**< 409: duplicate agent. */
    W_ENROLL_ERR_SERVER           /**< 500/503, or any other/malformed response. */
} w_enroll_status_t;

/**
 * @brief Validates the local enrollment config and builds the /enroll JSON
 *        body + password (#38465). Pure: no transport, no globals touched
 *        besides reading agt->enrollment/keys.
 *
 * Body shape: {"name","version","groups"?,"ip"?,"key_hash"?} per the #38438
 * contract. "ip" encodes the same 3 cases the legacy IP:'...' field did:
 * an explicit agent_address, the literal "src" for use_source_ip=yes, or
 * omitted entirely (default -- the manager decides). "key_hash" is the SHA1
 * of the current client.keys entry (w_get_key_hash()), present only when one
 * exists (absent on first enrollment).
 *
 * @param out Filled on success; the caller owns it via w_enroll_request_destroy().
 * @return 0 on success; -1 on a local validation failure (e.g. an invalid
 *         configured agent name or agent_address) -- nothing is sent in that case.
 */
int w_enrollment_build_request(w_enroll_request_t *out);

/** @brief Frees the heap fields of a w_enroll_request_t. NULL-safe. */
void w_enroll_request_destroy(w_enroll_request_t *request);

/**
 * @brief Parses one /enroll HTTP outcome and, on success, writes client.keys
 *        (atomically on Linux, directly on Windows -- see
 *        w_enrollment_store_key_entry()'s platform split) from the response
 *        body. Never touches curl/HTTP: the caller already has the raw
 *        result via w_https_client_enroll().
 *
 * Does NOT reload the in-memory `keys` global (OS_UpdateKeys()) or set the
 * crypto method: that stays the orchestrator's job (start_agent.c's
 * try_enroll_to_server()), same as it is today.
 */
w_enroll_status_t w_enrollment_process_response(const hc_enroll_result_t *result);

#endif /* ENROLLMENT_H */
