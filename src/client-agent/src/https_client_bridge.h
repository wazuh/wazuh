/*
 * Wazuh agent HTTPS client bridge (development scaffold)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HTTPS_CLIENT_BRIDGE_H
#define _HTTPS_CLIENT_BRIDGE_H

#include <stdbool.h>
#include <stddef.h> // size_t

#include "https_client.h" // hc_enroll_result_t

/**
 * @brief Start the HTTPS client module unconditionally. Relies on
 *        client-agent/src/main.c having already refused to start the agent
 *        (a hard exit) unless a validated server address is configured.
 */
void w_https_client_start(void);

/** @brief Stop and destroy the HTTPS client module if it was started. */
void w_https_client_stop(void);

/**
 * @brief Submit one stateless event frame ("queue:location:message" bytes) into
 *        the HTTPS /stateless accumulator. Non-blocking: appends and returns.
 *        Returns 0 if accepted, -1 if dropped (accumulator full) or the client
 *        is stopping / not started.
 */
int w_https_client_submit_event(const char *frame, size_t length);

/**
 * @brief Perform exactly one /enroll HTTP request (#38465), against the same
 *        manager/TLS material already configured for every other HTTPS
 *        endpoint (<agent><manager>, <agent><ssl>). Handle-less: usable before
 *        the module is started (first-boot enrollment has no handle yet) or
 *        standalone (re-enrollment after a 401). No retry loop -- the caller
 *        (client-agent/src/start_agent.c's try_enroll_to_server()) already
 *        owns backoff/retry one layer up.
 * @param body_json The already-built, already-validated JSON body
 *        (enrollment.c's job; never inspected here).
 * @param password Empty/NULL means no `wazuh-enroll+jwt` bearer (mTLS/open
 *        enrollment); a client cert (if <agent><ssl> has one) and a password
 *        may both apply at once, with no precedence between them.
 * @param result Filled with the HTTP outcome; http_code stays 0 when nothing
 *        was ever sent (invalid transport config, e.g. no CA under a
 *        verifying mode).
 * @return true once a request was sent and answered, whatever the HTTP
 *         status (the caller interprets 200 vs. 4xx/5xx); false when nothing
 *         was ever sent.
 */
bool w_https_client_enroll(const char *body_json, const char *password, hc_enroll_result_t *result);

#endif // _HTTPS_CLIENT_BRIDGE_H
