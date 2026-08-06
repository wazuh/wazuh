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

#include <stddef.h> // size_t

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

#endif // _HTTPS_CLIENT_BRIDGE_H
