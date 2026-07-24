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

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Start the HTTPS client module unconditionally. Relies on
 *        client-agent/src/main.c having already refused to start the agent
 *        (a hard exit) unless a validated server address is configured.
 */
void w_https_client_start(void);

/** @brief Stop and destroy the HTTPS client module if it was started. */
void w_https_client_stop(void);

/**
 * @brief Submit a stateless event frame to the HTTPS client's accumulator
 *        (issue #37835: /stateless egress split off the shared buffer).
 *
 * @param frame Raw frame bytes (agt->m_queue's msg, not required to be
 *              null-terminated); pass the exact received length, not -1.
 * @param length Exact frame length in bytes.
 * @return true if accepted by the module; false when the module isn't
 *         running (g_https_client == NULL), in which case the caller must
 *         fall back to the legacy path.
 */
bool w_https_client_submit_event(const uint8_t *frame, size_t length);

#endif // _HTTPS_CLIENT_BRIDGE_H
