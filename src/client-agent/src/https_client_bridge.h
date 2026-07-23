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

/**
 * @brief Start the HTTPS client module unconditionally. Relies on
 *        client-agent/src/main.c having already refused to start the agent
 *        (a hard exit) unless a validated server address is configured.
 */
void w_https_client_start(void);

/** @brief Stop and destroy the HTTPS client module if it was started. */
void w_https_client_stop(void);

#endif // _HTTPS_CLIENT_BRIDGE_H
