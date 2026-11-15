/* Copyright (C) Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef AGENT_MANAGER_ENTRY_H
#define AGENT_MANAGER_ENTRY_H

#include <stdint.h>

#include "client-config.h"

/**
 * @brief Release every manager entry and leave the agent with none.
 */
void w_agent_free_managers(agent *logr);

/**
 * @brief Make a manager the agent's single entry, replacing any earlier one.
 *
 * 5.x connects to one manager (#37702), so logr->server always holds one entry and the
 * NULL-rip sentinel after it. Shared by <agent><manager> and the legacy <client> block.
 *
 * @param host Manager host. An IPv6 address is stored expanded.
 * @param port Manager port.
 * @param endpoint Endpoint prefix; "" stores none.
 * @param scope_id IPv6 scope id, 0 when there is no zone.
 */
void w_agent_set_manager(agent *logr, const char *host, int port, const char *endpoint,
                         uint32_t scope_id);

#endif /* AGENT_MANAGER_ENTRY_H */
