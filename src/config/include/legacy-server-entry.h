/* Copyright (C) Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef LEGACY_SERVER_ENTRY_H
#define LEGACY_SERVER_ENTRY_H

#include "client-config.h"
#include "legacy-server-targets.h"

/**
 * @brief Make a legacy <client><server> target the agent's single manager entry.
 *
 * An <endpoint> is parsed exactly as one under <agent><manager> would be. An <address>
 * gets the 5.x HTTPS port and the manager's default prefix, and an INFO line with the
 * <endpoint> that keeps the agent where it connects now.
 *
 * @param logr Agent configuration; logr->server must be NULL.
 * @return 0 on success, OS_INVALID when an <endpoint> doesn't parse (logged).
 */
int w_legacy_server_install(agent *logr, const w_legacy_target_t *target);

#endif /* LEGACY_SERVER_ENTRY_H */
