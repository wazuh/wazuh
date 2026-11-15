/* Copyright (C) Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef LEGACY_CLIENT_MANAGER_H
#define LEGACY_CLIENT_MANAGER_H

#include "client-config.h"
#include "legacy-server-targets.h"

/**
 * @brief Make the target a legacy <client> chose the agent's manager.
 *
 * An <endpoint> is parsed exactly as one under <agent><manager> would be. An <address>
 * gets the 5.x HTTPS port and the manager's default prefix, and an INFO line with the
 * <endpoint> that keeps the agent where it connects now.
 *
 * @return 0 on success, also when there is no target; OS_INVALID when the chosen
 *         <endpoint> doesn't parse (logged).
 */
int w_legacy_client_set_manager(agent *logr, const w_legacy_targets_t *targets);

#endif /* LEGACY_CLIENT_MANAGER_H */
