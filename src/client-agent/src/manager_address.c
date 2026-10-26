/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"

bool w_agent_validate_manager_address(const agent *cfg)
{
    if (!(cfg->server && cfg->server[0].rip)) {
        merror(AG_INV_IP);
        return false;
    }

    if (!Validate_Address(cfg->server)) {
        merror(AG_INV_MNGIP, cfg->server[0].rip);
        return false;
    }

    return true;
}
