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

/* A package installed without a token keeps its placeholder address, and the address error alone
 * does not say what comes next: enrolling, which points <manager><endpoint> at the token's manager
 * (or, on a 4.x <client><server> block, says what to set by hand). Named only when client.keys is
 * empty: wazuh-agent-auth refuses an agent that already has a key. */
static void w_agent_hint_enrollment(void)
{
    if (FileSize(KEYS_FILE) <= 0) {
        merror(AG_NOT_ENROLLED);
    }
}

bool w_agent_validate_manager_address(const agent *cfg)
{
    if (!(cfg->server && cfg->server[0].rip)) {
        merror(AG_INV_IP);
        return false;
    }

    if (!Validate_Address(cfg->server)) {
        merror(AG_INV_MNGIP, cfg->server[0].rip);
        w_agent_hint_enrollment();
        return false;
    }

    return true;
}
