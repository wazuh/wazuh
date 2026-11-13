/* Copyright (C) Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef AGENT_MANAGER_BLOCKS_H
#define AGENT_MANAGER_BLOCKS_H

#include "os_xml.h"

/**
 * @brief Count the <manager> blocks under every <agent> of every root ReadConfig() reads.
 *
 * Walks the same nodes config.c dispatches, so each block counted is one Read_Agent_Manager()
 * reads in the same call, or the read fails. OS_ElementExist() can't answer this: it misses a
 * match in a second root, or after an <agent> without <manager>.
 */
int w_count_agent_manager_blocks(const OS_XML *xml);

#endif /* AGENT_MANAGER_BLOCKS_H */
