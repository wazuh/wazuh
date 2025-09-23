/*
 * Wazuh Shared Configuration Manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 19, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef AGENT_METADATA_WRAPPERS_H
#define AGENT_METADATA_WRAPPERS_H

#include "../../remoted/agent_metadata_db.h"

void __wrap_agent_metadata_init(void);

agent_meta_t* __wrap_agent_meta_from_agent_info(const char* id_str, const struct agent_info_data* ai);

int __wrap_agent_meta_upsert_locked(const char* agent_id_str, agent_meta_t* fresh);

int __wrap_agent_meta_snapshot_str(const char* agent_id_str, agent_meta_t* out);

void __wrap_agent_meta_free(agent_meta_t* m);

void __wrap_agent_meta_clear(agent_meta_t* m);

#endif // AGENT_METADATA_WRAPPERS_H
