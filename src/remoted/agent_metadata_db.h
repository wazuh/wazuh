/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef AGENT_METADATA_DB_H
#define AGENT_METADATA_DB_H

#include <stddef.h>

typedef struct agent_meta
{
    int agent_id;
    char* agent_ip;
    char* version;
    char* os_name;
    char* os_version;
    char* os_codename;
    char* os_platform;
    char* os_build;
    char* os_kernel;
    char* arch;
} agent_meta_t;

/* Forward declaration is OK in the header (we only need the pointer type here) */
struct agent_info_data;

void agent_metadata_init(void);
void agent_metadata_teardown(void);

agent_meta_t* agent_meta_from_agent_info(const char* id_str, const struct agent_info_data* ai);

int agent_meta_upsert_locked(const char* agent_id_str, agent_meta_t* fresh);

/* Snapshot helpers (copian strings; el caller libera con agent_meta_free) */
int agent_meta_snapshot_str(const char* agent_id_str, agent_meta_t* out);

void agent_meta_free(agent_meta_t* m);
void agent_meta_clear(agent_meta_t* m);

#endif /* AGENT_METADATA_DB_H */
