/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
 * February 17, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb_agents_helpers.h"
#include "wazuhdb_op.h"

static const char *agents_db_commands[] = {
    [WDB_AGENTS_SYS_OSINFO_GET] = "agent %d osinfo get",
};

cJSON* wdb_get_agent_sys_osinfo(int id,
                                int *sock) {
    char *wdbquery = NULL;
    char *wdboutput = NULL;
    int aux_sock = -1;

    os_malloc(WDBQUERY_SIZE, wdbquery);
    snprintf(wdbquery, WDBQUERY_SIZE, agents_db_commands[WDB_AGENTS_SYS_OSINFO_GET], id);

    os_malloc(WDBOUTPUT_SIZE, wdboutput);
    cJSON* result = wdbc_query_parse_json(sock?sock:&aux_sock, wdbquery, wdboutput, WDBOUTPUT_SIZE);

    if (!result || !result->child) {
        cJSON_Delete(result);
        result = NULL;
    }

    os_free(wdbquery);
    os_free(wdboutput);

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    return result;
}
