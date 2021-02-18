/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2021, Wazuh Inc.
 * February 17, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"
#include "defs.h"
#include "wazuhdb_op.h"

#define WDBQUERY_SIZE OS_BUFFER_SIZE
#define WDBOUTPUT_SIZE OS_MAXSTR

static const char *agent_db_commands[] = {
    [WDB_VU_HOTFIXES_REQUEST] = "agent %s sql SELECT HOTFIX FROM SYS_HOTFIXES WHERE SCAN_ID='%s';",

};

cJSON* wdb_get_agent_vu_hotfixes(char *agent_id, char *last_scan_id, int *sock) {
    cJSON *root = NULL;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    int aux_sock = -1;

    snprintf(wdbquery, sizeof(wdbquery), agent_db_commands[WDB_VU_HOTFIXES_REQUEST], agent_id, last_scan_id);
    root = wdbc_query_parse_json(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    if (!root) {
        merror("Error querying Wazuh DB to get the agent's '%s' hotfixes from scan %s.", agent_id, last_scan_id);
        return NULL;
    }

    return root;
}