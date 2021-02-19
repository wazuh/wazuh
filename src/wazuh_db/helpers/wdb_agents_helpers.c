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

#include "wdb_agents_helpers.h"
//#include "defs.h"
#include "wazuhdb_op.h"

#define WDBQUERY_SIZE OS_BUFFER_SIZE
#define WDBOUTPUT_SIZE OS_MAXSTR

static const char *agents_db_commands[] = {
    [WDB_AGENTS_VULN_CVE_INSERT] = "agent %d vuln_cve insert %s",
    [WDB_AGENTS_VULN_CVE_CLEAR] = "agent %d vuln_cve clear"
};

int wdb_agents_vuln_cve_insert(int id,
                               const char *name,
                               const char *version,
                               const char *architecture,
                               const char *cve,
                               int *sock) {
    int result = 0;
    cJSON *data_in = NULL;
    char *data_in_str = NULL;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char *payload = NULL;
    int aux_sock = -1;

    data_in = cJSON_CreateObject();

    if (!data_in) {
        mdebug1("Error creating data JSON for Wazuh DB.");
        return OS_INVALID;
    }

    cJSON_AddStringToObject(data_in, "name", name);
    cJSON_AddStringToObject(data_in, "version", version);
    cJSON_AddStringToObject(data_in, "architecture", architecture);
    cJSON_AddStringToObject(data_in, "cve", cve);

    data_in_str = cJSON_PrintUnformatted(data_in);
    cJSON_Delete(data_in);
    snprintf(wdbquery, sizeof(wdbquery), agents_db_commands[WDB_AGENTS_VULN_CVE_INSERT], id, data_in_str);
    os_free(data_in_str);

    result = wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    switch (result) {
        case OS_SUCCESS:
            if (WDBC_OK != wdbc_parse_result(wdboutput, &payload)) {
                mdebug1("Agents DB (%d) Error reported in the result of the query", id);
                result = OS_INVALID;
            }
            break;
        case OS_INVALID:
            mdebug1("Agents DB (%d) Error in the response from socket", id);
            mdebug2("Agents DB (%d) SQL query: %s", id, wdbquery);
            return OS_INVALID;
        default:
            mdebug1("Agents DB (%d) Cannot execute SQL query", id);
            mdebug2("Agents DB (%d) SQL query: %s", id, wdbquery);
            return OS_INVALID;
    }

    return result;
}

int wdb_agents_vuln_cve_clear(int id,
                              int *sock) {
    int result = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char *payload = NULL;
    int aux_sock = -1;

    snprintf(wdbquery, sizeof(wdbquery), agents_db_commands[WDB_AGENTS_VULN_CVE_CLEAR], id);

    result = wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    switch (result) {
        case OS_SUCCESS:
            if (WDBC_OK != wdbc_parse_result(wdboutput, &payload)) {
                mdebug1("Agents DB (%d) Error reported in the result of the query", id);
                result = OS_INVALID;
            }
            break;
        case OS_INVALID:
            mdebug1("Agents DB (%d) Error in the response from socket", id);
            mdebug2("Agents DB (%d) SQL query: %s", id, wdbquery);
            return OS_INVALID;
        default:
            mdebug1("Agents DB (%d) Cannot execute SQL query", id);
            mdebug2("Agents DB (%d) SQL query: %s", id, wdbquery);
            return OS_INVALID;
    }

    return result;
}
