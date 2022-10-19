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
    [WDB_AGENTS_SYS_OSINFO_SET_TRIAGGED] = "agent %d osinfo set_triaged",
    [WDB_AGENTS_VULN_CVES_INSERT] = "agent %d vuln_cves insert %s",
    [WDB_AGENTS_VULN_CVES_UPDATE_STATUS] = "agent %d vuln_cves update_status %s",
    [WDB_AGENTS_VULN_CVES_REMOVE] = "agent %d vuln_cves remove %s",
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

int wdb_set_agent_sys_osinfo_triaged(int id,
                                     int *sock) {
    int result = 0;
    char *wdbquery = NULL;
    char *wdboutput = NULL;
    char *payload = NULL;
    int aux_sock = -1;

    os_malloc(WDBQUERY_SIZE, wdbquery);
    snprintf(wdbquery, WDBQUERY_SIZE, agents_db_commands[WDB_AGENTS_SYS_OSINFO_SET_TRIAGGED], id);

    os_malloc(WDBOUTPUT_SIZE, wdboutput);
    result = wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, WDBOUTPUT_SIZE);

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
            result = OS_INVALID;
            break;
        default:
            mdebug1("Agents DB (%d) Cannot execute SQL query", id);
            mdebug2("Agents DB (%d) SQL query: %s", id, wdbquery);
            result = OS_INVALID;
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    os_free(wdbquery);
    os_free(wdboutput);

    return result;
}

cJSON* wdb_insert_vuln_cves(int id,
                            const char *name,
                            const char *version,
                            const char *architecture,
                            const char *cve,
                            const char *severity,
                            double cvss2_score,
                            double cvss3_score,
                            const char *reference,
                            const char *type,
                            const char *status,
                            char **external_references,
                            const char *condition,
                            const char *title,
                            const char *published,
                            const char *updated,
                            bool check_pkg_existence,
                            int *sock) {
    cJSON *data_in = NULL;
    char *data_in_str = NULL;
    char *wdbquery = NULL;
    char *wdboutput = NULL;
    int aux_sock = -1;

    data_in = cJSON_CreateObject();
    if (!data_in) {
        mdebug1("Error creating data JSON for Wazuh DB.");
        return NULL;
    }

    cJSON_AddStringToObject(data_in, "name", name);
    cJSON_AddStringToObject(data_in, "version", version);
    cJSON_AddStringToObject(data_in, "architecture", architecture);
    cJSON_AddStringToObject(data_in, "cve", cve);
    cJSON_AddStringToObject(data_in, "severity", severity);
    cJSON_AddNumberToObject(data_in, "cvss2_score", cvss2_score);
    cJSON_AddNumberToObject(data_in, "cvss3_score", cvss3_score);
    cJSON_AddStringToObject(data_in, "reference", reference);
    cJSON_AddStringToObject(data_in, "type", type);
    cJSON_AddStringToObject(data_in, "status", status);
    cJSON_AddStringToObject(data_in, "condition", condition);
    cJSON_AddStringToObject(data_in, "title", title);
    cJSON_AddStringToObject(data_in, "published", published);
    cJSON_AddStringToObject(data_in, "updated", updated);
    cJSON_AddBoolToObject(data_in, "check_pkg_existence", check_pkg_existence);

    // Limiting references just in case there are too many or the links are too long
    if (external_references) {
        char* str_cvs_references = NULL;
        os_calloc(WDB_MAX_QUERY_SIZE, sizeof(char), str_cvs_references);
        cJSON *j_cvs_references = cJSON_CreateArray();
        int refcount;
        for (refcount = 0; external_references[refcount]; ++refcount)
        {
            cJSON *j_ref_item = cJSON_CreateString(external_references[refcount]);
            cJSON_AddItemToArray(j_cvs_references, j_ref_item);

            cJSON_PrintPreallocated(j_cvs_references, str_cvs_references, WDB_MAX_QUERY_SIZE, FALSE);
            if (strlen(str_cvs_references) >= VULN_CVES_MAX_REFERENCES) {
                cJSON_DeleteItemFromArray(j_cvs_references, refcount);
                mdebug2("External references truncated before inserting in inventory.");
                break;
            }
        }
        cJSON_AddItemToObject(data_in, "external_references", j_cvs_references);
        os_free(str_cvs_references);
    }

    data_in_str = cJSON_PrintUnformatted(data_in);
    os_malloc(WDB_MAX_QUERY_SIZE, wdbquery);
    snprintf(wdbquery, WDB_MAX_QUERY_SIZE, agents_db_commands[WDB_AGENTS_VULN_CVES_INSERT], id, data_in_str);

    os_malloc(WDBOUTPUT_SIZE, wdboutput);
    cJSON* result = wdbc_query_parse_json(sock?sock:&aux_sock, wdbquery, wdboutput, WDBOUTPUT_SIZE);

    cJSON_Delete(data_in);
    os_free(data_in_str);
    os_free(wdbquery);
    os_free(wdboutput);

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    if (!result) {
        merror("Agents DB (%d) Error querying Wazuh DB to insert vuln_cves", id);
    }

    return result;
}

int wdb_update_vuln_cves_status(int id,
                                const char *old_status,
                                const char *new_status,
                                int *sock) {
    int result = 0;
    cJSON *data_in = NULL;
    char *data_in_str = NULL;
    char *wdbquery = NULL;
    char *wdboutput = NULL;
    char *payload = NULL;
    int aux_sock = -1;

    data_in = cJSON_CreateObject();

    if (!data_in) {
        mdebug1("Error creating data JSON for Wazuh DB.");
        return OS_INVALID;
    }

    cJSON_AddStringToObject(data_in, "old_status", old_status);
    cJSON_AddStringToObject(data_in, "new_status", new_status);

    data_in_str = cJSON_PrintUnformatted(data_in);
    os_malloc(WDBQUERY_SIZE, wdbquery);
    snprintf(wdbquery, WDBQUERY_SIZE, agents_db_commands[WDB_AGENTS_VULN_CVES_UPDATE_STATUS], id, data_in_str);

    os_malloc(WDBOUTPUT_SIZE, wdboutput);
    result = wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, WDBOUTPUT_SIZE);

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
            result = OS_INVALID;
            break;
        default:
            mdebug1("Agents DB (%d) Cannot execute SQL query", id);
            mdebug2("Agents DB (%d) SQL query: %s", id, wdbquery);
            result = OS_INVALID;
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    cJSON_Delete(data_in);
    os_free(data_in_str);
    os_free(wdbquery);
    os_free(wdboutput);

    return result;
}

int wdb_update_vuln_cves_status_by_type(int id,
                                        const char *type,
                                        const char *new_status,
                                        int *sock) {
    int result = 0;
    cJSON *data_in = NULL;
    char *data_in_str = NULL;
    char *wdbquery = NULL;
    char *wdboutput = NULL;
    char *payload = NULL;
    int aux_sock = -1;

    data_in = cJSON_CreateObject();

    if (!data_in) {
        mdebug1("Error creating data JSON for Wazuh DB.");
        return OS_INVALID;
    }

    cJSON_AddStringToObject(data_in, "type", type);
    cJSON_AddStringToObject(data_in, "new_status", new_status);

    data_in_str = cJSON_PrintUnformatted(data_in);
    os_malloc(WDBQUERY_SIZE, wdbquery);
    snprintf(wdbquery, WDBQUERY_SIZE, agents_db_commands[WDB_AGENTS_VULN_CVES_UPDATE_STATUS], id, data_in_str);

    os_malloc(WDBOUTPUT_SIZE, wdboutput);
    result = wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, WDBOUTPUT_SIZE);

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
            result = OS_INVALID;
            break;
        default:
            mdebug1("Agents DB (%d) Cannot execute SQL query", id);
            mdebug2("Agents DB (%d) SQL query: %s", id, wdbquery);
            result = OS_INVALID;
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    cJSON_Delete(data_in);
    os_free(data_in_str);
    os_free(wdbquery);
    os_free(wdboutput);

    return result;
}

cJSON* wdb_remove_vuln_cves_by_status(int id,
                                      const char *status,
                                      int *sock) {
    cJSON *data_in = NULL;
    char *data_in_str = NULL;
    char *wdbquery = NULL;
    char *wdboutput = NULL;
    char *payload = NULL;
    cJSON *data_out = NULL;
    wdbc_result wdb_res = WDBC_DUE;
    int aux_sock = -1;

    data_in = cJSON_CreateObject();

    if (!data_in) {
        mdebug1("Error creating data JSON for Wazuh DB.");
        return data_out;
    }

    cJSON_AddStringToObject(data_in, "status", status);

    data_in_str = cJSON_PrintUnformatted(data_in);
    os_malloc(WDBQUERY_SIZE, wdbquery);
    snprintf(wdbquery, WDBQUERY_SIZE, agents_db_commands[WDB_AGENTS_VULN_CVES_REMOVE], id, data_in_str);

    os_malloc(WDBOUTPUT_SIZE, wdboutput);
    while (wdb_res == WDBC_DUE) {
        // Query WazuhDB
        if (wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, WDBOUTPUT_SIZE) == 0) {
            wdb_res = wdbc_parse_result(wdboutput, &payload);

            if (WDBC_OK == wdb_res || WDBC_DUE == wdb_res) {
                const char *error = NULL;
                cJSON *cves = cJSON_ParseWithOpts(payload, &error, TRUE);

                if (!cves) {
                    mdebug1("Invalid vuln_cves JSON results syntax after removing vulnerabilities.");
                    mdebug2("JSON error near: %s", error);
                    wdb_res = WDBC_ERROR;
                }
                else {
                    if (!data_out) {
                        // The first call to Wazuh DB, we consider the query response as the response of the method.
                        data_out = cves;
                    }
                    else {
                        // In case of having vulnerabilities returned by chunks, from the second call, all the subsequent calls
                        // we will add the JSON response of the query to the JSON response of the query obtained in the first call.
                        cJSON *cve = NULL;
                        cJSON_ArrayForEach(cve, cves) {
                            cJSON_AddItemToArray(data_out, cJSON_Duplicate(cve, true));
                        }
                        cJSON_Delete(cves);
                    }
                }
            }
            else {
                mdebug1("Agents DB (%d) Error reported in the result of the query", id);
            }
        }
        else {
            mdebug1("Error removing vulnerabilities from the agent database.");
            wdb_res = WDBC_ERROR;
        }
    }

    if (WDBC_ERROR == wdb_res) {
        cJSON_Delete(data_out);
        data_out = NULL;
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    cJSON_Delete(data_in);
    os_free(data_in_str);
    os_free(wdbquery);
    os_free(wdboutput);

    return data_out;
}
