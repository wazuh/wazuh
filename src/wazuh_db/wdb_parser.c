/*
 * Wazuh Database Daemon
 * Copyright (C) 2015-2020, Wazuh Inc.
 * January 16, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"
#include "external/cJSON/cJSON.h"

int wdb_parse(char * input, char * output) {
    char * actor;
    char * id;
    char * query;
    char * sql;
    char * next;
    int agent_id = 0;
    char sagent_id[64] = "000";
    wdb_t * wdb;
    cJSON * data;
    char * out;
    int result = 0;

    if (!input) {
        mdebug1("Empty input query.");
        return -1;
    }

    // Clean string
    while (*input == ' ' || *input == '\n') {
        input++;
    }

    if (next = wstr_chr(input, ' '), !next) {
        mdebug1("Invalid DB query syntax.");
        mdebug2("DB query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", input);
        return -1;
    }

    actor = input;
    *next++ = '\0';

    if (strcmp(actor, "agent") == 0) {
        id = next;

        if (next = wstr_chr(id, ' '), !next) {
            mdebug1("Invalid DB query syntax.");
            mdebug2("DB query error near: %s", id);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", id);
            return -1;
        }

        *next++ = '\0';
        query = next;

        if (agent_id = strtol(id, &next, 10), *next) {
            mdebug1("Invalid agent ID '%s'", id);
            snprintf(output, OS_MAXSTR + 1, "err Invalid agent ID '%.32s'", id);
            return -1;
        }

        snprintf(sagent_id, sizeof(sagent_id), "%03d", agent_id);

        if (wdb = wdb_open_agent2(agent_id), !wdb) {
            merror("Couldn't open DB for agent '%s'", sagent_id);
            snprintf(output, OS_MAXSTR + 1, "err Couldn't open DB for agent %d", agent_id);
            return -1;
        }

        mdebug2("Agent %s query: %s", sagent_id, query);

        if (next = wstr_chr(query, ' '), next) {
            *next++ = '\0';
        }

        if (strcmp(query, "syscheck") == 0) {
            if (!next) {
                mdebug1("DB(%s) Invalid FIM query syntax.", sagent_id);
                mdebug2("DB(%s) FIM query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", query);
                result = -1;
            } else {
                result = wdb_parse_syscheck(wdb, next, output);
            }
        } else if (strcmp(query, "sca") == 0) {
            if (!next) {
                mdebug1("Invalid DB query syntax.");
                mdebug2("DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = -1;
            } else {
                result = wdb_parse_sca(wdb, next, output);
                if (result < 0){
                    merror("Unable to update 'sca_check' table for agent '%s'", sagent_id);
                } else {
                    result = 0;
                }
            }
        } else if (strcmp(query, "netinfo") == 0) {
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = -1;
            } else {
                if (wdb_parse_netinfo(wdb, next, output) == 0){
                    mdebug2("Updated 'sys_netiface' table for agent '%s'", sagent_id);
                } else {
                    merror("Unable to update 'sys_netiface' table for agent '%s'", sagent_id);
                }
            }
        } else if (strcmp(query, "netproto") == 0) {
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = -1;
            } else {
                if (wdb_parse_netproto(wdb, next, output) == 0){
                    mdebug2("Updated 'sys_netproto' table for agent '%s'", sagent_id);
                } else {
                    merror("Unable to update 'sys_netproto' table for agent '%s'", sagent_id);
                }
            }
        } else if (strcmp(query, "netaddr") == 0) {
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = -1;
            } else {
                if (wdb_parse_netaddr(wdb, next, output) == 0){
                    mdebug2("Updated 'sys_netaddr' table for agent '%s'", sagent_id);
                } else {
                    merror("Unable to update 'sys_netaddr' table for agent '%s'", sagent_id);
                }
            }
        } else if (strcmp(query, "osinfo") == 0) {
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = -1;
            } else {
                if (wdb_parse_osinfo(wdb, next, output) == 0){
                    mdebug2("Updated 'sys_osinfo' table for agent '%s'", sagent_id);
                } else {
                    merror("Unable to update 'sys_osinfo' table for agent '%s'", sagent_id);
                }
            }
        } else if (strcmp(query, "hardware") == 0) {
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = -1;
            } else {
                if (wdb_parse_hardware(wdb, next, output) == 0){
                    mdebug2("Updated 'sys_hwinfo' table for agent '%s'", sagent_id);
                } else {
                    merror("Unable to update 'sys_hwinfo' table for agent '%s'", sagent_id);
                }
            }
        } else if (strcmp(query, "port") == 0) {
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = -1;
            } else {
                if (wdb_parse_ports(wdb, next, output) == 0){
                    mdebug2("Updated 'sys_ports' table for agent '%s'", sagent_id);
                } else {
                    merror("Unable to update 'sys_ports' table for agent '%s'", sagent_id);
                }
            }
        } else if (strcmp(query, "package") == 0) {
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = -1;
            } else {
                if (wdb_parse_packages(wdb, next, output) == 0){
                    mdebug2("Updated 'sys_programs' table for agent '%s'", sagent_id);
                } else {
                    merror("Unable to update 'sys_programs' table for agent '%s'", sagent_id);
                }
            }
        } else if (strcmp(query, "hotfix") == 0) {
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = -1;
            } else {
                if (wdb_parse_hotfixes(wdb, next, output) == 0){
                    mdebug2("Updated 'sys_hotfixes' table for agent '%s'", sagent_id);
                } else {
                    merror("Unable to update 'sys_hotfixes' table for agent '%s'", sagent_id);
                }
            }
        } else if (strcmp(query, "process") == 0) {
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = -1;
            } else {
                if (wdb_parse_processes(wdb, next, output) == 0){
                    mdebug2("Updated 'sys_processes' table for agent '%s'", sagent_id);
                } else {
                    merror("Unable to update 'sys_processes' table for agent '%s'", sagent_id);
                }
            }
        } else if (strcmp(query, "ciscat") == 0) {
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = -1;
            } else {
                if (wdb_parse_ciscat(wdb, next, output) == 0){
                    mdebug2("Updated 'ciscat_results' table for agent '%s'", sagent_id);
                } else {
                    merror("Unable to update 'ciscat_results' table for agent '%s'", sagent_id);
                }
            }
        } else if (strcmp(query, "sql") == 0) {
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = -1;
            } else {
                sql = next;

                if (data = wdb_exec(wdb->db, sql), data) {
                    out = cJSON_PrintUnformatted(data);
                    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
                    os_free(out);
                    cJSON_Delete(data);
                } else {
                    mdebug1("DB(%s) Cannot execute SQL query.", sagent_id);
                    mdebug2("DB(%s) SQL query: %s", sagent_id, sql);
                    snprintf(output, OS_MAXSTR + 1, "err Cannot execute SQL query");
                    result = -1;
                }
            }
        } else if (strcmp(query, "remove") == 0) {
            wdb_leave(wdb);
            snprintf(output, OS_MAXSTR + 1, "ok");
            result = 0;

            w_mutex_lock(&pool_mutex);

            if (wdb_close(wdb, FALSE) < 0) {
                mdebug1("DB(%s) Cannot close database.", sagent_id);
                snprintf(output, OS_MAXSTR + 1, "err Cannot close database");
                result = -1;
            }

            if (wdb_remove_database(sagent_id) < 0) {
                snprintf(output, OS_MAXSTR + 1, "err Cannot remove database");
                result = -1;
            }

            w_mutex_unlock(&pool_mutex);
            return result;
        } else if (strcmp(query, "begin") == 0) {
            if (wdb_begin2(wdb) < 0) {
                mdebug1("DB(%s) Cannot begin transaction.", sagent_id);
                snprintf(output, OS_MAXSTR + 1, "err Cannot begin transaction");
                result = -1;
            } else {
                snprintf(output, OS_MAXSTR + 1, "ok");
            }
        } else if (strcmp(query, "commit") == 0) {
            if (wdb_commit2(wdb) < 0) {
                mdebug1("DB(%s) Cannot end transaction.", sagent_id);
                snprintf(output, OS_MAXSTR + 1, "err Cannot end transaction");
                result = -1;
            } else {
                snprintf(output, OS_MAXSTR + 1, "ok");
            }
        } else if (strcmp(query, "close") == 0) {
            wdb_leave(wdb);
            w_mutex_lock(&pool_mutex);

            if (wdb_close(wdb, TRUE) < 0) {
                mdebug1("DB(%s) Cannot close database.", sagent_id);
                snprintf(output, OS_MAXSTR + 1, "err Cannot close database");
                result = -1;
            } else {
                snprintf(output, OS_MAXSTR + 1, "ok");
                result = 0;
            }

            w_mutex_unlock(&pool_mutex);
            return result;
        } else {
            mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
            mdebug2("DB(%s) query error near: %s", sagent_id, query);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
            result = -1;
        }
        wdb_leave(wdb);
        return result;
    } else if (strcmp(actor, "wazuhdb") == 0) {
        query = next;

        if (next = wstr_chr(query, ' '), !next) {
            mdebug1("Invalid DB query syntax.");
            mdebug2("DB query error near: %s", query);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
            return -1;
        }
        *next++ = '\0';

        if(strcmp(query, "remove") == 0) {
            data = wdb_remove_multiple_agents(next);
            out = cJSON_PrintUnformatted(data);
            snprintf(output, OS_MAXSTR + 1, "ok %s", out);
            os_free(out);
            cJSON_Delete(data);
        } else {
            mdebug1("Invalid DB query syntax.");
            mdebug2("DB query error near: %s", query);
            snprintf(output, OS_MAXSTR + 1, "err No agents id provided");
            return -1;
        }
        return result;
    } else if(strcmp(actor, "mitre") == 0) {
        query = next;

        if (wdb = wdb_open_mitre(), !wdb) {
            mdebug2("Couldn't open DB mitre: %s/%s.db", WDB_DIR, WDB_MITRE_NAME);
            snprintf(output, OS_MAXSTR + 1, "err Couldn't open DB mitre");
            return -1;
        }

        if (next = wstr_chr(query, ' '), !next) {
            mdebug1("Invalid DB query syntax.");
            mdebug2("DB query error near: %s", query);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
            wdb_leave(wdb);
            return -1;
        }
        *next++ = '\0';

        if (strcmp(query, "sql") == 0) {
            if (!next) {
                mdebug1("Mitre DB Invalid DB query syntax.");
                mdebug2("Mitre DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = -1;
            } else {
                sql = next;

                if (data = wdb_exec(wdb->db, sql), data) {
                    out = cJSON_PrintUnformatted(data);
                    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
                    os_free(out);
                    cJSON_Delete(data);
                } else {
                    mdebug1("Mitre DB Cannot execute SQL query; err database %s/%s.db: %s", WDB_DIR, WDB_MITRE_NAME, sqlite3_errmsg(wdb->db));
                    mdebug2("Mitre DB SQL query: %s", sql);
                    snprintf(output, OS_MAXSTR + 1, "err Cannot execute Mitre database query; %s", sqlite3_errmsg(wdb->db));
                    result = -1;
                }
            }
        } else if (strcmp(query, "get") == 0) {
            if (!next) {
                mdebug1("Mitre DB Invalid DB query syntax.");
                mdebug2("Mitre DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = -1;
            } else {
                result = wdb_parse_mitre_get(wdb, next, output);
            }
        } else {
            mdebug1("Invalid DB query syntax.");
            mdebug2("DB query error near: %s", query);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
            result = -1;
        }
        wdb_leave(wdb);
        return result;
    } else if(strcmp(actor, "global") == 0) {
        query = next;

        mdebug2("Global query: %s", query);

        if (wdb = wdb_open_global(), !wdb) {
            mdebug2("Couldn't open DB global: %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
            snprintf(output, OS_MAXSTR + 1, "err Couldn't open DB global");
            return OS_INVALID;
        }

        if (next = wstr_chr(query, ' '), next) {
            *next++ = '\0';
        }

        if (strcmp(query, "sql") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                if (data = wdb_exec(wdb->db, next), data) {
                    out = cJSON_PrintUnformatted(data);
                    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
                    os_free(out);
                    cJSON_Delete(data);
                } else {
                    mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                    mdebug2("Global DB SQL query: %s", next);
                    snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                    result = OS_INVALID;
                }
            }
        } else if (strcmp(query, "insert-agent") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for insert-agent.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_insert_agent(wdb, next, output);
            }
        } else if (strcmp(query, "update-agent-name") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for update-agent-name.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_update_agent_name(wdb, next, output);
            }
        } else if (strcmp(query, "update-agent-data") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for update-agent-data.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_update_agent_data(wdb, next, output);
            }
        } else if (strcmp(query, "get-labels") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for get-labels.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_get_agent_labels(wdb, next, output);
            }
        } else if (strcmp(query, "set-labels") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for set-labels.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_set_agent_labels(wdb, next, output);
            }
        } else if (strcmp(query, "update-keepalive") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for update-keepalive.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_update_agent_keepalive(wdb, next, output);
            }
        } else if (strcmp(query, "delete-agent") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for delete-agent.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_delete_agent(wdb, next, output);
            }
        } else if (strcmp(query, "select-agent-name") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for select-agent-name.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_select_agent_name(wdb, next, output);
            }
        } else if (strcmp(query, "select-agent-group") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for select-agent-group.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_select_agent_group(wdb, next, output);
            }
        } else if (strcmp(query, "delete-agent-belong") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for delete-agent-belong.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_delete_agent_belong(wdb, next, output);
            }
        } else if (strcmp(query, "find-agent") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for find-agent.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_find_agent(wdb, next, output);
            }
        } else if (strcmp(query, "select-fim-offset") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for select-fim-offset.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_select_fim_offset(wdb, next, output);
            }
        } else if (strcmp(query, "select-reg-offset") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for select-reg-offset.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_select_reg_offset(wdb, next, output);
            }
        } else if (strcmp(query, "update-fim-offset") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for update-fim-offset.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_update_fim_offset(wdb, next, output);
            }
        } else if (strcmp(query, "update-reg-offset") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for update-reg-offset.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_update_reg_offset(wdb, next, output);
            }
        } else if (strcmp(query, "select-agent-status") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for select-agent-status.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_select_agent_status(wdb, next, output);
            }
        } else if (strcmp(query, "update-agent-status") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for update-agent-status.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_update_agent_status(wdb, next, output);
            }
        } else if (strcmp(query, "update-agent-group") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for update-agent-group.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_update_agent_group(wdb, next, output);
            }
        } else if (strcmp(query, "find-group") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for find-group.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_find_group(wdb, next, output);
            }
        } else if (strcmp(query, "insert-agent-group") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for insert-agent-group.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_insert_agent_group(wdb, next, output);
            }
        } else if (strcmp(query, "insert-agent-belong") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for insert-agent-belong.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_insert_agent_belong(wdb, next, output);
            }
        } else if (strcmp(query, "delete-group-belong") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for delete-group-belong.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_delete_group_belong(wdb, next, output);
            }
        } else if (strcmp(query, "delete-group") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for delete-group.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_delete_group(wdb, next, output);
            }
        } else if (strcmp(query, "select-groups") == 0) {
            result = wdb_parse_global_select_groups(wdb, output);
        } else if (strcmp(query, "select-keepalive") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for select-keepalive.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_select_agent_keepalive(wdb, next, output);
            }
        } else if (strcmp(query, "sync-agent-info-get") == 0) {
            result = wdb_parse_global_sync_agent_info_get(wdb, next, output);
        } else if (strcmp(query, "sync-agent-info-set") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for sync-agent-info-set.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_sync_agent_info_set(wdb, next, output);
            }
        } 
        else if (strcmp(query, "get-agents-by-keepalive") == 0) { 
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for get-agents-by-keepalive.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_get_agents_by_keepalive(wdb, next, output);
            }
        }
        else if (strcmp(query, "get-all-agents") == 0) { 
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for get-all-agents.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_get_all_agents(wdb, next, output);
            }
        }
        else if (strcmp(query, "get-agent-info") == 0) {
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for get-agent-info.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                result = wdb_parse_global_get_agent_info(wdb, next, output);
            }
        } 
        else {
            mdebug1("Invalid DB query syntax.");
            mdebug2("Global DB query error near: %s", query);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
            result = OS_INVALID;
        }
        wdb_leave(wdb);
        return result;
    } else {
        mdebug1("DB(%s) Invalid DB query actor: %s", sagent_id, actor);
        snprintf(output, OS_MAXSTR + 1, "err Invalid DB query actor: '%.32s'", actor);
        return OS_INVALID;
    }
}

int wdb_parse_syscheck(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * checksum;
    char buffer[OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE];
    int ftype;
    int result;
    long ts;

    if (next = wstr_chr(input, ' '), !next) {
        mdebug2("DB(%s) Invalid FIM query syntax: %s", wdb->id, input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid FIM query syntax, near '%.32s'", input);
        return -1;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "scan_info_get") == 0) {
        if (result = wdb_scan_info_get(wdb, "fim", next, &ts), result < 0) {
            mdebug1("DB(%s) Cannot get FIM scan info.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot get fim scan info.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok %ld", ts);
        }

        return result;
    } else if (strcmp(curr, "updatedate") == 0) {
        if (result = wdb_fim_update_date_entry(wdb, next), result < 0) {
            mdebug1("DB(%s) Cannot update fim date field.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot update fim date field.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "cleandb") == 0) {
        if (result = wdb_fim_clean_old_entries(wdb), result < 0) {
            mdebug1("DB(%s) Cannot clean fim database.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot clean fim database.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "scan_info_update") == 0) {
        curr = next;

        if (next = wstr_chr(curr, ' '), !next) {
            mdebug1("DB(%s) Invalid scan_info fim query syntax.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", curr);
            return -1;
        }

        *next++ = '\0';
        ts = atol(next);
        if (result = wdb_scan_info_update(wdb, "fim", curr, ts), result < 0) {
            mdebug1("DB(%s) Cannot save fim control message.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot save fim control message");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "control") == 0) {
        if (result = wdb_scan_info_fim_checks_control(wdb, next), result < 0) {
            mdebug1("DB(%s) Cannot save fim check_control message.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot save fim control message");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "load") == 0) {
        if (result = wdb_syscheck_load(wdb, next, buffer, sizeof(buffer)), result < 0) {
            mdebug1("DB(%s) Cannot load FIM.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot load Syscheck");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok %s", buffer);
        }

        return result;
    } else if (strcmp(curr, "delete") == 0) {
        if (result = wdb_fim_delete(wdb, next), result < 0) {
            mdebug1("DB(%s) Cannot delete FIM entry.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete Syscheck");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = wstr_chr(curr, ' '), !next) {
            mdebug1("DB(%s) Invalid FIM query syntax.", wdb->id);
            mdebug2("DB(%s) FIM query: %s", wdb->id, curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", curr);
            return -1;
        }

        *next++ = '\0';

        if (strcmp(curr, "file") == 0) {
            ftype = WDB_FILE_TYPE_FILE;
        } else if (strcmp(curr, "registry") == 0) {
            ftype = WDB_FILE_TYPE_REGISTRY;
        } else {
            mdebug1("DB(%s) Invalid FIM query syntax.", wdb->id);
            mdebug2("DB(%s) FIM query: %s", wdb->id, curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", curr);
            return -1;
        }

        checksum = next;

        if (next = wstr_chr(checksum, ' '), !next) {
            mdebug1("DB(%s) Invalid FIM query syntax.", wdb->id);
            mdebug2("FIM query: %s", checksum);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", checksum);
            return -1;
        }

        *next++ = '\0';

        // Only the part before '!' has been escaped
        char *mark = strchr(checksum, '!');
        if (mark) *mark = '\0';
        char *unsc_checksum = wstr_replace(checksum, "\\ ", " ");
        if (mark) {
            *mark = '!';
            size_t unsc_size = strlen(unsc_checksum);
            size_t mark_size = strlen(mark);
            os_realloc(unsc_checksum, unsc_size + mark_size + 1, unsc_checksum);
            strncpy(unsc_checksum + unsc_size, mark, mark_size);
            unsc_checksum[unsc_size + mark_size] = '\0';
        }

        if (result = wdb_syscheck_save(wdb, ftype, unsc_checksum, next), result < 0) {
            mdebug1("DB(%s) Cannot save FIM.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Syscheck");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }
        free(unsc_checksum);

        return result;
    } else if (strcmp(curr, "save2") == 0) {
        if (wdb_syscheck_save2(wdb, next) == -1) {
            mdebug1("DB(%s) Cannot save FIM.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Syscheck");
            return -1;
        }

        snprintf(output, OS_MAXSTR + 1, "ok");
        return 0;
    } else if (strncmp(curr, "integrity_check_", 16) == 0) {
        switch (wdbi_query_checksum(wdb, WDB_FIM, curr, next)) {
        case -1:
            mdebug1("DB(%s) Cannot query FIM range checksum.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot perform range checksum");
            return -1;

        case 0:
            snprintf(output, OS_MAXSTR + 1, "ok no_data");
            break;

        case 1:
            snprintf(output, OS_MAXSTR + 1, "ok checksum_fail");
            break;

        default:
            snprintf(output, OS_MAXSTR + 1, "ok ");
        }

        return 0;
    } else if (strcmp(curr, "integrity_clear") == 0) {
        switch (wdbi_query_clear(wdb, WDB_FIM, next)) {
        case -1:
            mdebug1("DB(%s) Cannot query FIM range checksum.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot perform range checksum");
            return -1;

        default:
            snprintf(output, OS_MAXSTR + 1, "ok ");
        }

        return 0;
    } else {
        mdebug1("DB(%s) Invalid FIM query syntax.", wdb->id);
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", curr);
        return -1;
    }
}

int wdb_parse_sca(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * result_check; // Pass, failed
    char * status_check;
    char * reason_check;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid Security Configuration Assessment query syntax.");
        mdebug2("Security Configuration Assessment query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", input);
        return -1;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "query") == 0) {

        int pm_id;
        char result_found[OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE] = {0};

        curr = next;
        pm_id = strtol(curr,NULL,10);

        result = wdb_sca_find(wdb, pm_id, result_found);

        switch (result) {
            case 0:
                snprintf(output, OS_MAXSTR + 1, "ok not found");
                break;
            case 1:
                snprintf(output, OS_MAXSTR + 1, "ok found %s",result_found);
                break;
            default:
                mdebug1("Cannot query Security Configuration Assessment.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot query Security Configuration Assessment");
        }

        return result;
    } else if (strcmp(curr, "update") == 0) {

        int pm_id;
        int scan_id;

        curr = next;
        pm_id = strtol(curr,NULL,10);

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        *next++ = '\0';
        result_check = next;

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        *next++ = '\0';
        status_check = next;

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        *next++ = '\0';
        reason_check = next;

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        *next++ = '\0';
        curr = next;
        if (!strncmp(curr, "NULL", 4))
            scan_id = -1;
        else
            scan_id = strtol(curr,NULL,10);

        if (result = wdb_sca_update(wdb, result_check, pm_id, scan_id, status_check, reason_check), result < 0) {
            mdebug1("Cannot update Security Configuration Assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot update Security Configuration Assessment information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "insert") == 0) {

        curr = next;
        cJSON *event;
        const char *jsonErrPtr;
        if (event = cJSON_ParseWithOpts(curr, &jsonErrPtr, 0), !event)
        {
            mdebug1("Invalid Security Configuration Assessment query syntax. JSON object not found or invalid");
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        cJSON *id = NULL;
        cJSON *scan_id = NULL;
        cJSON *title = NULL;
        cJSON *description = NULL;
        cJSON *rationale = NULL;
        cJSON *remediation = NULL;
        cJSON *condition = NULL;
        cJSON *file = NULL;
        cJSON *directory = NULL;
        cJSON *process = NULL;
        cJSON *registry = NULL;
        cJSON *command = NULL;
        cJSON *reference = NULL;
        cJSON *result_check = NULL;
        cJSON *policy_id = NULL;
        cJSON *check = NULL;
        cJSON *status = NULL;
        cJSON *reason = NULL;

        if( scan_id = cJSON_GetObjectItem(event, "id"), !scan_id) {
            mdebug1("Invalid Security Configuration Assessment query syntax. JSON object not found or invalid");
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if( !scan_id->valueint ) {
            mdebug1("Malformed JSON: field 'id' must be a number");
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if( policy_id = cJSON_GetObjectItem(event, "policy_id"), !policy_id) {
            mdebug1("Malformed JSON: field 'policy_id' not found");
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if( !policy_id->valuestring ) {
            mdebug1("Malformed JSON: field 'policy_id' must be a string");
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if( check = cJSON_GetObjectItem(event, "check"),!check) {
            mdebug1("Malformed JSON: field 'check' not found");
            return -1;

        } else {

            if( id = cJSON_GetObjectItem(check, "id"), !id) {
                mdebug1("Malformed JSON: field 'id' not found");
                return -1;
            }

            if( !id->valueint ) {
                mdebug1("Malformed JSON: field 'id' must be a string");
                return -1;
            }

            if( title = cJSON_GetObjectItem(check, "title"), !title) {
                mdebug1("Malformed JSON: field 'title' not found");
                return -1;
            }

            if( !title->valuestring ) {
                mdebug1("Malformed JSON: field 'title' must be a string");
                return -1;
            }

            description = cJSON_GetObjectItem(check, "description");

            if( description && !description->valuestring ) {
                mdebug1("Malformed JSON: field 'description' must be a string");
                return -1;
            }

            rationale = cJSON_GetObjectItem(check, "rationale");

            if( rationale && !rationale->valuestring ) {
                mdebug1("Malformed JSON: field 'rationale' must be a string");
                return -1;
            }

            remediation = cJSON_GetObjectItem(check, "remediation");
            if( remediation && !remediation->valuestring ) {
                mdebug1("Malformed JSON: field 'remediation' must be a string");
                return -1;
            }

            reference = cJSON_GetObjectItem(check, "references");

            if( reference && !reference->valuestring ) {
                mdebug1("Malformed JSON: field 'reference' must be a string");
                return -1;
            }

            file = cJSON_GetObjectItem(check, "file");
            if( file && !file->valuestring ) {
                mdebug1("Malformed JSON: field 'file' must be a string");
                return -1;
            }

            condition = cJSON_GetObjectItem(check, "condition");
            if(condition && !condition->valuestring){
                mdebug1("Malformed JSON: field 'condition' must be a string");
                return -1;
            }

            directory = cJSON_GetObjectItem(check, "directory");
            if( directory && !directory->valuestring ) {
                mdebug1("Malformed JSON: field 'directory' must be a string");
                return -1;
            }

            process = cJSON_GetObjectItem(check, "process");
            if( process && !process->valuestring ) {
                mdebug1("Malformed JSON: field 'process' must be a string");
                return -1;
            }

            registry = cJSON_GetObjectItem(check, "registry");
            if( registry && !registry->valuestring ) {
                mdebug1("Malformed JSON: field 'registry' must be a string");
                return -1;
            }

            command = cJSON_GetObjectItem(check, "command");
            if( command && !command->valuestring ) {
                mdebug1("Malformed JSON: field 'command' must be a string");
                return -1;
            }

            if ( status = cJSON_GetObjectItem(check, "status"), status) {
                if ( reason = cJSON_GetObjectItem(check, "reason"), !reason) {
                    merror("Malformed JSON: field 'reason' not found");
                    return -1;
                }

                if( !status->valuestring ) {
                    merror("Malformed JSON: field 'status' must be a string");
                    return -1;
                }

                if( !reason->valuestring ) {
                    merror("Malformed JSON: field 'reason' must be a string");
                    return -1;
                }
            }

            if( result_check = cJSON_GetObjectItem(check, "result"), !result_check) {
                if (!status){
                    merror("Malformed JSON: field 'result' not found");
                    return -1;
                }
            } else {
                if(!result_check->valuestring ) {
                    mdebug1("Malformed JSON: field 'result' must be a string");
                    return -1;
                }
            }
        }


        if (result = wdb_sca_save(wdb, id->valueint, scan_id->valueint, title->valuestring,
                    description ? description->valuestring : NULL,
                    rationale ? rationale->valuestring : NULL,
                    remediation ? remediation->valuestring : NULL,
                    condition ? condition->valuestring : NULL,
                    file ? file->valuestring : NULL,
                    directory ? directory->valuestring : NULL,
                    process ? process->valuestring : NULL,
                    registry ? registry->valuestring : NULL,
                    reference ? reference->valuestring : NULL,
                    result_check ? result_check->valuestring : "",
                    policy_id->valuestring,
                    command ? command->valuestring : NULL,
                    status ? status->valuestring : NULL, reason ? reason->valuestring : NULL),
            result < 0)
        {
            mdebug1("Cannot save Security Configuration Assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Security Configuration Assessment information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        cJSON_Delete(event);

        return result;
    } else if (strcmp(curr, "delete_policy") == 0) {

        char *policy_id;

        curr = next;
        policy_id = curr;

        if (result = wdb_sca_policy_delete(wdb,policy_id), result < 0) {
            mdebug1("Cannot delete Security Configuration Assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete Security Configuration Assessment information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "delete_check_distinct") == 0) {

        char *policy_id;
        int scan_id;

        curr = next;
        policy_id = curr;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        *next++ = '\0';
        curr = next;
        if (!strncmp(curr, "NULL", 4))
            scan_id = -1;
        else
            scan_id = strtol(curr,NULL,10);

        if (result = wdb_sca_check_delete_distinct(wdb,policy_id,scan_id), result < 0) {
            mdebug1("Cannot delete Security Configuration Assessment checks.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete Security Configuration Assessment checks.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
            wdb_sca_check_compliances_delete(wdb);
            wdb_sca_check_rules_delete(wdb);
        }

        return result;

    } else if (strcmp(curr, "delete_check") == 0) {

        char *policy_id;

        curr = next;
        policy_id = curr;

        if (result = wdb_sca_check_delete(wdb,policy_id), result < 0) {
            mdebug1("Cannot delete Security Configuration Assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete Security Configuration Assessment check information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
            wdb_sca_check_compliances_delete(wdb);
            wdb_sca_check_rules_delete(wdb);
        }

        return result;
    } else if (strcmp(curr, "query_results") == 0) {

        char * policy_id;
        char result_found[OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE] = {0};

        curr = next;
        policy_id = curr;

        result = wdb_sca_checks_get_result(wdb, policy_id, result_found);

        switch (result) {
            case 0:
                snprintf(output, OS_MAXSTR + 1, "ok not found");
                break;
            case 1:
                snprintf(output, OS_MAXSTR + 1, "ok found %s",result_found);
                break;
            default:
                mdebug1("Cannot query Security Configuration Assessment.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot query Security Configuration Assessment global");
        }

        return result;
    } else if (strcmp(curr, "query_scan") == 0) {

        char *policy_id;
        char result_found[OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE] = {0};

        curr = next;
        policy_id = curr;

        result = wdb_sca_scan_find(wdb, policy_id, result_found);

        switch (result) {
            case 0:
                snprintf(output, OS_MAXSTR + 1, "ok not found");
                break;
            case 1:
                snprintf(output, OS_MAXSTR + 1, "ok found %s",result_found);
                break;
            default:
                mdebug1("Cannot query Security Configuration Assessment.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot query Security Configuration Assessment scan");
        }

        return result;
    } else if (strcmp(curr, "query_policies") == 0) {

        char result_found[OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE] = {0};

        result = wdb_sca_policy_get_id(wdb, result_found);

        switch (result) {
            case 0:
                snprintf(output, OS_MAXSTR + 1, "ok not found");
                break;
            case 1:
                snprintf(output, OS_MAXSTR + 1, "ok found %s",result_found);
                break;
            default:
                mdebug1("Cannot query Security Configuration Assessment.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot query Security Configuration Assessment scan");
        }

        return result;
    } else if (strcmp(curr, "query_policy") == 0) {

        char *policy;
        char result_found[OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE] = {0};

        curr = next;
        policy = curr;

        result = wdb_sca_policy_find(wdb, policy, result_found);

        switch (result) {
            case 0:
                snprintf(output, OS_MAXSTR + 1, "ok not found");
                break;
            case 1:
                snprintf(output, OS_MAXSTR + 1, "ok found %s",result_found);
                break;
            default:
                mdebug1("Cannot query Security Configuration Assessment.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot query policy scan");
        }

        return result;
    } else if (strcmp(curr, "query_policy_sha256") == 0) {

        char *policy;
        char result_found[OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE] = {0};

        curr = next;
        policy = curr;

        result = wdb_sca_policy_sha256(wdb, policy, result_found);
        switch (result) {
            case 0:
                snprintf(output, OS_MAXSTR + 1, "ok not found");
                break;
            case 1:
                snprintf(output, OS_MAXSTR + 1, "ok found %s", result_found);
                break;
            default:
                mdebug1("Cannot query Security Configuration Assessment.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot query policy scan");
        }

        return result;
    } else if (strcmp(curr, "insert_policy") == 0) {

        char *name;
        char *file;
        char *id;
        char *description;
        char *references;
        char *hash_file;

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        name = curr;
        *next++ = '\0';

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        file = curr;
        *next++ = '\0';

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        id = curr;
        *next++ = '\0';

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        description = curr;
        *next++ = '\0';

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        references = curr;
        *next++ = '\0';

        hash_file = next;
        if (result = wdb_sca_policy_info_save(wdb,name,file,id,description,references,hash_file), result < 0) {
            mdebug1("Cannot save Security Configuration Assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Security Configuration Assessment global information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    } else if (strcmp(curr, "insert_rules") == 0){

        int id_check;
        char *type;
        char *rule;

         curr = next;

         if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return -1;
        }

         id_check = strtol(curr,NULL,10);
        *next++ = '\0';

         curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

         type = curr;
        *next++ = '\0';

         rule = next;
        if (result = wdb_sca_rules_save(wdb,id_check,type,rule), result < 0) {
            mdebug1("Cannot save configuration assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save configuration assessment global information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

         return result;

    } else if (strcmp(curr, "insert_compliance") == 0) {

        int id_check;
        char *key;
        char *value;

        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        id_check = strtol(curr,NULL,10);
        *next++ = '\0';

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        key = curr;
        *next++ = '\0';

        value = next;
        if (result = wdb_sca_compliance_save(wdb,id_check,key,value), result < 0) {
            mdebug1("Cannot save configuration assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save configuration assessment global information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "insert_scan_info") == 0) {

        curr = next;

        int pm_start_scan;
        int pm_end_scan;
        int scan_id;
        char * policy_id;
        int pass;
        int fail;
        int invalid;
        int total_checks;
        int score;
        char *hash;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            pm_start_scan = -1;
        else
            pm_start_scan = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            pm_end_scan = -1;
        else
            pm_end_scan = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            scan_id = -1;
        else
            scan_id = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        policy_id = curr;
        *next++ = '\0';

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            pass = -1;
        else
            pass = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            fail = -1;
        else
            fail = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            invalid = -1;
        else
            invalid = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            total_checks = -1;
        else
            total_checks = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            score = -1;
        else
            score = strtol(curr,NULL,10);

        *next++ = '\0';

        hash = next;
        if (result = wdb_sca_scan_info_save(wdb,pm_start_scan,pm_end_scan,scan_id,policy_id,pass,fail,invalid,total_checks,score,hash), result < 0) {
            mdebug1("Cannot save configuration assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save configuration assessment information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "update_scan_info") == 0) {
        curr = next;

        char *module;
        int pm_end_scan;


        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        module = curr;
        *next++ = '\0';

        if (!strcmp(module, "NULL"))
            module = NULL;

        *next++ = '\0';
        curr = next;

        if (!strncmp(curr, "NULL", 4))
            pm_end_scan = -1;
        else
            pm_end_scan = strtol(curr,NULL,10);

        if (result = wdb_sca_scan_info_update(wdb, module,pm_end_scan), result < 0) {
            mdebug1("Cannot save configuration assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save configuration assessment information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "update_scan_info_start") == 0) {

        char *policy_id;
        int pm_start_scan;
        int pm_end_scan;
        int scan_id;
        int pass;
        int fail;
        int invalid;
        int total_checks;
        int score;
        char *hash;

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        policy_id = curr;

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strcmp(policy_id, "NULL"))
            policy_id = NULL;

        *next++ = '\0';
        curr = next;

        if (!strncmp(curr, "NULL", 4))
            pm_start_scan = -1;
        else
            pm_start_scan = strtol(curr,NULL,10);

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            pm_end_scan = -1;
        else
            pm_end_scan = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            scan_id = -1;
        else
            scan_id = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            pass = -1;
        else
            pass = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            fail = -1;
        else
            fail = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            invalid = -1;
        else
            invalid = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            total_checks = -1;
        else
            total_checks = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            score = -1;
        else
            score = strtol(curr,NULL,10);

        *next++ = '\0';

        hash = next;

        if (result = wdb_sca_scan_info_update_start(wdb, policy_id,pm_start_scan,pm_end_scan,scan_id,pass,fail,invalid,total_checks,score,hash), result < 0) {
            mdebug1("Cannot save configuration assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save configuration assessment information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else {
        mdebug1("Invalid configuration assessment query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Rootcheck query syntax, near '%.32s'", curr);
        return -1;
    }
}

int wdb_parse_netinfo(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    char * scan_time;
    char * name;
    char * adapter;
    char * type;
    char * state;
    int mtu;
    char * mac;
    long tx_packets;
    long rx_packets;
    long tx_bytes;
    long rx_bytes;
    long tx_errors;
    long rx_errors;
    long tx_dropped;
    long rx_dropped;
    long result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid Network query syntax.");
        mdebug2("Network query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", input);
        return -1;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(scan_id, "NULL"))
            scan_id = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_time = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %s", scan_time);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", scan_time);
            return -1;
        }

        if (!strcmp(scan_time, "NULL"))
            scan_time = NULL;

        name = curr;
        *next++ = '\0';
        curr = next;


        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %s", name);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", name);
            return -1;
        }

        if (!strcmp(name, "NULL"))
            name = NULL;

        adapter = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %s", adapter);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", adapter);
            return -1;
        }

        if (!strcmp(adapter, "NULL"))
            adapter = NULL;

        type = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %s", type);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", type);
            return -1;
        }

        if (!strcmp(type, "NULL"))
            type = NULL;

        state = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %s", state);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", state);
            return -1;
        }

        if (!strcmp(state, "NULL"))
            state = NULL;

        if (!strncmp(curr, "NULL", 4))
            mtu = -1;
        else
            mtu = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %d", mtu);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return -1;
        }

        mac = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %s", mac);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", mac);
            return -1;
        }

        if (!strcmp(mac, "NULL"))
            mac = NULL;

        if (!strncmp(curr, "NULL", 4))
            tx_packets = -1;
        else
            tx_packets = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %ld", tx_packets);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            rx_packets = -1;
        else
            rx_packets = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %ld", rx_packets);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            tx_bytes = -1;
        else
            tx_bytes = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %ld", tx_bytes);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            rx_bytes = -1;
        else
            rx_bytes = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %ld", rx_bytes);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            tx_errors = -1;
        else
            tx_errors = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %ld", tx_errors);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            rx_errors = -1;
        else
            rx_errors = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %ld", rx_errors);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            tx_dropped = -1;
        else
            tx_dropped = strtol(curr,NULL,10);

        *next++ = '\0';
        if (!strncmp(next, "NULL", 4))
            rx_dropped = -1;
        else
            rx_dropped = strtol(next,NULL,10);

        if (result = wdb_netinfo_save(wdb, scan_id, scan_time, name, adapter, type, state, mtu, mac, tx_packets, rx_packets, tx_bytes, rx_bytes, tx_errors, rx_errors, tx_dropped, rx_dropped), result < 0) {
            mdebug1("Cannot save Network information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Network information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    } else if (strcmp(curr, "del") == 0) {

        if (!strcmp(next, "NULL"))
            scan_id = NULL;
        else
            scan_id = next;

        if (result = wdb_netinfo_delete(wdb, scan_id), result < 0) {
            mdebug1("Cannot delete old network information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete old network information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    } else {
        mdebug1("Invalid netinfo query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid netinfo query syntax, near '%.32s'", curr);
        return -1;
    }
}

int wdb_parse_netproto(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    char * iface;
    int type;
    char * gateway;
    int metric;
    char * dhcp;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid netproto query syntax.");
        mdebug2("netproto query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid netproto query syntax, near '%.32s'", input);
        return -1;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid netproto query syntax.");
            mdebug2("netproto query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid netproto query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(scan_id, "NULL"))
            scan_id = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid netproto query syntax.");
            mdebug2("netproto query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid netproto query syntax, near '%.32s'", curr);
            return -1;
        }

        iface = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid netproto query syntax.");
            mdebug2("netproto query: %s", iface);
            snprintf(output, OS_MAXSTR + 1, "err Invalid netproto query syntax, near '%.32s'", iface);
            return -1;
        }

        if (!strcmp(iface, "NULL"))
            iface = NULL;

        type = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %d", type);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return -1;
        }

        gateway = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid netproto query syntax.");
            mdebug2("netproto query: %s", gateway);
            snprintf(output, OS_MAXSTR + 1, "err Invalid netproto query syntax, near '%.32s'", gateway);
            return -1;
        }

        if (!strcmp(gateway, "NULL"))
            gateway = NULL;

        dhcp = curr;
        *next++ = '\0';

        if (!strcmp(dhcp, "NULL"))
            dhcp = NULL;

        if (!strncmp(next, "NULL", 4))
            metric = -1;
        else
            metric = strtol(next,NULL,10);

        if (result = wdb_netproto_save(wdb, scan_id, iface, type, gateway, dhcp, metric), result < 0) {
            mdebug1("Cannot save netproto information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save netproto information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    } else {
        mdebug1("Invalid netproto query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid netproto query syntax, near '%.32s'", curr);
        return -1;
    }
}

int wdb_parse_netaddr(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    int proto;
    char * address;
    char * netmask;
    char * broadcast;
    char * iface;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid netaddr query syntax.");
        mdebug2("netaddr query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid netaddr query syntax, near '%.32s'", input);
        return -1;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid netaddr query syntax.");
            mdebug2("netaddr query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid netaddr query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(scan_id, "NULL"))
            scan_id = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid netaddr query syntax.");
            mdebug2("netaddr query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid netaddr query syntax, near '%.32s'", curr);
            return -1;
        }

        iface = curr;
		*next++ = '\0';
		curr = next;

		if (next = strchr(curr, '|'), !next) {
			mdebug1("Invalid netaddr query syntax.");
			mdebug2("netaddr query: %s", iface);
			snprintf(output, OS_MAXSTR + 1, "err Invalid netaddr query syntax, near '%.32s'", iface);
			return -1;
		}

		if (!strcmp(iface, "NULL"))
			iface = NULL;

        proto = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %d", proto);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return -1;
        }

        address = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid netaddr query syntax.");
            mdebug2("netaddr query: %s", address);
            snprintf(output, OS_MAXSTR + 1, "err Invalid netaddr query syntax, near '%.32s'", address);
            return -1;
        }

        if (!strcmp(address, "NULL"))
            address = NULL;

        netmask = curr;
        *next++ = '\0';

        if (!strcmp(netmask, "NULL"))
            netmask = NULL;

        if (!strcmp(next, "NULL"))
            broadcast = NULL;
        else
            broadcast = next;

        if (result = wdb_netaddr_save(wdb, scan_id, iface, proto, address, netmask, broadcast), result < 0) {
            mdebug1("Cannot save netaddr information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save netaddr information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    } else {
        mdebug1("Invalid netaddr query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid netaddr query syntax, near '%.32s'", curr);
        return -1;
    }
}

int wdb_parse_osinfo(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    char * scan_time;
    char * hostname;
    char * architecture;
    char * os_name;
    char * os_version;
    char * os_codename;
    char * os_major;
    char * os_minor;
    char * os_build;
    char * os_platform;
    char * sysname;
    char * release;
    char * version;
    char * os_release;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid OS info query syntax.");
        mdebug2("OS info query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", input);
        return -1;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(scan_id, "NULL"))
            scan_id = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_time = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", scan_time);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", scan_time);
            return -1;
        }

        if (!strcmp(scan_time, "NULL"))
            scan_time = NULL;

        hostname = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", hostname);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", hostname);
            return -1;
        }

        if (!strcmp(hostname, "NULL"))
            hostname = NULL;

        architecture = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", architecture);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", architecture);
            return -1;
        }

        if (!strcmp(architecture, "NULL"))
            architecture = NULL;

        os_name = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", os_name);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", os_name);
            return -1;
        }

        if (!strcmp(os_name, "NULL"))
            os_name = NULL;

        os_version = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", os_version);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", os_version);
            return -1;
        }

        if (!strcmp(os_version, "NULL"))
            os_version = NULL;

        os_codename = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", os_codename);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", os_codename);
            return -1;
        }

        if (!strcmp(os_codename, "NULL"))
            os_codename = NULL;

        os_major = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", os_major);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", os_major);
            return -1;
        }

        if (!strcmp(os_major, "NULL"))
            os_major = NULL;

        os_minor = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", os_minor);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", os_minor);
            return -1;
        }

        if (!strcmp(os_minor, "NULL"))
            os_minor = NULL;

        os_build = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", os_build);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", os_build);
            return -1;
        }

        if (!strcmp(os_build, "NULL"))
            os_build = NULL;

        os_platform = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", os_platform);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", os_platform);
            return -1;
        }

        if (!strcmp(os_platform, "NULL"))
            os_platform = NULL;

        sysname = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", sysname);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", sysname);
            return -1;
        }

        if (!strcmp(sysname, "NULL"))
            sysname = NULL;

        release = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(release, "NULL"))
            release = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid OS info query syntax.");
            mdebug2("OS info query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", curr);
            return -1;
        }

        version = curr;
        *next++ = '\0';

        if (!strcmp(version, "NULL"))
            version = NULL;

        if (!strcmp(next, "NULL"))
            os_release = NULL;
        else
            os_release = next;

        if (result = wdb_osinfo_save(wdb, scan_id, scan_time, hostname, architecture, os_name, os_version, os_codename, os_major, os_minor, os_build, os_platform, sysname, release, version, os_release), result < 0) {
            mdebug1("Cannot save OS information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save OS information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else {
        mdebug1("Invalid OS info query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", curr);
        return -1;
    }
}

int wdb_parse_hardware(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    char * scan_time;
    char * serial;
    char * cpu_name;
    int cpu_cores;
    char * cpu_mhz;
    uint64_t ram_total;
    uint64_t ram_free;
    int ram_usage;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid HW info query syntax.");
        mdebug2("HW info query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", input);
        return -1;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid HW info query syntax.");
            mdebug2("HW info query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid HW info query syntax.");
            mdebug2("HW info query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strcmp(scan_id, "NULL"))
            scan_id = NULL;

        scan_time = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid HW info query syntax.");
            mdebug2("HW info query: %s", scan_time);
            snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", scan_time);
            return -1;
        }

        if (!strcmp(scan_time, "NULL"))
            scan_time = NULL;

        serial = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid HW info query syntax.");
            mdebug2("HW info query: %s", serial);
            snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", serial);
            return -1;
        }

        if (!strcmp(serial, "NULL"))
            serial = NULL;

        cpu_name = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid HW info query syntax.");
            mdebug2("HW info query: %s", cpu_name);
            snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", cpu_name);
            return -1;
        }

        if (!strcmp(cpu_name, "NULL"))
            cpu_name = NULL;

        cpu_cores = strtol(curr,NULL,10);
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid HW info query syntax.");
            mdebug2("HW info query: %d", cpu_cores);
            snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", curr);
            return -1;
        }

        cpu_mhz = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid HW info query syntax.");
            mdebug2("HW info query: %s", cpu_mhz);
            snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strcmp(cpu_mhz, "NULL"))
            cpu_mhz = NULL;

        ram_total = strtol(curr,NULL,10);
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid HW info query syntax.");
            mdebug2("HW info query: %" PRIu64, ram_total);
            snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", curr);
            return -1;
        }

        ram_free = strtol(curr,NULL,10);
        *next++ = '\0';
        ram_usage = strtol(next,NULL,10);

        if (result = wdb_hardware_save(wdb, scan_id, scan_time, serial, cpu_name, cpu_cores, cpu_mhz, ram_total, ram_free, ram_usage), result < 0) {
            mdebug1("wdb_parse_hardware(): Cannot save HW information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save HW information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else {
        mdebug1("Invalid HW info query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", curr);
        return -1;
    }
}

int wdb_parse_ports(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    char * scan_time;
    char * protocol;
    char * local_ip;
    int local_port;
    char * remote_ip;
    int remote_port;
    int tx_queue;
    int rx_queue;
    int inode;
    char * state;
    int pid;
    char * process;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid Port query syntax.");
        mdebug2("Port query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", input);
        return -1;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(scan_id, "NULL"))
            scan_id = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_time = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %s", scan_time);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", scan_time);
            return -1;
        }

        if (!strcmp(scan_time, "NULL"))
            scan_time = NULL;

        protocol = curr;
        *next++ = '\0';
        curr = next;


        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %s", protocol);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", protocol);
            return -1;
        }

        if (!strcmp(protocol, "NULL"))
            protocol = NULL;

        local_ip = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %s", local_ip);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", local_ip);
            return -1;
        }

        if (!strcmp(local_ip, "NULL"))
            local_ip = NULL;

        if (!strncmp(curr, "NULL", 4))
            local_port = -1;
        else
            local_port = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %d", local_port);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", curr);
            return -1;
        }

        remote_ip = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %s", remote_ip);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", remote_ip);
            return -1;
        }

        if (!strcmp(remote_ip, "NULL"))
            remote_ip = NULL;

        if (!strncmp(curr, "NULL", 4))
            remote_port = -1;
        else
            remote_port = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %d", remote_port);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            tx_queue = -1;
        else
            tx_queue = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %d", tx_queue);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            rx_queue = -1;
        else
            rx_queue = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %d", rx_queue);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            inode = -1;
        else
            inode = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %d", inode);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", curr);
            return -1;
        }

        state = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %s", state);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", state);
            return -1;
        }

        if (!strcmp(state, "NULL"))
            state = NULL;

        if (!strncmp(curr, "NULL", 4))
            pid = -1;
        else
            pid = strtol(curr,NULL,10);

        *next++ = '\0';
        if (!strncmp(next, "NULL", 4))
            process = NULL;
        else
            process = next;

        if (result = wdb_port_save(wdb, scan_id, scan_time, protocol, local_ip, local_port, remote_ip, remote_port, tx_queue, rx_queue, inode, state, pid, process), result < 0) {
            mdebug1("Cannot save Port information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Port information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "del") == 0) {

        if (!strcmp(next, "NULL"))
            scan_id = NULL;
        else
            scan_id = next;

        if (result = wdb_port_delete(wdb, scan_id), result < 0) {
            mdebug1("Cannot delete old Port information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete old Port information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    } else {
        mdebug1("Invalid Port query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", curr);
        return -1;
    }
}


int wdb_parse_packages(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    char * scan_time;
    char * format;
    char * name;
    char * priority;
    char * section;
    long size;
    char * vendor;
    char * install_time;
    char * version;
    char * architecture;
    char * multiarch;
    char * source;
    char * description;
    char * location;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid Package info query syntax.");
        mdebug2("Package info query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Package info query syntax, near '%.32s'", input);
        return -1;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Package info query syntax.");
            mdebug2("Package info query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Package info query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(scan_id, "NULL"))
            scan_id = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Package info query syntax.");
            mdebug2("Package info query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Package info query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_time = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Package info query syntax.");
            mdebug2("Package info query: %s", scan_time);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Package info query syntax, near '%.32s'", scan_time);
            return -1;
        }

        if (!strcmp(scan_time, "NULL"))
            scan_time = NULL;

        format = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Package info query syntax.");
            mdebug2("Package info query: %s", format);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Package info query syntax, near '%.32s'", format);
            return -1;
        }

        if (!strcmp(format, "NULL"))
            format = NULL;

        name = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Package info query syntax.");
            mdebug2("Package info query: %s", name);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Package info query syntax, near '%.32s'", name);
            return -1;
        }

        if (!strcmp(name, "NULL"))
            name = NULL;

        priority = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Package info query syntax.");
            mdebug2("Package info query: %s", priority);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Package info query syntax, near '%.32s'", priority);
            return -1;
        }

        if (!strcmp(priority, "NULL"))
            priority = NULL;

        section = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Package info query syntax.");
            mdebug2("Package info query: %s", section);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Package info query syntax, near '%.32s'", section);
            return -1;
        }

        if (!strcmp(section, "NULL"))
            section = NULL;

        if (!strncmp(curr, "NULL", 4))
            size = -1;
        else
            size = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Package query syntax.");
            mdebug2("Package query: %ld", size);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Package query syntax, near '%.32s'", curr);
            return -1;
        }

        vendor = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Package info query syntax.");
            mdebug2("Package info query: %s", vendor);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Package info query syntax, near '%.32s'", vendor);
            return -1;
        }

        if (!strcmp(vendor, "NULL"))
            vendor = NULL;

        install_time = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Package info query syntax.");
            mdebug2("Package info query: %s", install_time);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Package info query syntax, near '%.32s'", install_time);
            return -1;
        }

        if (!strcmp(install_time, "NULL"))
            install_time = NULL;

        version = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Package info query syntax.");
            mdebug2("Package info query: %s", version);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Package info query syntax, near '%.32s'", version);
            return -1;
        }

        if (!strcmp(version, "NULL"))
            version = NULL;

        architecture = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Package info query syntax.");
            mdebug2("Package info query: %s", architecture);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Package info query syntax, near '%.32s'", architecture);
            return -1;
        }

        if (!strcmp(architecture, "NULL"))
            architecture = NULL;

        multiarch = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Package info query syntax.");
            mdebug2("Package info query: %s", multiarch);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Package info query syntax, near '%.32s'", multiarch);
            return -1;
        }

        if (!strcmp(multiarch, "NULL"))
            multiarch = NULL;

        source = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Package info query syntax.");
            mdebug2("Package info query: %s", source);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Package info query syntax, near '%.32s'", source);
            return -1;
        }

        if (!strcmp(source, "NULL"))
            source = NULL;

        description = curr;
        *next++ = '\0';

        if (!strcmp(description, "NULL"))
            description = NULL;

        if (!strcmp(next, "NULL"))
            location = NULL;
        else
            location = next;

        if (result = wdb_package_save(wdb, scan_id, scan_time, format, name, priority, section, size, vendor, install_time, version, architecture, multiarch, source, description, location), result < 0) {
            mdebug1("Cannot save Package information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Package information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    } else if (strcmp(curr, "del") == 0) {

        if (!strcmp(next, "NULL"))
            scan_id = NULL;
        else
            scan_id = next;

        if (result = wdb_package_update(wdb, scan_id), result < 0) {
            mdebug1("Cannot update scanned packages.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save scanned packages before delete old Package information.");
        }

        if (result = wdb_package_delete(wdb, scan_id), result < 0) {
            mdebug1("Cannot delete old Package information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete old Package information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    } else {
        mdebug1("Invalid Package info query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Package info query syntax, near '%.32s'", curr);
        return -1;
    }
}

int wdb_parse_hotfixes(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    char * scan_time;
    char *hotfix;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid Hotfix info query syntax.");
        mdebug2("Hotfix info query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Hotfix info query syntax, near '%.32s'", input);
        return -1;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Hotfix info query syntax.");
            mdebug2("Hotfix info query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Hotfix info query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Hotfix info query syntax.");
            mdebug2("Hotfix info query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Hotfix info query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_time = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Hotfix info query syntax.");
            mdebug2("Hotfix info query: %s", scan_time);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Hotfix info query syntax, near '%.32s'", scan_time);
            return -1;
        }

        hotfix = curr;
        *next++ = '\0';

        if (result = wdb_hotfix_save(wdb, scan_id, scan_time, hotfix), result < 0) {
            mdebug1("Cannot save Hotfix information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Hotfix information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "del") == 0) {

        if (!strcmp(next, "NULL"))
            scan_id = NULL;
        else
            scan_id = next;

        if (result = wdb_hotfix_delete(wdb, scan_id), result < 0) {
            mdebug1("Cannot delete old Process information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete old Hotfix information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        wdb_set_hotfix_metadata(wdb, scan_id);

        return result;

    } else {
        mdebug1("Invalid Hotfix info query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Hotfix info query syntax, near '%.32s'", curr);
        return -1;
    }
}

int wdb_parse_processes(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    char * scan_time;
    int pid, ppid, utime, stime, priority, nice, size, vm_size, resident, share, start_time, pgrp, session, nlwp, tgid, tty, processor;
    char * name;
    char * state;
    char * cmd;
    char * argvs;
    char * euser;
    char * ruser;
    char * suser;
    char * egroup;
    char * rgroup;
    char * sgroup;
    char * fgroup;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid Process query syntax.");
        mdebug2("Process query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", input);
        return -1;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(scan_id, "NULL"))
            scan_id = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_time = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", scan_time);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", scan_time);
            return -1;
        }

        if (!strcmp(scan_time, "NULL"))
            scan_time = NULL;

        if (!strncmp(curr, "NULL", 4))
            pid = -1;
        else
            pid = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", pid);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return -1;
        }

        name = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", name);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", name);
            return -1;
        }

        if (!strcmp(name, "NULL"))
            name = NULL;

        state = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", state);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", state);
            return -1;
        }

        if (!strcmp(state, "NULL"))
            state = NULL;

        if (!strncmp(curr, "NULL", 4))
            ppid = -1;
        else
            ppid = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", ppid);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            utime = -1;
        else
            utime = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", utime);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            stime = -1;
        else
            stime = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", stime);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return -1;
        }

        cmd = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", cmd);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", cmd);
            return -1;
        }

        if (!strcmp(cmd, "NULL"))
            cmd = NULL;

        argvs = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", argvs);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", argvs);
            return -1;
        }

        if (!strcmp(argvs, "NULL"))
            argvs = NULL;

        euser = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", euser);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", euser);
            return -1;
        }

        if (!strcmp(euser, "NULL"))
            euser = NULL;

        ruser = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", ruser);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", ruser);
            return -1;
        }

        if (!strcmp(ruser, "NULL"))
            ruser = NULL;

        suser = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", suser);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", suser);
            return -1;
        }

        if (!strcmp(suser, "NULL"))
            suser = NULL;

        egroup = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", egroup);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", egroup);
            return -1;
        }

        if (!strcmp(egroup, "NULL"))
            egroup = NULL;

        rgroup = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", rgroup);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", rgroup);
            return -1;
        }

        if (!strcmp(rgroup, "NULL"))
            rgroup = NULL;

        sgroup = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", sgroup);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", sgroup);
            return -1;
        }

        if (!strcmp(sgroup, "NULL"))
            sgroup = NULL;

        fgroup = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", fgroup);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", fgroup);
            return -1;
        }

        if (!strcmp(fgroup, "NULL"))
            fgroup = NULL;

        if (!strncmp(curr, "NULL", 4))
            priority = -1;
        else
            priority = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", priority);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            nice = 0;
        else
            nice = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", nice);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            size = -1;
        else
            size = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", size);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            vm_size = -1;
        else
            vm_size = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", vm_size);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            resident = -1;
        else
            resident = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", resident);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            share = -1;
        else
            share = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", share);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            start_time = -1;
        else
            start_time = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", start_time);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            pgrp = -1;
        else
            pgrp = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", pgrp);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            session = -1;
        else
            session = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", session);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            nlwp = -1;
        else
            nlwp = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", nlwp);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            tgid = -1;
        else
            tgid = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", tgid);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            tty = -1;
        else
            tty = strtol(curr,NULL,10);

        *next++ = '\0';
        if (!strncmp(next, "NULL", 4))
            processor = -1;
        else
            processor = strtol(next,NULL,10);

        if (result = wdb_process_save(wdb, scan_id, scan_time, pid, name, state, ppid, utime, stime, cmd, argvs, euser, ruser, suser, egroup, rgroup, sgroup, fgroup, priority, nice, size, vm_size, resident, share, start_time, pgrp, session, nlwp, tgid, tty, processor), result < 0) {
            mdebug1("Cannot save Process information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Process information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "del") == 0) {

        if (!strcmp(next, "NULL"))
            scan_id = NULL;
        else
            scan_id = next;

        if (result = wdb_process_delete(wdb, scan_id), result < 0) {
            mdebug1("Cannot delete old Process information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete old Process information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    } else {
        mdebug1("Invalid Process query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
        return -1;
    }
}

int wdb_parse_ciscat(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    char * scan_time;
    char * benchmark;
    char * profile;
    int pass, fail, error, notchecked, unknown, score;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid CISCAT query syntax.");
        mdebug2("CISCAT query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", input);
        return -1;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(scan_id, "NULL"))
            scan_id = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", curr);
            return -1;
        }

        scan_time = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %s", scan_time);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", scan_time);
            return -1;
        }

        if (!strcmp(scan_time, "NULL"))
            scan_time = NULL;

        benchmark = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %s", benchmark);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", benchmark);
            return -1;
        }

        if (!strcmp(benchmark, "NULL"))
            benchmark = NULL;

        profile = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %s", profile);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", profile);
            return -1;
        }

        if (!strcmp(profile, "NULL"))
            profile = NULL;

        if (!strncmp(curr, "NULL", 4))
            pass = -1;
        else
            pass = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %d", pass);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            fail = -1;
        else
            fail = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %d", fail);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            error = -1;
        else
            error = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %d", error);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            notchecked = -1;
        else
            notchecked = strtol(curr,NULL,10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %d", notchecked);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", curr);
            return -1;
        }

        if (!strncmp(curr, "NULL", 4))
            unknown = -1;
        else
            unknown = strtol(curr,NULL,10);

        *next++ = '\0';
        if (!strncmp(next, "NULL", 4))
            score = -1;
        else
            score = strtol(next,NULL,10);

        if (result = wdb_ciscat_save(wdb, scan_id, scan_time, benchmark, profile, pass, fail, error, notchecked, unknown, score), result < 0) {
            mdebug1("Cannot save CISCAT information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save CISCAT information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else {
        mdebug1("Invalid CISCAT query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", curr);
        return -1;
    }
}

// Function to get values from MITRE database

int wdb_parse_mitre_get(wdb_t * wdb, char * input, char * output) {
    char * next;
    char * id;
    int result;

    if (next = wstr_chr(input, ' '), !next) {
        mdebug1("Invalid DB query syntax.");
        mdebug2("DB query error near: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", input);
        return -1;
    }
    *next++ = '\0';

    if (strcmp(input, "name") == 0) {
        if (!next) {
            mdebug1("Mitre DB Invalid DB query syntax.");
            mdebug2("Mitre DB query error near: %s", input);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", input);
            return -1;
        } else {
            id = next;
            char result_found[OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE] = {0};
            result = wdb_mitre_name_get(wdb, id, result_found);
            switch (result) {
                case 0:
                    snprintf(output, OS_MAXSTR + 1, "err not found");
                    break;
                case 1:
                    snprintf(output, OS_MAXSTR + 1, "ok %s", result_found);
                    break;
                default:
                    mdebug1("Cannot query MITRE technique's name.");
                    snprintf(output, OS_MAXSTR + 1, "err Cannot query name of MITRE technique '%s'", id);
            }

            return result;
        }
    } else {
        mdebug1("Invalid DB query syntax.");
        mdebug2("DB query error near: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", input);
        return -1;
    }
}

int wdb_parse_global_insert_agent(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_id = NULL;
    cJSON *j_name = NULL;
    cJSON *j_ip = NULL;
    cJSON *j_register_ip = NULL;
    cJSON *j_internal_key = NULL;
    cJSON *j_group = NULL;
    cJSON *j_date_add = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when inserting agent.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id = cJSON_GetObjectItem(agent_data, "id");
        j_name = cJSON_GetObjectItem(agent_data, "name");
        j_ip = cJSON_GetObjectItem(agent_data, "ip");
        j_register_ip = cJSON_GetObjectItem(agent_data, "register_ip");
        j_internal_key = cJSON_GetObjectItem(agent_data, "internal_key");
        j_group = cJSON_GetObjectItem(agent_data, "group");
        j_date_add = cJSON_GetObjectItem(agent_data, "date_add");

        // These are the only constraints defined in the database for this
        // set of parameters. All the other parameters could be NULL.
        if (cJSON_IsNumber(j_id) &&
            cJSON_IsString(j_name) && j_name->valuestring &&
            cJSON_IsNumber(j_date_add)) {

            // Getting each field
            int id = j_id->valueint;
            char* name = j_name->valuestring;
            char* ip = cJSON_IsString(j_ip) ? j_ip->valuestring : NULL;
            char* register_ip = cJSON_IsString(j_register_ip) ? j_register_ip->valuestring : NULL;
            char* internal_key = cJSON_IsString(j_internal_key) ? j_internal_key->valuestring : NULL;
            char* group = cJSON_IsString(j_group) ? j_group->valuestring : NULL;
            int date_add = j_date_add->valueint;

            if (OS_SUCCESS != wdb_global_insert_agent(wdb, id, name, ip, register_ip, internal_key, group, date_add)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                return OS_INVALID;
            }
        } else {
            mdebug1("Global DB Invalid JSON data when inserting agent. Not compliant with constraints defined in the database.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    snprintf(output, OS_MAXSTR + 1, "ok");
    cJSON_Delete(agent_data);

    return OS_SUCCESS;
}

int wdb_parse_global_update_agent_name(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_id = NULL;
    cJSON *j_name = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when updating agent name.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id = cJSON_GetObjectItem(agent_data, "id");
        j_name = cJSON_GetObjectItem(agent_data, "name");

        if (cJSON_IsNumber(j_id) &&
            cJSON_IsString(j_name) && j_name->valuestring) {

            // Getting each field
            int id = j_id->valueint;
            char* name = j_name->valuestring;

            if (OS_SUCCESS != wdb_global_update_agent_name(wdb, id, name)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                return OS_INVALID;
            }
        } else {
            mdebug1("Global DB Invalid JSON data when updating agent name.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    snprintf(output, OS_MAXSTR + 1, "ok");
    cJSON_Delete(agent_data);

    return OS_SUCCESS;
}

int wdb_parse_global_update_agent_data(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_id = NULL;
    cJSON *j_os_name = NULL;
    cJSON *j_os_version = NULL;
    cJSON *j_os_major = NULL;
    cJSON *j_os_minor = NULL;
    cJSON *j_os_codename = NULL;
    cJSON *j_os_platform = NULL;
    cJSON *j_os_build = NULL;
    cJSON *j_os_uname = NULL;
    cJSON *j_os_arch = NULL;
    cJSON *j_version = NULL;
    cJSON *j_config_sum = NULL;
    cJSON *j_merged_sum = NULL;
    cJSON *j_manager_host = NULL;
    cJSON *j_node_name = NULL;
    cJSON *j_agent_ip = NULL;
    cJSON *j_sync_status = NULL;
    cJSON *j_labels = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when updating agent version.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id = cJSON_GetObjectItem(agent_data, "id");
        j_os_name = cJSON_GetObjectItem(agent_data, "os_name");
        j_os_version = cJSON_GetObjectItem(agent_data, "os_version");
        j_os_major = cJSON_GetObjectItem(agent_data, "os_major");
        j_os_minor = cJSON_GetObjectItem(agent_data, "os_minor");
        j_os_codename = cJSON_GetObjectItem(agent_data, "os_codename");
        j_os_platform = cJSON_GetObjectItem(agent_data, "os_platform");
        j_os_build = cJSON_GetObjectItem(agent_data, "os_build");
        j_os_uname = cJSON_GetObjectItem(agent_data, "os_uname");
        j_os_arch = cJSON_GetObjectItem(agent_data, "os_arch");
        j_version = cJSON_GetObjectItem(agent_data, "version");
        j_config_sum = cJSON_GetObjectItem(agent_data, "config_sum");
        j_merged_sum = cJSON_GetObjectItem(agent_data, "merged_sum");
        j_manager_host = cJSON_GetObjectItem(agent_data, "manager_host");
        j_node_name = cJSON_GetObjectItem(agent_data, "node_name");
        j_agent_ip = cJSON_GetObjectItem(agent_data, "agent_ip");
        j_sync_status = cJSON_GetObjectItem(agent_data, "sync_status");
        j_labels = cJSON_GetObjectItem(agent_data, "labels");

        if (cJSON_IsNumber(j_id)) {
            // Getting each field
            int id = j_id->valueint;
            char *os_name = cJSON_IsString(j_os_name) ? j_os_name->valuestring : NULL;
            char *os_version = cJSON_IsString(j_os_version) ? j_os_version->valuestring : NULL;
            char *os_major = cJSON_IsString(j_os_major) ? j_os_major->valuestring : NULL;
            char *os_minor = cJSON_IsString(j_os_minor) ? j_os_minor->valuestring : NULL;
            char *os_codename = cJSON_IsString(j_os_codename) ? j_os_codename->valuestring : NULL;
            char *os_platform = cJSON_IsString(j_os_platform) ? j_os_platform->valuestring : NULL;
            char *os_build = cJSON_IsString(j_os_build) ? j_os_build->valuestring : NULL;
            char *os_uname = cJSON_IsString(j_os_uname) ? j_os_uname->valuestring : NULL;
            char *os_arch = cJSON_IsString(j_os_arch) ? j_os_arch->valuestring : NULL;
            char *version = cJSON_IsString(j_version) ? j_version->valuestring : NULL;
            char *config_sum = cJSON_IsString(j_config_sum) ? j_config_sum->valuestring : NULL;
            char *merged_sum = cJSON_IsString(j_merged_sum) ? j_merged_sum->valuestring : NULL;
            char *manager_host = cJSON_IsString(j_manager_host) ? j_manager_host->valuestring : NULL;
            char *node_name = cJSON_IsString(j_node_name) ? j_node_name->valuestring : NULL;
            char *agent_ip = cJSON_IsString(j_agent_ip) ? j_agent_ip->valuestring : NULL;
            char *sync_status = cJSON_IsString(j_sync_status) ? j_sync_status->valuestring : "synced";
            char *labels = cJSON_IsString(j_labels) ? j_labels->valuestring : NULL;

            if (OS_SUCCESS != wdb_global_update_agent_version(wdb, id, os_name, os_version, os_major, os_minor, os_codename,
                                                              os_platform, os_build, os_uname, os_arch, version, config_sum,
                                                              merged_sum, manager_host, node_name, agent_ip, sync_status)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                return OS_INVALID;
            }
            else {
                // We will only add the agent's labels if the agent was successfully added to the database.
                // We dont check for NULL because if NULL, the current labels should be removed.
                // The output string will be filled by the labels setter method.
                char *labels_data = NULL;
                os_calloc(OS_MAXSTR, sizeof(char), labels_data);
                snprintf(labels_data, OS_MAXSTR, "%d", id);
                wm_strcat(&labels_data, labels, ' ');

                int result = wdb_parse_global_set_agent_labels(wdb, labels_data, output);

                cJSON_Delete(agent_data);
                os_free(labels_data);
                return result;
            }
        } else {
            mdebug1("Global DB Invalid JSON data when updating agent version.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    return OS_SUCCESS;
}

int wdb_parse_global_get_agent_labels(wdb_t * wdb, char * input, char * output) {
    int agent_id = 0;
    cJSON *labels = NULL;
    char *out = NULL;

    agent_id = atoi(input);

    if (labels = wdb_global_get_agent_labels(wdb, agent_id), !labels) {
        mdebug1("Error getting agent labels from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agent labels from global.db.");
        return OS_INVALID;
    }

    out = cJSON_PrintUnformatted(labels);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(labels);

    return OS_SUCCESS;
}

int wdb_parse_global_set_agent_labels(wdb_t * wdb, char * input, char * output) {
    char *id = NULL;
    char *label = NULL;
    char *value = NULL;
    char *savedptr = NULL;
    char id_delim[] = { ' ', '\0' };
    char label_delim[] = { '\n', '\0' };

    // The input could be in the next ways
    // "agent_id key1:value1\nkey2:value2" --> In this, case strtok_r finds a space, so we remove the
    //                                         old labels using the agent_id and then insert the new ones.
    // "agent_id" --> In this, case strtok_r finds the NULL character and we just remove the old
    //                labels using the agent_id. The next strtok_r will finalize the execution.
    if (id = strtok_r(input, id_delim, &savedptr), !id) {
        mdebug1("Invalid DB query syntax.");
        mdebug2("DB query error near: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", input);
        return OS_INVALID;
    }

    int agent_id = atoi(id);

    // Removing old labels from the labels table
    if (OS_SUCCESS != wdb_global_del_agent_labels(wdb, agent_id)) {
        mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
        snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    // Parsing the labes string "key1:value1\nkey2:value2"
    for (label = strtok_r(NULL, label_delim, &savedptr); label; label = strtok_r(NULL, label_delim, &savedptr)) {
        if (value = strstr(label, ":"), value) {
            *value = '\0';
            value++;
        }
        else {
            continue;
        }

        // Inserting new labels in the database
        if (OS_SUCCESS != wdb_global_set_agent_label(wdb, agent_id, label, value)) {
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
            snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
            return OS_INVALID;
        }

        value = NULL;
    }

    snprintf(output, OS_MAXSTR + 1, "ok");

    return OS_SUCCESS;
}

int wdb_parse_global_update_agent_keepalive(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_id = NULL;
    cJSON *j_sync_status = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when updating agent keepalive.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id = cJSON_GetObjectItem(agent_data, "id");
        j_sync_status = cJSON_GetObjectItem(agent_data, "sync_status");

        if (cJSON_IsNumber(j_id) && cJSON_IsString(j_sync_status)) {
            // Getting each field
            int id = j_id->valueint;
            char *sync_status = j_sync_status->valuestring;

            if (OS_SUCCESS != wdb_global_update_agent_keepalive(wdb, id, sync_status)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                return OS_INVALID;
            }
        } else {
            mdebug1("Global DB Invalid JSON data when updating agent keepalive.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    snprintf(output, OS_MAXSTR + 1, "ok");
    cJSON_Delete(agent_data);

    return OS_SUCCESS;
}

int wdb_parse_global_delete_agent(wdb_t * wdb, char * input, char * output) {
    int agent_id = 0;

    agent_id = atoi(input);

    if (OS_SUCCESS != wdb_global_delete_agent(wdb, agent_id)) {
        mdebug1("Error deleting agent from agent table in global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error deleting agent from agent table in global.db.");
        return OS_INVALID;
    }

    snprintf(output, OS_MAXSTR + 1, "ok");

    return OS_SUCCESS;
}

int wdb_parse_global_select_agent_name(wdb_t * wdb, char * input, char * output) {
    int agent_id = 0;
    cJSON *name = NULL;
    char *out = NULL;

    agent_id = atoi(input);

    if (name = wdb_global_select_agent_name(wdb, agent_id), !name) {
        mdebug1("Error getting agent name from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agent name from global.db.");
        return OS_INVALID;
    }

    out = cJSON_PrintUnformatted(name);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(name);

    return OS_SUCCESS;
}

int wdb_parse_global_select_agent_group(wdb_t * wdb, char * input, char * output) {
    int agent_id = 0;
    cJSON *name = NULL;
    char *out = NULL;

    agent_id = atoi(input);

    if (name = wdb_global_select_agent_group(wdb, agent_id), !name) {
        mdebug1("Error getting agent group from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agent group from global.db.");
        return OS_INVALID;
    }

    out = cJSON_PrintUnformatted(name);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(name);

    return OS_SUCCESS;
}

int wdb_parse_global_delete_agent_belong(wdb_t * wdb, char * input, char * output) {
    int agent_id = 0;

    agent_id = atoi(input);

    if (OS_SUCCESS != wdb_global_delete_agent_belong(wdb, agent_id)) {
        mdebug1("Error deleting agent from belongs table in global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error deleting agent from belongs table in global.db.");
        return OS_INVALID;
    }

    snprintf(output, OS_MAXSTR + 1, "ok");

    return OS_SUCCESS;
}

int wdb_parse_global_find_agent(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_name = NULL;
    cJSON *j_ip = NULL;
    cJSON *j_id = NULL;
    char *out = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when finding agent id.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_name = cJSON_GetObjectItem(agent_data, "name");
        j_ip = cJSON_GetObjectItem(agent_data, "ip");

        if (cJSON_IsString(j_name) && cJSON_IsString(j_ip)) {
            // Getting each field
            char *name = j_name->valuestring;
            char *ip = j_ip->valuestring;

            if (j_id = wdb_global_find_agent(wdb, name, ip), !j_id) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                return OS_INVALID;
            }
        } else {
            mdebug1("Global DB Invalid JSON data when finding agent id.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    out = cJSON_PrintUnformatted(j_id);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(j_id);
    cJSON_Delete(agent_data);

    return OS_SUCCESS;
}

int wdb_parse_global_select_fim_offset(wdb_t * wdb, char * input, char * output) {
    int agent_id = 0;
    cJSON *offset = NULL;
    char *out = NULL;

    agent_id = atoi(input);

    if (offset = wdb_global_select_agent_fim_offset(wdb, agent_id), !offset) {
        mdebug1("Error getting agent fim offset from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agent fim offset from global.db.");
        return OS_INVALID;
    }

    out = cJSON_PrintUnformatted(offset);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(offset);

    return OS_SUCCESS;
}

int wdb_parse_global_select_reg_offset(wdb_t * wdb, char * input, char * output) {
    int agent_id = 0;
    cJSON *offset = NULL;
    char *out = NULL;

    agent_id = atoi(input);

    if (offset = wdb_global_select_agent_reg_offset(wdb, agent_id), !offset) {
        mdebug1("Error getting agent reg offset from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agent reg offset from global.db.");
        return OS_INVALID;
    }

    out = cJSON_PrintUnformatted(offset);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(offset);

    return OS_SUCCESS;
}

int wdb_parse_global_update_fim_offset(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_id = NULL;
    cJSON *j_offset = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when updating agent fim offset.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id = cJSON_GetObjectItem(agent_data, "id");
        j_offset = cJSON_GetObjectItem(agent_data, "offset");

        if (cJSON_IsNumber(j_id) && cJSON_IsNumber(j_offset)) {
            // Getting each field
            int id = j_id->valueint;
            long offset = j_offset->valuedouble;

            if (OS_SUCCESS != wdb_global_update_agent_fim_offset(wdb, id, offset)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                return OS_INVALID;
            }
        } else {
            mdebug1("Global DB Invalid JSON data when updating agent fim offset.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    snprintf(output, OS_MAXSTR + 1, "ok");
    cJSON_Delete(agent_data);

    return OS_SUCCESS;
}

int wdb_parse_global_update_reg_offset(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_id = NULL;
    cJSON *j_offset = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when updating agent reg offset.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id = cJSON_GetObjectItem(agent_data, "id");
        j_offset = cJSON_GetObjectItem(agent_data, "offset");

        if (cJSON_IsNumber(j_id) && cJSON_IsNumber(j_offset)) {
            // Getting each field
            int id = j_id->valueint;
            long offset = j_offset->valuedouble;

            if (OS_SUCCESS != wdb_global_update_agent_reg_offset(wdb, id, offset)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                return OS_INVALID;
            }
        } else {
            mdebug1("Global DB Invalid JSON data when updating agent reg offset.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    snprintf(output, OS_MAXSTR + 1, "ok");
    cJSON_Delete(agent_data);

    return OS_SUCCESS;
}

int wdb_parse_global_select_agent_status(wdb_t * wdb, char * input, char * output) {
    int agent_id = 0;
    cJSON *status = NULL;
    char *out = NULL;

    agent_id = atoi(input);

    if (status = wdb_global_select_agent_status(wdb, agent_id), !status) {
        mdebug1("Error getting agent update status from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agent update status from global.db.");
        return OS_INVALID;
    }

    out = cJSON_PrintUnformatted(status);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(status);

    return OS_SUCCESS;
}

int wdb_parse_global_update_agent_status(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_id = NULL;
    cJSON *j_status = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when updating agent update status.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id = cJSON_GetObjectItem(agent_data, "id");
        j_status = cJSON_GetObjectItem(agent_data, "status");

        if (cJSON_IsNumber(j_id) && cJSON_IsString(j_status) && j_status->valuestring) {
            // Getting each field
            int id = j_id->valueint;
            char *status = j_status->valuestring;

            if (OS_SUCCESS != wdb_global_update_agent_status(wdb, id, status)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                return OS_INVALID;
            }
        } else {
            mdebug1("Global DB Invalid JSON data when updating agent update status.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    snprintf(output, OS_MAXSTR + 1, "ok");
    cJSON_Delete(agent_data);

    return OS_SUCCESS;
}

int wdb_parse_global_update_agent_group(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_id = NULL;
    cJSON *j_group = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when updating agent group.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id = cJSON_GetObjectItem(agent_data, "id");
        j_group = cJSON_GetObjectItem(agent_data, "group");

        if (cJSON_IsNumber(j_id)) {
            // Getting each field
            int id = j_id->valueint;
            char *group = cJSON_IsString(j_group) ? j_group->valuestring : NULL;

            if (OS_SUCCESS != wdb_global_update_agent_group(wdb, id, group)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                return OS_INVALID;
            }
        } else {
            mdebug1("Global DB Invalid JSON data when updating agent group.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    snprintf(output, OS_MAXSTR + 1, "ok");
    cJSON_Delete(agent_data);

    return OS_SUCCESS;
}

int wdb_parse_global_find_group(wdb_t * wdb, char * input, char * output) {
    char *group_name = NULL;
    cJSON *group_id = NULL;
    char *out = NULL;

    group_name = input;

    if (group_id = wdb_global_find_group(wdb, group_name), !group_id) {
        mdebug1("Error getting group id from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting group id from global.db.");
        return OS_INVALID;
    }

    out = cJSON_PrintUnformatted(group_id);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(group_id);

    return OS_SUCCESS;
}

int wdb_parse_global_insert_agent_group(wdb_t * wdb, char * input, char * output) {
    char *group_name = NULL;

    group_name = input;

    if (OS_SUCCESS != wdb_global_insert_agent_group(wdb, group_name)) {
        mdebug1("Error inserting group in global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error inserting group in global.db.");
        return OS_INVALID;
    }

    snprintf(output, OS_MAXSTR + 1, "ok");

    return OS_SUCCESS;
}

int wdb_parse_global_insert_agent_belong(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_id_group = NULL;
    cJSON *j_id_agent = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when inserting agent to belongs table.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id_group = cJSON_GetObjectItem(agent_data, "id_group");
        j_id_agent = cJSON_GetObjectItem(agent_data, "id_agent");

        if (cJSON_IsNumber(j_id_group) && cJSON_IsNumber(j_id_agent)) {
            // Getting each field
            int id_group = j_id_group->valueint;
            int id_agent = j_id_agent->valueint;

            if (OS_SUCCESS != wdb_global_insert_agent_belong(wdb, id_group, id_agent)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                return OS_INVALID;
            }
        } else {
            mdebug1("Global DB Invalid JSON data when inserting agent to belongs table.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    snprintf(output, OS_MAXSTR + 1, "ok");
    cJSON_Delete(agent_data);

    return OS_SUCCESS;
}

int wdb_parse_global_delete_group_belong(wdb_t * wdb, char * input, char * output) {
    char *group_name = NULL;

    group_name = input;

    if (OS_SUCCESS != wdb_global_delete_group_belong(wdb, group_name)) {
        mdebug1("Error deleting group from belongs table in global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error deleting group from belongs table in global.db.");
        return OS_INVALID;
    }

    snprintf(output, OS_MAXSTR + 1, "ok");

    return OS_SUCCESS;
}

int wdb_parse_global_delete_group(wdb_t * wdb, char * input, char * output) {
    char *group_name = NULL;

    group_name = input;

    if (OS_SUCCESS != wdb_global_delete_group(wdb, group_name)) {
        mdebug1("Error deleting group in global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error deleting group in global.db.");
        return OS_INVALID;
    }

    snprintf(output, OS_MAXSTR + 1, "ok");

    return OS_SUCCESS;
}

int wdb_parse_global_select_groups(wdb_t * wdb, char * output) {
    cJSON *groups = NULL;
    char *out = NULL;

    if (groups = wdb_global_select_groups(wdb), !groups) {
        mdebug1("Error getting groups from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting groups from global.db.");
        return OS_INVALID;
    }

    out = cJSON_PrintUnformatted(groups);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(groups);

    return OS_SUCCESS;
}

int wdb_parse_global_select_agent_keepalive(wdb_t * wdb, char * input, char * output) {
   char *out = NULL;
   char *next = NULL;
   
   if (next = wstr_chr(input, ' '), !next) {
        mdebug1("Invalid DB query syntax.");
        mdebug2("DB query error near: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", input);
        return OS_INVALID;
    }
    *next++ = '\0';

    char* agent_name = input;
    char* agent_ip = next;
    cJSON *keepalive = NULL;

    keepalive = wdb_global_select_agent_keepalive(wdb, agent_name, agent_ip);
    if (!keepalive) {
        mdebug1("Error getting agent keepalive from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agent keepalive from global.db.");
        return OS_INVALID;
    }

    out = cJSON_PrintUnformatted(keepalive);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(keepalive);

    return OS_SUCCESS;
}

int wdb_parse_global_sync_agent_info_get(wdb_t* wdb, char* input, char* output) {
    static int last_id = 0;
    char* agent_info_sync = NULL;

    if (input) {
        char *next = wstr_chr(input, ' ');
        if(next) {
            *next++ = '\0';
            if (strcmp(input, "last_id") == 0) {
                last_id = atoi(next);
            }
        }
    }

    wdbc_result status = wdb_global_sync_agent_info_get(wdb, &last_id, &agent_info_sync);
    snprintf(output, WDB_MAX_RESPONSE_SIZE, "%s %s",  WDBC_RESULT[status], agent_info_sync);
    os_free(agent_info_sync)
    if (status != WDBC_DUE) {
        last_id = 0;
    }

    return OS_SUCCESS;
}

int wdb_parse_global_sync_agent_info_set(wdb_t * wdb, char * input, char * output){
    const char *error = NULL;
    int agent_id = 0;
    cJSON *root = NULL;
    cJSON *json_agent = NULL;
    cJSON *json_field = NULL;
    cJSON *json_label = NULL;
    cJSON *json_labels = NULL;
    cJSON *json_key = NULL;
    cJSON *json_value = NULL;
    cJSON *json_id = NULL;

    /* 
    * The cJSON_GetErrorPtr() method is not thread safe, using cJSON_ParseWithOpts() instead,
    * error indicates where the string caused an error.
    * The third arguments is TRUE and it will give an error if the input string 
    * contains data after the JSON command
    */ 
    root = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!root) {
        mdebug1("Global DB Invalid JSON syntax updating unsynced agents.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;

    } else {
        cJSON_ArrayForEach(json_agent, root){
            // Inserting new agent information in the database
            if (OS_SUCCESS != wdb_global_sync_agent_info_set(wdb, json_agent)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(root);
                return OS_INVALID;
            }
            // Checking for labels
            json_labels = cJSON_GetObjectItem(json_agent, "labels");
            if(cJSON_IsArray(json_labels)){
                // The JSON has a label array
                // Removing old labels from the labels table before inserting
                json_field = cJSON_GetObjectItem(json_agent, "id");
                agent_id = cJSON_IsNumber(json_field) ? json_field->valueint : -1;

                if (agent_id == -1){
                    mdebug1("Global DB Cannot execute SQL query; incorrect agent id in labels array.");
                    snprintf(output, OS_MAXSTR + 1, "err Cannot update labels due to invalid id.");
                    cJSON_Delete(root);
                    return OS_INVALID;
                }

                else if (OS_SUCCESS != wdb_global_del_agent_labels(wdb, agent_id)) {
                    mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                    snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                    cJSON_Delete(root);
                    return OS_INVALID;
                }
                // For every label in array, insert it in the database
                cJSON_ArrayForEach(json_label, json_labels){
                    json_key = cJSON_GetObjectItem(json_label, "key");
                    json_value = cJSON_GetObjectItem(json_label, "value");
                    json_id = cJSON_GetObjectItem(json_label, "id");

                    if(cJSON_IsString(json_key) && json_key->valuestring != NULL && cJSON_IsString(json_value) && 
                        json_value->valuestring != NULL && cJSON_IsNumber(json_id)){
                        // Inserting labels in the database
                        if (OS_SUCCESS != wdb_global_set_agent_label(wdb, json_id->valueint, json_key->valuestring, json_value->valuestring)) {
                            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                            snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                            cJSON_Delete(root);
                            return OS_INVALID;
                        }
                    }
                }
            }
        }
    }

    snprintf(output, OS_MAXSTR + 1, "ok");
    cJSON_Delete(root);

    return OS_SUCCESS;
}

int wdb_parse_global_get_agent_info(wdb_t* wdb, char* input, char* output) {
    int agent_id = 0;
    cJSON *agent_info = NULL;
    char *out = NULL;

    agent_id = atoi(input);

    if (agent_info = wdb_global_get_agent_info(wdb, agent_id), !agent_info) {
        mdebug1("Error getting agent information from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agent information from global.db.");
        return OS_INVALID;
    }

    out = cJSON_PrintUnformatted(agent_info);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(agent_info);

    return OS_SUCCESS;
}

int wdb_parse_global_get_agents_by_keepalive(wdb_t* wdb, char* input, char* output) {
    static int last_id = 0;
    char* out = NULL;
    char *next = NULL;
    char comparator = '<';
    int keep_alive = 0;
    const char delim[2] = " ";
    char *savedptr = NULL;

    /* Get keepalive condition */
    next = strtok_r(input, delim, &savedptr);
    if (next == NULL || strcmp(next, "condition") != 0) {
        mdebug1("Invalid arguments 'condition' not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments 'condition' not found");
        return OS_INVALID;
    }
    next = strtok_r(NULL, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments 'condition' not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments 'condition' not found");
        return OS_INVALID;
    }
    comparator = *next;
    next = strtok_r(NULL, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments 'condition' not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments 'condition' not found");
        return OS_INVALID;
    }
    keep_alive = atoi(next);
    
    /* Get last_id*/
    next = strtok_r(NULL, delim, &savedptr);
    if (next == NULL || strcmp(next, "last_id") != 0) {
        mdebug1("Invalid arguments 'last_id' not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments 'last_id' not found");
        return OS_INVALID;
    }
    next = strtok_r(NULL, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments 'last_id' not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments 'last_id' not found");
        return OS_INVALID;
    }
    last_id = atoi(next);
    
    wdbc_result status = wdb_global_get_agents_by_keepalive(wdb, &last_id, comparator, keep_alive, &out);
    snprintf(output, OS_MAXSTR + 1, "%s %s", WDBC_RESULT[status], out);

    os_free(out)

    return OS_SUCCESS;
}

int wdb_parse_global_get_all_agents(wdb_t* wdb, char* input, char* output) {
    int last_id = 0;
    char* out = NULL;
    char *next = NULL;
    const char delim[2] = " ";
    char *savedptr = NULL;
    
    /* Get last_id*/
    next = strtok_r(input, delim, &savedptr);
    if (next == NULL || strcmp(next, "last_id") != 0) {
        mdebug1("Invalid arguments 'last_id' not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments 'last_id' not found");
        return OS_INVALID;
    }
    next = strtok_r(NULL, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments 'last_id' not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments 'last_id' not found");
        return OS_INVALID;
    }
    last_id = atoi(next);
    
    wdbc_result status = wdb_global_get_all_agents(wdb, &last_id, &out);
    snprintf(output, OS_MAXSTR + 1, "%s %s",  WDBC_RESULT[status], out);
    
    os_free(out)

    return OS_SUCCESS;
}
