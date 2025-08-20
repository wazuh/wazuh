/*
 * Wazuh Database Daemon
 * Copyright (C) 2015, Wazuh Inc.
 * January 16, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuhdb_op.h"
#include "wdb.h"
#include "external/cJSON/cJSON.h"
#include "wdb_state.h"

sqlite3 * wdb_global_pre(void **wdb_ctx)
{
    struct timeval begin;
    struct timeval end;
    struct timeval diff;
    wdb_t * wdb;

    w_inc_global();

    gettimeofday(&begin, 0);
    if (wdb = wdb_open_global(), !wdb) {
        mdebug2("Couldn't open DB global: %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
        gettimeofday(&end, 0);
        timersub(&end, &begin, &diff);
        w_inc_global_open_time(diff);
        return NULL;
    } else if (!wdb->enabled) {
        mdebug2("Database disabled: %s/%s.db.", WDB2_DIR, WDB_GLOB_NAME);
        wdb_pool_leave(wdb);
        gettimeofday(&end, 0);
        timersub(&end, &begin, &diff);
        w_inc_global_open_time(diff);
        return NULL;
    }

    gettimeofday(&end, 0);
    timersub(&end, &begin, &diff);
    w_inc_global_open_time(diff);

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    *wdb_ctx = (void *)wdb;
    return wdb->db;
}

void wdb_global_post(void *wdb_ctx)
{
    wdb_t * wdb = (wdb_t *)wdb_ctx;

    if (wdb) {
        wdb_pool_leave(wdb);
    }
}

int wdb_parse(char * input, char * output, int peer) {
    char * actor;
    char * query;
    char * sql;
    char * next;
    char path[PATH_MAX + 1];
    wdb_t * wdb;
    cJSON * data;
    char * out;
    int result = 0;
    struct timeval begin;
    struct timeval end;
    struct timeval diff;

    w_inc_queries_total();

    if (!input) {
        mdebug1("Empty input query.");
        return OS_INVALID;
    }

    // Clean string
    while (*input == ' ' || *input == '\n') {
        input++;
    }

    if (next = wstr_chr(input, ' '), !next) {
        mdebug1("Invalid DB query syntax.");
        mdebug2("DB query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", input);
        return OS_INVALID;
    }

    actor = input;
    *next++ = '\0';

    if (strcmp(actor, "global") == 0) {
        query = next;

        w_inc_global();

        mdebug2("Global query: %s", query);

        gettimeofday(&begin, 0);
        if (wdb = wdb_open_global(), !wdb) {
            mdebug2("Couldn't open DB global: %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
            snprintf(output, OS_MAXSTR + 1, "err Couldn't open DB global");
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_open_time(diff);
            return OS_INVALID;
        } else if (!wdb->enabled) {
            mdebug2("Database disabled: %s/%s.db.", WDB2_DIR, WDB_GLOB_NAME);
            snprintf(output, OS_MAXSTR + 1, "err DB global disabled.");
            wdb_pool_leave(wdb);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_open_time(diff);
            return OS_INVALID;
        }
        gettimeofday(&end, 0);
        timersub(&end, &begin, &diff);
        w_inc_global_open_time(diff);
        // Add the current peer to wdb structure
        wdb->peer = peer;

        if (next = wstr_chr(query, ' '), next) {
            *next++ = '\0';
        }

        if (strcmp(query, "sql") == 0) {
            w_inc_global_sql();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                sql = next;

                gettimeofday(&begin, 0);
                data = wdb_exec(wdb->db, sql);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_sql_time(diff);
                if (data) {
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
            w_inc_global_agent_insert_agent();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for insert-agent.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_insert_agent(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_insert_agent_time(diff);
            }
        } else if (strcmp(query, "update-agent-name") == 0) {
            w_inc_global_agent_update_agent_name();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for update-agent-name.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_update_agent_name(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_update_agent_name_time(diff);
            }
        } else if (strcmp(query, "update-agent-data") == 0) {
            w_inc_global_agent_update_agent_data();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for update-agent-data.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_update_agent_data(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_update_agent_data_time(diff);
            }
        } else if (strcmp(query, "get-labels") == 0) {
            w_inc_global_labels_get_labels();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for get-labels.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_get_agent_labels(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_labels_get_labels_time(diff);
            }
        } else if (strcmp(query, "update-keepalive") == 0) {
            w_inc_global_agent_update_keepalive();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for update-keepalive.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_update_agent_keepalive(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_update_keepalive_time(diff);
            }
        } else if (strcmp(query, "update-connection-status") == 0) {
            w_inc_global_agent_update_connection_status();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for update-connection-status.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_update_connection_status(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_update_connection_status_time(diff);
            }
        } else if (strcmp(query, "update-status-code") == 0) {
            w_inc_global_agent_update_status_code();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for update-status-code.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_update_status_code(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_update_status_code_time(diff);
            }
        } else if (strcmp(query, "delete-agent") == 0) {
            w_inc_global_agent_delete_agent();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for delete-agent.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_delete_agent(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_delete_agent_time(diff);
            }
        } else if (strcmp(query, "select-agent-name") == 0) {
            w_inc_global_agent_select_agent_name();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for select-agent-name.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_select_agent_name(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_select_agent_name_time(diff);
            }
        } else if (strcmp(query, "select-agent-group") == 0) {
            w_inc_global_agent_select_agent_group();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for select-agent-group.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_select_agent_group(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_select_agent_group_time(diff);
            }
        } else if (strcmp(query, "find-agent") == 0) {
            w_inc_global_agent_find_agent();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for find-agent.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_find_agent(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_find_agent_time(diff);
            }
        } else if (strcmp(query, "find-group") == 0) {
            w_inc_global_group_find_group();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for find-group.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_find_group(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_group_find_group_time(diff);
            }
        } else if (strcmp(query, "insert-agent-group") == 0) {
            w_inc_global_group_insert_agent_group();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for insert-agent-group.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_insert_agent_group(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_group_insert_agent_group_time(diff);
            }
        } else if (strcmp(query, "select-group-belong") == 0) {
            w_inc_global_belongs_select_group_belong();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for select-group-belong.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_select_group_belong(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_belongs_select_group_belong_time(diff);
            }
        } else if (strcmp(query, "get-group-agents") == 0) {
            w_inc_global_belongs_get_group_agent();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for get-group-agents.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_get_group_agents(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_belongs_get_group_agent_time(diff);
            }
        } else if (strcmp(query, "delete-group") == 0) {
            w_inc_global_group_delete_group();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for delete-group.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_delete_group(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_group_delete_group_time(diff);
            }
        } else if (strcmp(query, "select-groups") == 0) {
            w_inc_global_group_select_groups();
            gettimeofday(&begin, 0);
            result = wdb_parse_global_select_groups(wdb, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_group_select_groups_time(diff);
        } else if (strcmp(query, "sync-agent-groups-get") == 0) {
            w_inc_global_agent_sync_agent_groups_get();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for sync-agent-groups-get.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_sync_agent_groups_get(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_sync_agent_groups_get_time(diff);
            }
        } else if (strcmp(query, "set-agent-groups") == 0) {
            w_inc_global_agent_set_agent_groups();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for set-agent-groups.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_set_agent_groups(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_set_agent_groups_time(diff);
            }
        } else if (strcmp(query, "sync-agent-info-get") == 0) {
            w_inc_global_agent_sync_agent_info_get();
            gettimeofday(&begin, 0);
            result = wdb_parse_global_sync_agent_info_get(wdb, next, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_agent_sync_agent_info_get_time(diff);
        } else if (strcmp(query, "sync-agent-info-set") == 0) {
            w_inc_global_agent_sync_agent_info_set();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for sync-agent-info-set.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_sync_agent_info_set(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_sync_agent_info_set_time(diff);
            }
        } else if (strcmp(query, "get-groups-integrity") == 0) {
            w_inc_global_agent_get_groups_integrity();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for get-groups-integrity.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_get_groups_integrity(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_get_groups_integrity_time(diff);
            }
        } else if (strcmp(query, "recalculate-agent-group-hashes") == 0) {
            w_inc_global_agent_recalculate_agent_group_hashes();
            gettimeofday(&begin, 0);
            result = wdb_parse_global_recalculate_agent_group_hashes(wdb, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_agent_recalculate_agent_group_hashes_time(diff);
        } else if (strcmp(query, "disconnect-agents") == 0) {
            w_inc_global_agent_disconnect_agents();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for disconnect-agents.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_disconnect_agents(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_disconnect_agents_time(diff);
            }
        } else if (strcmp(query, "get-all-agents") == 0) {
            w_inc_global_agent_get_all_agents();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for get-all-agents.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_get_all_agents(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_get_all_agents_time(diff);
            }
        } else if (strcmp(query, "get-distinct-groups") == 0) {
            w_inc_global_agent_get_distinct_groups();
            gettimeofday(&begin, 0);
            result = wdb_parse_global_get_distinct_agent_groups(wdb, next, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_agent_get_distinct_groups_time(diff);
        } else if (strcmp(query, "get-agent-info") == 0) {
            w_inc_global_agent_get_agent_info();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for get-agent-info.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_get_agent_info(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_get_agent_info_time(diff);
            }
        } else if (strcmp(query, "reset-agents-connection") == 0) {
            w_inc_global_agent_reset_agents_connection();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for reset-agents-connection.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_reset_agents_connection(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_reset_agents_connection_time(diff);
            }
        } else if (strcmp(query, "get-agents-by-connection-status") == 0) {
            w_inc_global_agent_get_agents_by_connection_status();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for get-agents-by-connection-status.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_get_agents_by_connection_status(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_get_agents_by_connection_status_time(diff);
            }
        } else if (strcmp(query, "backup") == 0) {
            w_inc_global_backup();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for backup.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                // The "backup restore" command takes the pool_mutex to remove the wdb pointer
                gettimeofday(&begin, 0);
                result = wdb_parse_global_backup(&wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_backup_time(diff);
            }
        } else if (strcmp(query, "vacuum") == 0) {
            w_inc_global_vacuum();
            gettimeofday(&begin, 0);
            if (wdb_commit2(wdb) < 0) {
                mdebug1("Global DB Cannot end transaction.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot end transaction");
                result = -1;
            }

            wdb_finalize_all_statements(wdb);

            if (result != -1) {
                if (wdb_vacuum(wdb) < 0) {
                    mdebug1("Global DB Cannot vacuum database.");
                    snprintf(output, OS_MAXSTR + 1, "err Cannot vacuum database");
                    result = -1;
                } else {
                    int fragmentation_after_vacuum;

                    // save fragmentation after vacuum
                    if (fragmentation_after_vacuum = wdb_get_db_state(wdb), fragmentation_after_vacuum == OS_INVALID) {
                        mdebug1("Global DB Couldn't get fragmentation after vacuum for the database.");
                        snprintf(output, OS_MAXSTR + 1, "err Vacuum performed, but couldn't get fragmentation information after vacuum");
                        result = -1;
                    } else {
                        char str_vacuum_time[OS_SIZE_128] = { '\0' };
                        char str_vacuum_value[OS_SIZE_128] = { '\0' };

                        snprintf(str_vacuum_time, OS_SIZE_128, "%ld", time(0));
                        snprintf(str_vacuum_value, OS_SIZE_128, "%d", fragmentation_after_vacuum);
                        if (wdb_update_last_vacuum_data(wdb, str_vacuum_time, str_vacuum_value) != OS_SUCCESS) {
                            mdebug1("Global DB Couldn't update last vacuum info for the database.");
                            snprintf(output, OS_MAXSTR + 1, "err Vacuum performed, but last vacuum information couldn't be updated in the metadata table");
                            result = -1;
                        } else {
                            cJSON *json_fragmentation = cJSON_CreateObject();
                            cJSON_AddNumberToObject(json_fragmentation, "fragmentation_after_vacuum", fragmentation_after_vacuum);
                            char *out = cJSON_PrintUnformatted(json_fragmentation);
                            snprintf(output, OS_MAXSTR + 1, "ok %s", out);

                            os_free(out);
                            cJSON_Delete(json_fragmentation);
                            result = 0;
                        }
                    }
                }
            }
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_vacuum_time(diff);
        } else if (strcmp(query, "get_fragmentation") == 0) {
            w_inc_global_get_fragmentation();
            gettimeofday(&begin, 0);
            int state = wdb_get_db_state(wdb);
            int free_pages = wdb_get_db_free_pages_percentage(wdb);
            if (state < 0 || free_pages < 0) {
                mdebug1("Global DB Cannot get database fragmentation.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot get database fragmentation");
                result = -1;
            } else {
                cJSON *json_fragmentation = cJSON_CreateObject();
                cJSON_AddNumberToObject(json_fragmentation, "fragmentation", state);
                cJSON_AddNumberToObject(json_fragmentation, "free_pages_percentage", free_pages);
                char *out = cJSON_PrintUnformatted(json_fragmentation);
                snprintf(output, OS_MAXSTR + 1, "ok %s", out);

                os_free(out);
                cJSON_Delete(json_fragmentation);
                result = 0;
            }
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_get_fragmentation_time(diff);
        } else if (strcmp(query, "sleep") == 0) {
            unsigned long delay_ms;
            w_inc_global_sleep();
            gettimeofday(&begin, 0);
            if (!next || (delay_ms = strtoul(next, NULL, 10)) == ULONG_MAX) {
                mdebug1("Global DB Invalid DB query syntax.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                w_time_delay(delay_ms);
                snprintf(output, OS_MAXSTR + 1, "ok ");
            }
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_sleep_time(diff);
        } else {
            mdebug1("Invalid DB query syntax.");
            mdebug2("Global DB query error near: %s", query);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
            result = OS_INVALID;
        }
        if (result == OS_INVALID) {
            snprintf(path, sizeof(path), "%s/%s.db", WDB2_DIR, wdb->id);
            if (!w_is_file(path)) {
                mwarn("DB(%s) not found. This behavior is unexpected, the database will be recreated.", path);
                wdb_close(wdb, FALSE);
            }
        }
        wdb_pool_leave(wdb);
        return result;
    } else if (strcmp(actor, "task") == 0) {
        cJSON *parameters_json = NULL;
        const char *json_err;
        query = next;

        w_inc_task();

        mdebug2("Task query: %s", query);

        if (wdb = wdb_open_tasks(), !wdb) {
            mdebug2("Couldn't open DB task: %s/%s.db", WDB_TASK_DIR, WDB_TASK_NAME);
            snprintf(output, OS_MAXSTR + 1, "err Couldn't open DB task");
            return OS_INVALID;
        }
        // Add the current peer to wdb structure
        wdb->peer = peer;

        if (next = wstr_chr(query, ' '), !next) {
            mdebug1("Invalid DB query syntax.");
            mdebug2("DB query error near: %s", query);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
            wdb_pool_leave(wdb);
            return OS_INVALID;
        }

        *next++ = '\0';

        if (!strcmp("upgrade", query)) {
            w_inc_task_upgrade();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            // Detect parameters
            if (parameters_json = cJSON_ParseWithOpts(next, &json_err, 0), !parameters_json) {
                snprintf(output, OS_MAXSTR + 1, "err Invalid command parameters, near '%.32s'", next);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            gettimeofday(&begin, 0);
            result = wdb_parse_task_upgrade(wdb, parameters_json, "upgrade", output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_task_upgrade_time(diff);
            cJSON_Delete(parameters_json);

        } else if (!strcmp("upgrade_custom", query)) {
            w_inc_task_upgrade_custom();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            // Detect parameters
            if (parameters_json = cJSON_ParseWithOpts(next, &json_err, 0), !parameters_json) {
                snprintf(output, OS_MAXSTR + 1, "err Invalid command parameters, near '%.32s'", next);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            gettimeofday(&begin, 0);
            result = wdb_parse_task_upgrade(wdb, parameters_json, "upgrade_custom", output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_task_upgrade_custom_time(diff);
            cJSON_Delete(parameters_json);

        } else if (!strcmp("upgrade_get_status", query)) {
            w_inc_task_upgrade_get_status();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            // Detect parameters
            if (parameters_json = cJSON_ParseWithOpts(next, &json_err, 0), !parameters_json) {
                snprintf(output, OS_MAXSTR + 1, "err Invalid command parameters, near '%.32s'", next);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            gettimeofday(&begin, 0);
            result = wdb_parse_task_upgrade_get_status(wdb, parameters_json, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_task_upgrade_get_status_time(diff);
            cJSON_Delete(parameters_json);

        } else if (!strcmp("upgrade_update_status", query)) {
            w_inc_task_upgrade_update_status();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            // Detect parameters
            if (parameters_json = cJSON_ParseWithOpts(next, &json_err, 0), !parameters_json) {
                snprintf(output, OS_MAXSTR + 1, "err Invalid command parameters, near '%.32s'", next);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            gettimeofday(&begin, 0);
            result = wdb_parse_task_upgrade_update_status(wdb, parameters_json, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_task_upgrade_update_status_time(diff);
            cJSON_Delete(parameters_json);

        } else if (!strcmp("upgrade_result", query)) {
            w_inc_task_upgrade_result();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            // Detect parameters
            if (parameters_json = cJSON_ParseWithOpts(next, &json_err, 0), !parameters_json) {
                snprintf(output, OS_MAXSTR + 1, "err Invalid command parameters, near '%.32s'", next);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            gettimeofday(&begin, 0);
            result = wdb_parse_task_upgrade_result(wdb, parameters_json, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_task_upgrade_result_time(diff);
            cJSON_Delete(parameters_json);

        } else if (!strcmp("upgrade_cancel_tasks", query)) {
            w_inc_task_upgrade_cancel_tasks();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            // Detect parameters
            if (parameters_json = cJSON_ParseWithOpts(next, &json_err, 0), !parameters_json) {
                snprintf(output, OS_MAXSTR + 1, "err Invalid command parameters, near '%.32s'", next);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            gettimeofday(&begin, 0);
            result = wdb_parse_task_upgrade_cancel_tasks(wdb, parameters_json, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_task_upgrade_cancel_tasks_time(diff);
            cJSON_Delete(parameters_json);

        } else if (!strcmp("set_timeout", query)) {
            w_inc_task_set_timeout();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            // Detect parameters
            if (parameters_json = cJSON_ParseWithOpts(next, &json_err, 0), !parameters_json) {
                snprintf(output, OS_MAXSTR + 1, "err Invalid command parameters, near '%.32s'", next);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            gettimeofday(&begin, 0);
            result = wdb_parse_task_set_timeout(wdb, parameters_json, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_task_set_timeout_time(diff);
            cJSON_Delete(parameters_json);

        } else if (!strcmp("delete_old", query)) {
            w_inc_task_delete_old();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            // Detect parameters
            if (parameters_json = cJSON_ParseWithOpts(next, &json_err, 0), !parameters_json) {
                snprintf(output, OS_MAXSTR + 1, "err Invalid command parameters, near '%.32s'", next);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            gettimeofday(&begin, 0);
            result = wdb_parse_task_delete_old(wdb, parameters_json, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_task_delete_old_time(diff);
            cJSON_Delete(parameters_json);

        } else if (!strcmp("sql", query)) {
            w_inc_task_sql();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                sql = next;

                gettimeofday(&begin, 0);
                data = wdb_exec(wdb->db, sql);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_task_sql_time(diff);
                if (data) {
                    out = cJSON_PrintUnformatted(data);
                    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
                    os_free(out);
                    cJSON_Delete(data);
                } else {
                    mdebug1("Tasks DB Cannot execute SQL query; err database %s/%s.db: %s", WDB_TASK_DIR, WDB_TASK_NAME, sqlite3_errmsg(wdb->db));
                    mdebug2("Tasks DB SQL query: %s", sql);
                    snprintf(output, OS_MAXSTR + 1, "err Cannot execute Tasks database query; %s", sqlite3_errmsg(wdb->db));
                    result = OS_INVALID;
                }
            }
        } else {
            mdebug1("Invalid DB query syntax.");
            mdebug2("Task DB query error near: %s", query);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
            result = OS_INVALID;
        }
        wdb_pool_leave(wdb);
        return result;
    } else {
        mdebug1("Invalid DB query actor: %s", actor);
        snprintf(output, OS_MAXSTR + 1, "err Invalid DB query actor: '%.32s'", actor);
        return OS_INVALID;
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

    wdb_global_group_hash_cache(WDB_GLOBAL_GROUP_HASH_CLEAR, NULL);

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
    cJSON *j_connection_status = NULL;
    cJSON *j_sync_status = NULL;
    cJSON *j_labels = NULL;
    cJSON *j_group_config_status = NULL;

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
        j_connection_status = cJSON_GetObjectItem(agent_data, "connection_status");
        j_sync_status = cJSON_GetObjectItem(agent_data, "sync_status");
        j_labels = cJSON_GetObjectItem(agent_data, "labels");
        j_group_config_status = cJSON_GetObjectItem(agent_data, "group_config_status");

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
            char *connection_status = cJSON_IsString(j_connection_status) ? j_connection_status->valuestring : NULL;
            char *sync_status = cJSON_IsString(j_sync_status) ? j_sync_status->valuestring : "synced";
            char *labels = cJSON_IsString(j_labels) ? j_labels->valuestring : NULL;
            char *group_config_status = cJSON_IsString(j_group_config_status) ? j_group_config_status->valuestring : NULL;

            char *validated_sync_status = wdb_global_validate_sync_status(wdb, id, sync_status);

            if (OS_SUCCESS != wdb_global_update_agent_version(wdb, id, os_name, os_version, os_major, os_minor, os_codename,
                                                              os_platform, os_build, os_uname, os_arch, version, config_sum,
                                                              merged_sum, manager_host, node_name, agent_ip, connection_status,
                                                              validated_sync_status, group_config_status)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                os_free(validated_sync_status);
                return OS_INVALID;
            } else {
                // We will only add the agent's labels if the agent was successfully added to the database.
                // We dont check for NULL because if NULL, the current labels should be removed.
                // The output string will be filled by the labels setter method.
                char *labels_data = NULL;
                os_calloc(OS_MAXSTR, sizeof(char), labels_data);
                snprintf(labels_data, OS_MAXSTR, "%d", id);
                wm_strcat(&labels_data, labels, ' ');

                int result = wdb_parse_global_set_agent_labels(wdb, labels_data, output);

                cJSON_Delete(agent_data);
                os_free(validated_sync_status);
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
        } else {
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
    cJSON *j_connection_status = NULL;
    cJSON *j_sync_status = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when updating agent keepalive.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id = cJSON_GetObjectItem(agent_data, "id");
        j_connection_status = cJSON_GetObjectItem(agent_data, "connection_status");
        j_sync_status = cJSON_GetObjectItem(agent_data, "sync_status");

        if (cJSON_IsNumber(j_id) && cJSON_IsString(j_connection_status) && cJSON_IsString(j_sync_status)) {
            // Getting each field
            int id = j_id->valueint;
            char *connection_status = j_connection_status->valuestring;
            char *sync_status = j_sync_status->valuestring;

            char *validated_sync_status = wdb_global_validate_sync_status(wdb, id, sync_status);

            if (OS_SUCCESS != wdb_global_update_agent_keepalive(wdb, id, connection_status, validated_sync_status)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                os_free(validated_sync_status);
                return OS_INVALID;
            }

            os_free(validated_sync_status);
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

int wdb_parse_global_update_connection_status(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_id = NULL;
    cJSON *j_connection_status = NULL;
    cJSON *j_sync_status = NULL;
    cJSON *j_status_code = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when updating agent connection status.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id = cJSON_GetObjectItem(agent_data, "id");
        j_connection_status = cJSON_GetObjectItem(agent_data, "connection_status");
        j_sync_status = cJSON_GetObjectItem(agent_data, "sync_status");
        j_status_code = cJSON_GetObjectItem(agent_data, "status_code");

        if (cJSON_IsNumber(j_id) && cJSON_IsString(j_connection_status) && cJSON_IsString(j_sync_status) && cJSON_IsNumber(j_status_code)) {
            // Getting each field
            int id = j_id->valueint;
            char *connection_status = j_connection_status->valuestring;
            char *sync_status = j_sync_status->valuestring;
            int status_code = j_status_code->valueint;

            char *validated_sync_status = wdb_global_validate_sync_status(wdb, id, sync_status);

            if (OS_SUCCESS != wdb_global_update_agent_connection_status(wdb, id, connection_status, validated_sync_status, status_code)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                os_free(validated_sync_status);
                return OS_INVALID;
            }

            os_free(validated_sync_status);
        } else {
            mdebug1("Global DB Invalid JSON data when updating agent connection status.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    snprintf(output, OS_MAXSTR + 1, "ok");
    cJSON_Delete(agent_data);

    return OS_SUCCESS;
}

int wdb_parse_global_update_status_code(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_id = NULL;
    cJSON *j_status_code = NULL;
    cJSON *j_version = NULL;
    cJSON *j_sync_status = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when updating agent status code.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id = cJSON_GetObjectItem(agent_data, "id");
        j_status_code = cJSON_GetObjectItem(agent_data, "status_code");
        j_version = cJSON_GetObjectItem(agent_data, "version");
        j_sync_status = cJSON_GetObjectItem(agent_data, "sync_status");

        if (cJSON_IsNumber(j_id) && cJSON_IsNumber(j_status_code) && (j_version == NULL || cJSON_IsString(j_version)) && cJSON_IsString(j_sync_status)) {
            // Getting each field
            int id = j_id->valueint;
            int status_code = j_status_code->valueint;
            char *version = NULL;
            if (j_version != NULL) {
                version = j_version->valuestring;
            }
            char *sync_status = j_sync_status->valuestring;

            char *validated_sync_status = wdb_global_validate_sync_status(wdb, id, sync_status);

            if (OS_SUCCESS != wdb_global_update_agent_status_code(wdb, id, status_code, version, validated_sync_status)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                os_free(validated_sync_status);
                return OS_INVALID;
            }

            os_free(validated_sync_status);
        } else {
            mdebug1("Global DB Invalid JSON data when updating agent status code.");
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

    wdb_global_group_hash_cache(WDB_GLOBAL_GROUP_HASH_CLEAR, NULL);

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

int wdb_parse_global_select_group_belong(wdb_t *wdb, char *input, char *output) {
    int agent_id = atoi(input);
    cJSON *agent_groups = NULL;

    if (agent_groups = wdb_global_select_group_belong(wdb, agent_id), !agent_groups) {
        mdebug1("Error getting agent groups information from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agent groups information from global.db.");
        return OS_INVALID;
    }

    char *out = NULL;
    out = cJSON_PrintUnformatted(agent_groups);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(agent_groups);

    return OS_SUCCESS;
}

int wdb_parse_global_get_group_agents(wdb_t* wdb, char* input, char* output) {
    int last_agent_id = 0;
    char *next = NULL;
    const char delim[2] = " ";
    char *savedptr = NULL;
    char *group_name = NULL;

    /* Get group name */
    next = strtok_r(input, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments, group name not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments, group name not found.");
        return OS_INVALID;
    }
    group_name = next;

    /* Get last_id */
    next = strtok_r(NULL, delim, &savedptr);
    if (next == NULL || strcmp(next, "last_id") != 0) {
        mdebug1("Invalid arguments, 'last_id' not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments, 'last_id' not found.");
        return OS_INVALID;
    }
    next = strtok_r(NULL, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments, last agent id not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments, last agent id not found.");
        return OS_INVALID;
    }
    last_agent_id = atoi(next);

    // Execute command
    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_group_agents(wdb, &status, group_name, last_agent_id);
    if (!result) {
        mdebug1("Error getting group agents from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting group agents from global.db.");
        return OS_INVALID;
    }

    //Print response
    char* out = cJSON_PrintUnformatted(result);
    snprintf(output, OS_MAXSTR + 1, "%s %s",  WDBC_RESULT[status], out);

    cJSON_Delete(result);
    os_free(out)

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

int wdb_parse_global_set_agent_groups(wdb_t* wdb, char* input, char* output) {
    int ret = OS_SUCCESS;
    const char *error = NULL;
    cJSON *args = cJSON_ParseWithOpts(input, &error, TRUE);
    if (args) {
        cJSON *j_mode = cJSON_GetObjectItem(args, "mode");
        cJSON *j_sync_status = cJSON_GetObjectItem(args, "sync_status");
        cJSON *j_groups_data = cJSON_GetObjectItem(args, "data");

        // Mandatory fields
        if (cJSON_IsArray(j_groups_data) && cJSON_IsString(j_mode)) {
            wdb_groups_set_mode_t mode = WDB_GROUP_INVALID_MODE;
            char* sync_status = "synced";
            if (0 == strcmp(j_mode->valuestring, "override")) {
                mode = WDB_GROUP_OVERRIDE;
            } else if (0 == strcmp(j_mode->valuestring, "append")) {
                mode = WDB_GROUP_APPEND;
            } else if (0 == strcmp(j_mode->valuestring, "empty_only")) {
                mode = WDB_GROUP_EMPTY_ONLY;
            } else if (0 == strcmp(j_mode->valuestring, "remove")) {
                mode = WDB_GROUP_REMOVE;
            }

            if (WDB_GROUP_INVALID_MODE != mode) {
                if (cJSON_IsString(j_sync_status)) {
                    sync_status = j_sync_status->valuestring;
                }

                wdbc_result status = wdb_global_set_agent_groups(wdb, mode, sync_status, j_groups_data);
                if (status == WDBC_OK) {
                    snprintf(output, OS_MAXSTR + 1, "%s",  WDBC_RESULT[status]);
                } else {
                    snprintf(output, OS_MAXSTR + 1, "%s An error occurred during the set of the groups",  WDBC_RESULT[status]);
                    ret = OS_INVALID;
                }
            } else {
                mdebug1("Invalid mode '%s' in set_agent_groups command.", j_mode->valuestring);
                snprintf(output, OS_MAXSTR + 1, "err Invalid mode '%s' in set_agent_groups command", j_mode->valuestring);
                ret = OS_INVALID;
            }
        } else {
            mdebug1("Missing mandatory fields in set_agent_groups command.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, missing required fields");
            ret = OS_INVALID;
        }
        cJSON_Delete(args);
    } else {
        mdebug1("Global DB Invalid JSON syntax when parsing set_agent_groups");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        ret = OS_INVALID;
    }

    return ret;
}

int wdb_parse_global_sync_agent_groups_get(wdb_t* wdb, char* input, char* output) {
    int ret = OS_SUCCESS;
    const char *error = NULL;
    cJSON *args = cJSON_ParseWithOpts(input, &error, TRUE);
    if (args) {
        cJSON *j_sync_condition = cJSON_GetObjectItem(args, "condition");
        cJSON *j_last_id = cJSON_GetObjectItem(args, "last_id");
        cJSON *j_set_synced = cJSON_GetObjectItem(args, "set_synced");
        cJSON *j_get_hash = cJSON_GetObjectItem(args, "get_global_hash");
        cJSON *j_agent_registration_delta = cJSON_GetObjectItem(args, "agent_registration_delta");

        // Checking data types of alternative parameters in case they would have been sent in the input JSON.
        if ((j_sync_condition && !cJSON_IsString(j_sync_condition)) ||
            (j_last_id && (!cJSON_IsNumber(j_last_id) || j_last_id->valueint < 0)) ||
            (j_set_synced && !cJSON_IsBool(j_set_synced)) ||
            (j_get_hash && !cJSON_IsBool(j_get_hash)) ||
            (j_agent_registration_delta && (!cJSON_IsNumber(j_agent_registration_delta) || j_agent_registration_delta->valueint < 0))) {
            mdebug1("Invalid alternative fields data in sync-agent-groups-get command.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, invalid alternative fields data");
            ret = OS_INVALID;
        } else {
            wdb_groups_sync_condition_t condition = WDB_GROUP_NO_CONDITION;
            int last_id = 0;
            bool set_synced = false;
            bool get_hash = false;
            int agent_registration_delta = 0;

            if (j_sync_condition && 0 == strcmp(j_sync_condition->valuestring, "sync_status")) {
                condition = WDB_GROUP_SYNC_STATUS;
            } else if (j_sync_condition && 0 == strcmp(j_sync_condition->valuestring, "all")) {
                condition = WDB_GROUP_ALL;
            } else if (j_sync_condition) {
                condition = WDB_GROUP_INVALID_CONDITION;
            }
            if (j_last_id) {
                last_id = j_last_id->valueint;
            }
            if (cJSON_IsTrue(j_set_synced)) {
                set_synced = true;
            }
            if (cJSON_IsTrue(j_get_hash)) {
                get_hash = true;
            }
            if (j_agent_registration_delta) {
                agent_registration_delta = j_agent_registration_delta->valueint;
            }

            cJSON* agent_group_sync = NULL;
            wdbc_result status = wdb_global_sync_agent_groups_get(wdb, condition, last_id, set_synced, get_hash, agent_registration_delta, &agent_group_sync);
            if (agent_group_sync) {
                char* response = cJSON_PrintUnformatted(agent_group_sync);
                cJSON_Delete(agent_group_sync);
                if (strlen(response) <= WDB_MAX_RESPONSE_SIZE) {
                    snprintf(output, OS_MAXSTR + 1, "%s %s", WDBC_RESULT[status], response);
                } else {
                    snprintf(output, OS_MAXSTR + 1, "err %s", "Invalid response from wdb_global_sync_agent_groups_get");
                    ret = OS_INVALID;
                }
                os_free(response);
            } else {
                snprintf(output, OS_MAXSTR + 1, "err %s", "Could not obtain a response from wdb_global_sync_agent_groups_get");
                ret = OS_INVALID;
            }
        }
        cJSON_Delete(args);
    } else {
        mdebug1("Global DB Invalid JSON syntax when parsing sync-agent-groups-get");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        ret = OS_INVALID;
    }

    return ret;
}

int wdb_parse_global_sync_agent_info_get(wdb_t* wdb, char* input, char* output) {
    static int last_id = 0;
    char* agent_info_sync = NULL;

    if (input) {
        char *next = wstr_chr(input, ' ');
        if (next) {
            *next++ = '\0';
            if (strcmp(input, "last_id") == 0) {
                last_id = atoi(next);
            }
        }
    }

    wdbc_result status = wdb_global_sync_agent_info_get(wdb, &last_id, &agent_info_sync);
    snprintf(output, OS_MAXSTR + 1, "%s %s",  WDBC_RESULT[status], agent_info_sync);
    os_free(agent_info_sync)
    if (status != WDBC_DUE) {
        last_id = 0;
    }

    return OS_SUCCESS;
}

int wdb_parse_global_sync_agent_info_set(wdb_t * wdb, char * input, char * output) {
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
        cJSON_ArrayForEach(json_agent, root) {
            // Inserting new agent information in the database
            if (OS_SUCCESS != wdb_global_sync_agent_info_set(wdb, json_agent)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(root);
                return OS_INVALID;
            }
            // Checking for labels
            json_labels = cJSON_GetObjectItem(json_agent, "labels");
            if (cJSON_IsArray(json_labels)) {
                // The JSON has a label array
                // Removing old labels from the labels table before inserting
                json_field = cJSON_GetObjectItem(json_agent, "id");
                agent_id = cJSON_IsNumber(json_field) ? json_field->valueint : OS_INVALID;

                if (agent_id == OS_INVALID) {
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
                cJSON_ArrayForEach(json_label, json_labels) {
                    json_key = cJSON_GetObjectItem(json_label, "key");
                    json_value = cJSON_GetObjectItem(json_label, "value");
                    json_id = cJSON_GetObjectItem(json_label, "id");

                    if (cJSON_IsString(json_key) && json_key->valuestring != NULL && cJSON_IsString(json_value) &&
                        json_value->valuestring != NULL && cJSON_IsNumber(json_id)) {
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

int wdb_parse_get_groups_integrity(wdb_t* wdb, char* input, char* output) {
    int input_len = strlen(input);
    if (input_len < OS_SHA1_HEXDIGEST_SIZE) {
        mdebug1("Hash hex-digest does not have the expected length. Expected (%d) got (%d)",
                OS_SHA1_HEXDIGEST_SIZE,
                input_len);
        snprintf(output,
                 OS_MAXSTR + 1,
                 "err Hash hex-digest does not have the expected length. Expected (%d) got (%d)",
                 OS_SHA1_HEXDIGEST_SIZE,
                 input_len);
        return OS_INVALID;
    }

    os_sha1 hash = {0};
    strncpy(hash, input, OS_SHA1_HEXDIGEST_SIZE);

    cJSON *j_result = wdb_global_get_groups_integrity(wdb, hash);
    if (j_result == NULL) {
        mdebug1("Error getting groups integrity information from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting groups integrity information from global.db.");
        return OS_INVALID;
    }

    char* out = cJSON_PrintUnformatted(j_result);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(j_result);
    return OS_SUCCESS;
}

int wdb_parse_global_recalculate_agent_group_hashes(wdb_t* wdb, char* output) {

    if (OS_SUCCESS != wdb_global_recalculate_all_agent_groups_hash(wdb)) {
        mwarn("Error recalculating group hash of agents in global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error recalculating group hash of agents in global.db");
        return OS_INVALID;
    }

    snprintf(output, OS_MAXSTR + 1, "ok");

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

int wdb_parse_global_get_agents_by_connection_status(wdb_t* wdb, char* input, char* output) {
    int last_id = 0;
    int limit = 0;
    char *connection_status = NULL;
    char *node_name = NULL;
    char *next = NULL;
    const char delim[2] = " ";
    char *savedptr = NULL;

    /* Get last_id*/
    next = strtok_r(input, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments 'last_id' not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments 'last_id' not found");
        return OS_INVALID;
    }
    last_id = atoi(next);
    /* Get connection status */
    next = strtok_r(NULL, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments 'connection_status' not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments 'connection_status' not found");
        return OS_INVALID;
    }
    connection_status = next;

    /* Get node name */
    next = strtok_r(NULL, delim, &savedptr);
    if (next != NULL) {
        node_name = next;

        /* Get limit */
        next = strtok_r(NULL, delim, &savedptr);
        if (next == NULL) {
            mdebug1("Invalid arguments 'limit' not found.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid arguments 'limit' not found");
            return OS_INVALID;
        }
        limit = atoi(next);
    }

    // Execute command
    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(wdb, last_id, connection_status, node_name, limit, &status);
    if (!result) {
        mdebug1("Error getting agents by connection status from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agents by connection status from global.db.");
        return OS_INVALID;
    }

    //Print response
    char* out = cJSON_PrintUnformatted(result);
    snprintf(output, OS_MAXSTR + 1, "%s %s",  WDBC_RESULT[status], out);

    cJSON_Delete(result);
    os_free(out)

    return OS_SUCCESS;
}

int wdb_parse_global_get_all_agents(wdb_t* wdb, char* input, char* output) {
    int last_id = 0;
    char *next = NULL;
    const char delim[2] = " ";
    char *savedptr = NULL;

    /* Check if is last_id or context */
    next = strtok_r(input, delim, &savedptr);
    if (next == NULL || (strcmp(next, "last_id") != 0 && strcmp(next, "context") != 0)) {
        mdebug1("Invalid arguments 'last_id' or 'context' not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments 'last_id' or 'context' not found");
        return OS_INVALID;
    }

    if (strcmp(next, "context") == 0) {
        int status = wdb_global_get_all_agents_context(wdb);
        if (status != OS_SUCCESS) {
            snprintf(output, OS_MAXSTR + 1, "err Error getting agents from global.db.");
        }
        else {
            snprintf(output, OS_MAXSTR + 1, "ok []");
        }
        return status;
    }
    else {
        next = strtok_r(NULL, delim, &savedptr);
        if (next == NULL) {
            mdebug1("Invalid arguments 'last_id' not found.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid arguments 'last_id' not found");
            return OS_INVALID;
        }
        last_id = atoi(next);

        // Execute command
        wdbc_result status = WDBC_UNKNOWN;
        cJSON* result = wdb_global_get_all_agents(wdb, last_id, &status);

        if (!result) {
            mdebug1("Error getting agents from global.db.");
            snprintf(output, OS_MAXSTR + 1, "err Error getting agents from global.db.");
            return OS_INVALID;
        }

        //Print response
        char* out = cJSON_PrintUnformatted(result);
        snprintf(output, OS_MAXSTR + 1, "%s %s",  WDBC_RESULT[status], out);

        cJSON_Delete(result);
        os_free(out);

        return OS_SUCCESS;
    }
}

int wdb_parse_global_get_distinct_agent_groups(wdb_t* wdb, char* input, char* output) {

    // Execute command
    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_distinct_agent_groups(wdb, input, &status);
    if (!result) {
        mdebug1("Error getting agent groups from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agent groups from global.db.");
        return OS_INVALID;
    }

    //Print response
    char* out = cJSON_PrintUnformatted(result);
    snprintf(output, OS_MAXSTR + 1, "%s %s",  WDBC_RESULT[status], out);

    cJSON_Delete(result);
    os_free(out)

    return OS_SUCCESS;
}

int wdb_parse_reset_agents_connection(wdb_t * wdb, char* input, char * output) {
    if (OS_SUCCESS != wdb_global_reset_agents_connection(wdb, input)) {
        mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
        snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    snprintf(output, OS_MAXSTR + 1, "ok");
    return OS_SUCCESS;
}

int wdb_parse_global_disconnect_agents(wdb_t* wdb, char* input, char* output) {
    int last_id = 0;
    int keep_alive = 0;
    char *sync_status = NULL;
    char *next = NULL;
    const char delim[2] = " ";
    char *savedptr = NULL;

    /* Get last id*/
    next = strtok_r(input, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments last id not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments last id not found");
        return OS_INVALID;
    }
    last_id = atoi(next);

    /* Get keepalive*/
    next = strtok_r(NULL, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments keepalive not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments keepalive not found");
        return OS_INVALID;
    }
    keep_alive = atoi(next);

    /* Get sync_status*/
    next = strtok_r(NULL, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments sync_status not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments sync_status not found");
        return OS_INVALID;
    }
    sync_status = next;

    // Execute command
    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(wdb, last_id, keep_alive, sync_status, &status);
    if (!result) {
        mdebug1("Error getting agents to be disconnected from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agents to be disconnected from global.db.");
        return OS_INVALID;
    }

    //Print response
    char* out = cJSON_PrintUnformatted(result);
    snprintf(output, OS_MAXSTR + 1, "%s %s",  WDBC_RESULT[status], out);

    cJSON_Delete(result);
    os_free(out)

    return OS_SUCCESS;
}

int wdb_parse_global_backup(wdb_t** wdb, char* input, char* output) {
    int result = OS_INVALID;
    char * next;
    const char delim[] = " ";
    char *tail = NULL;

    next = strtok_r(input, delim, &tail);

    if (!next) {
        snprintf(output, OS_MAXSTR + 1, "err Missing backup action");
    }
    else if (strcmp(next, "create") == 0) {
        result = wdb_global_create_backup(*wdb, output, NULL);
        if (OS_SUCCESS != result) {
            merror("Creating Global DB snapshot on demand failed: %s", output);
        }
    }
    else if (strcmp(next, "get") == 0) {
        result = wdb_parse_global_get_backup(output);
    }
    else if (strcmp(next, "restore") == 0) {
        // During a restore, the global wdb_t pointer may change. The mutex prevents anyone else from accesing it
        result = wdb_parse_global_restore_backup(wdb, tail, output);
    }
    else {
        snprintf(output, OS_MAXSTR + 1, "err Invalid backup action: %s", next);
    }

    return result;
}

int wdb_parse_global_get_backup(char* output) {
    cJSON* j_backups = wdb_global_get_backups();

    if (j_backups) {
        char* out = cJSON_PrintUnformatted(j_backups);
        snprintf(output, OS_MAXSTR + 1, "ok %s", out);
        os_free(out);
        cJSON_Delete(j_backups);
        return OS_SUCCESS;
    } else {
        snprintf(output, OS_MAXSTR + 1, "err Cannot execute backup get command, unable to open '%s' folder", WDB_BACKUP_FOLDER);
        return OS_INVALID;
    }
}

int wdb_parse_global_restore_backup(wdb_t** wdb, char* input, char* output) {
    cJSON *j_parameters = NULL;
    const char *error = NULL;
    int result = OS_INVALID;

    j_parameters = cJSON_ParseWithOpts(input, &error, TRUE);

    if (!j_parameters && strcmp(input, "")) {
        mdebug1("Invalid backup JSON syntax when restoring snapshot.");
        mdebug2("JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        char* snapshot = cJSON_GetStringValue(cJSON_GetObjectItem(j_parameters, "snapshot"));
        cJSON* j_save_pre_restore_state = cJSON_GetObjectItem(j_parameters, "save_pre_restore_state");
        bool save_pre_restore_state = cJSON_IsBool(j_save_pre_restore_state) ? (bool) j_save_pre_restore_state->valueint : false;
        result = wdb_global_restore_backup(wdb, snapshot, save_pre_restore_state, output);
    }

    cJSON_Delete(j_parameters);
    return result;
}

int wdb_parse_task_upgrade(wdb_t* wdb, const cJSON *parameters, const char *command, char* output) {
    int result = OS_INVALID;
    int agent_id = OS_INVALID;
    char *node = NULL;
    char *module = NULL;

    cJSON *agent_id_json = cJSON_GetObjectItem(parameters, "agent");
    if (!agent_id_json || (agent_id_json->type != cJSON_Number)) {
        snprintf(output, OS_MAXSTR + 1, "err Error insert task: 'parsing agent error'");
        return OS_INVALID;
    }
    agent_id = agent_id_json->valueint;

    cJSON *node_json = cJSON_GetObjectItem(parameters, "node");
    if (!node_json || (node_json->type != cJSON_String)) {
        snprintf(output, OS_MAXSTR + 1, "err Error insert task: 'parsing node error'");
        return OS_INVALID;
    }
    node = node_json->valuestring;

    cJSON *module_json = cJSON_GetObjectItem(parameters, "module");
    if (!module_json || (module_json->type != cJSON_String)) {
        snprintf(output, OS_MAXSTR + 1, "err Error insert task: 'parsing module error'");
        return OS_INVALID;
    }
    module = module_json->valuestring;

    result = wdb_task_insert_task(wdb, agent_id, node, module, command);

    cJSON *response = cJSON_CreateObject();
    char *out = NULL;

    if (result >= 0) {
        cJSON_AddNumberToObject(response, "error", OS_SUCCESS);
        cJSON_AddNumberToObject(response, "task_id", result);
        result = OS_SUCCESS;
    } else {
        cJSON_AddNumberToObject(response, "error", result);
    }
    out = cJSON_PrintUnformatted(response);

    snprintf(output, OS_MAXSTR + 1, "ok %s", out);

    os_free(out);
    cJSON_Delete(response);

    return result;
}

int wdb_parse_task_upgrade_get_status(wdb_t* wdb, const cJSON *parameters, char* output) {
    int result = OS_INVALID;
    int agent_id = OS_INVALID;
    char *node = NULL;
    char *task_status = NULL;

    cJSON *agent_id_json = cJSON_GetObjectItem(parameters, "agent");
    if (!agent_id_json || (agent_id_json->type != cJSON_Number)) {
        snprintf(output, OS_MAXSTR + 1, "err Error get upgrade task status: 'parsing agent error'");
        return OS_INVALID;
    }
    agent_id = agent_id_json->valueint;

    cJSON *node_json = cJSON_GetObjectItem(parameters, "node");
    if (!node_json || (node_json->type != cJSON_String)) {
        snprintf(output, OS_MAXSTR + 1, "err Error get upgrade task status: 'parsing node error'");
        return OS_INVALID;
    }
    node = node_json->valuestring;

    result = wdb_task_get_upgrade_task_status(wdb, agent_id, node, &task_status);

    cJSON *response = cJSON_CreateObject();
    char *out = NULL;

    cJSON_AddNumberToObject(response, "error", result);
    if (result == OS_SUCCESS) {
        cJSON_AddStringToObject(response, "status", task_status);
    }
    out = cJSON_PrintUnformatted(response);

    snprintf(output, OS_MAXSTR + 1, "ok %s", out);

    os_free(out);
    cJSON_Delete(response);

    os_free(task_status);

    return result;
}

int wdb_parse_task_upgrade_update_status(wdb_t* wdb, const cJSON *parameters, char* output) {
    int result = OS_INVALID;
    int agent_id = OS_INVALID;
    char *node = NULL;
    char *status = NULL;
    char *error = NULL;

    cJSON *agent_id_json = cJSON_GetObjectItem(parameters, "agent");
    if (!agent_id_json || (agent_id_json->type != cJSON_Number)) {
        snprintf(output, OS_MAXSTR + 1, "err Error upgrade update status task: 'parsing agent error'");
        return OS_INVALID;
    }
    agent_id = agent_id_json->valueint;

    cJSON *node_json = cJSON_GetObjectItem(parameters, "node");
    if (!node_json || (node_json->type != cJSON_String)) {
        snprintf(output, OS_MAXSTR + 1, "err Error upgrade update status task: 'parsing node error'");
        return OS_INVALID;
    }
    node = node_json->valuestring;

    cJSON *status_json = cJSON_GetObjectItem(parameters, "status");
    if (!status_json || (status_json->type != cJSON_String)) {
        snprintf(output, OS_MAXSTR + 1, "err Error upgrade update status task: 'parsing status error'");
        return OS_INVALID;
    }
    status = status_json->valuestring;

    cJSON *error_json = cJSON_GetObjectItem(parameters, "error_msg");
    if (error_json && (error_json->type == cJSON_String)) {
        error = error_json->valuestring;
    }

    result = wdb_task_update_upgrade_task_status(wdb, agent_id, node, status, error);

    cJSON *response = cJSON_CreateObject();
    char *out = NULL;

    cJSON_AddNumberToObject(response, "error", result);
    out = cJSON_PrintUnformatted(response);

    snprintf(output, OS_MAXSTR + 1, "ok %s", out);

    os_free(out);
    cJSON_Delete(response);

    return result;
}

int wdb_parse_task_upgrade_result(wdb_t* wdb, const cJSON *parameters, char* output) {
    int result = OS_INVALID;
    int agent_id = OS_INVALID;
    char *node_result = NULL;
    char *module_result = NULL;
    char *command_result = NULL;
    char *status = NULL;
    char *error = NULL;
    int create_time = OS_INVALID;
    int last_update_time = OS_INVALID;

    cJSON *agent_id_json = cJSON_GetObjectItem(parameters, "agent");
    if (!agent_id_json || (agent_id_json->type != cJSON_Number)) {
        snprintf(output, OS_MAXSTR + 1, "err Error upgrade result task: 'parsing agent error'");
        return OS_INVALID;
    }
    agent_id = agent_id_json->valueint;

    result = wdb_task_get_upgrade_task_by_agent_id(wdb, agent_id, &node_result, &module_result, &command_result, &status, &error, &create_time, &last_update_time);

    cJSON *response = cJSON_CreateObject();
    char *out = NULL;

    if (result >= 0) {
        cJSON_AddNumberToObject(response, "error", OS_SUCCESS);
        cJSON_AddNumberToObject(response, "task_id", result);
        cJSON_AddStringToObject(response, "node", node_result);
        cJSON_AddStringToObject(response, "module", module_result);
        cJSON_AddStringToObject(response, "command", command_result);
        cJSON_AddStringToObject(response, "status", status);
        cJSON_AddStringToObject(response, "error_msg", error);
        cJSON_AddNumberToObject(response, "create_time", create_time);
        cJSON_AddNumberToObject(response, "update_time", last_update_time);
        result = OS_SUCCESS;
    } else {
        cJSON_AddNumberToObject(response, "error", result);
    }
    out = cJSON_PrintUnformatted(response);

    snprintf(output, OS_MAXSTR + 1, "ok %s", out);

    os_free(out);
    cJSON_Delete(response);

    os_free(node_result);
    os_free(module_result);
    os_free(command_result);
    os_free(status);
    os_free(error);

    return result;
}

int wdb_parse_task_upgrade_cancel_tasks(wdb_t* wdb, const cJSON *parameters, char* output) {
    int result = OS_INVALID;
    char *node = NULL;

    cJSON *node_json = cJSON_GetObjectItem(parameters, "node");
    if (!node_json || (node_json->type != cJSON_String)) {
        snprintf(output, OS_MAXSTR + 1, "err Error upgrade cancel task: 'parsing node error'");
        return OS_INVALID;
    }
    node = node_json->valuestring;

    result = wdb_task_cancel_upgrade_tasks(wdb, node);

    cJSON *response = cJSON_CreateObject();
    char *out = NULL;

    cJSON_AddNumberToObject(response, "error", result);
    out = cJSON_PrintUnformatted(response);

    snprintf(output, OS_MAXSTR + 1, "ok %s", out);

    os_free(out);
    cJSON_Delete(response);

    return result;
}

int wdb_parse_task_set_timeout(wdb_t* wdb, const cJSON *parameters, char* output) {
    int result = OS_INVALID;
    int now = OS_INVALID;
    int interval = OS_INVALID;
    time_t next_timeout = OS_INVALID;

    cJSON *now_json = cJSON_GetObjectItem(parameters, "now");
    if (!now_json || (now_json->type != cJSON_Number)) {
        snprintf(output, OS_MAXSTR + 1, "err Error set timeout task: 'parsing now error'");
        return OS_INVALID;
    }
    now = now_json->valueint;

    cJSON *interval_json = cJSON_GetObjectItem(parameters, "interval");
    if (!interval_json || (interval_json->type != cJSON_Number)) {
        snprintf(output, OS_MAXSTR + 1, "err Error set timeout task: 'parsing interval error'");
        return OS_INVALID;
    }
    interval = interval_json->valueint;

    next_timeout = now + interval;

    result = wdb_task_set_timeout_status(wdb, now, interval, &next_timeout);

    cJSON *response = cJSON_CreateObject();
    char *out = NULL;

    cJSON_AddNumberToObject(response, "error", result);
    if (result == OS_SUCCESS) {
        cJSON_AddNumberToObject(response, "timestamp", next_timeout);
    }
    out = cJSON_PrintUnformatted(response);

    snprintf(output, OS_MAXSTR + 1, "ok %s", out);

    os_free(out);
    cJSON_Delete(response);

    return result;
}

int wdb_parse_task_delete_old(wdb_t* wdb, const cJSON *parameters, char* output) {
    int result = OS_INVALID;
    int timestamp = OS_INVALID;

    cJSON *timestamp_json = cJSON_GetObjectItem(parameters, "timestamp");
    if (!timestamp_json || (timestamp_json->type != cJSON_Number)) {
        snprintf(output, OS_MAXSTR + 1, "err Error delete old task: 'parsing timestamp error'");
        return OS_INVALID;
    }
    timestamp = timestamp_json->valueint;

    result = wdb_task_delete_old_entries(wdb, timestamp);

    cJSON *response = cJSON_CreateObject();
    char *out = NULL;

    cJSON_AddNumberToObject(response, "error", result);
    out = cJSON_PrintUnformatted(response);

    snprintf(output, OS_MAXSTR + 1, "ok %s", out);

    os_free(out);
    cJSON_Delete(response);

    return result;
}
