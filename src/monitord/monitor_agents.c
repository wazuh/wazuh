/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "monitord.h"
#include "read-agents.h"
#include "external/sqlite/sqlite3.h"

static int mon_send_agent_msg(char *agent, char *msg);

void monitor_agents()
{
    char **cr_agents;
    char **av_agents;

    av_agents = get_agents(GA_ACTIVE,mond.delete_old_agents);

    /* No agent saved */
    if (!mond.agents) {
        mond.agents = av_agents;
        return;
    }

    /* Check if any of the previously available agents are disconnected */
    cr_agents = mond.agents;
    while (*cr_agents) {
        int available = 0;
        char **tmp_av;

        tmp_av = av_agents;
        while (tmp_av && *tmp_av) {
            if (strcmp(*cr_agents, *tmp_av) == 0) {
                available = 1;
                break;
            }
            tmp_av++;
        }

        /* Agent disconnected */
        if (available == 0) {
            char str[OS_SIZE_1024 + 1];
            int error;

            /* Send disconnected message */
            snprintf(str, OS_SIZE_1024 - 1, AG_DISCON_MSG, *cr_agents);
            if (error = mon_send_agent_msg(*cr_agents, str), error) {
                if (error == 2) {
                    // Agent is no longer in the database
                    snprintf(str, OS_SIZE_1024 - 1, OS_AG_REMOVED, *cr_agents);
                    if (SendMSG(mond.a_queue, str, ARGV0, LOCALFILE_MQ) < 0) {
                        merror("Could not generate removed agent alert for '%s'", *cr_agents);
                    }
                } else {
                    merror("Could not generate disconnected agent alert for '%s'", *cr_agents);
                }
            }

            if(mond.delete_old_agents > 0) {
                /* Delete old agent if time has passed */
                if(!delete_old_agent(*cr_agents) && error != 2){
                    snprintf(str, OS_SIZE_1024 - 1, OS_AG_REMOVED, *cr_agents);
                    if (SendMSG(mond.a_queue, str, ARGV0,
                                LOCALFILE_MQ) < 0) {
                        merror(QUEUE_SEND);
                    }
                }
            }
        }
        cr_agents++;
    }

    /* Delete old agents when using key-polling module */
    if(mond.delete_old_agents > 0) {
        char **na_agents;
        na_agents = get_agents(GA_NOTACTIVE,mond.delete_old_agents);

        char **na_agents_p = na_agents;

        if(na_agents_p) {
            while (*na_agents_p) {
                if(!delete_old_agent(*na_agents_p)){
                    char str[OS_SIZE_1024 + 1];
                    snprintf(str, OS_SIZE_1024 - 1, OS_AG_REMOVED, *na_agents_p);
                    if (SendMSG(mond.a_queue, str, ARGV0,
                                LOCALFILE_MQ) < 0) {
                        merror(QUEUE_SEND);
                    }
                }
                na_agents_p++;
            }
            free_strarray(na_agents);
        }
    }

    /* Remove old agent list and add current one */
    free_agents(mond.agents);
    mond.agents = av_agents;
    return;
}

int delete_old_agent(const char *agent){
    int sock;
    int json_output = 1;
    int val = 0;
    char agent_name[128] = {0};
    char *a_name_end = strrchr(agent,'-');
    strncpy(agent_name,agent,a_name_end - agent);

    char *agent_id = get_agent_id_from_name(agent_name);
    if(agent_id) {
        if (sock = auth_connect(), sock < 0) {
            mdebug1("Monitord could not connecto to Authd socket. Is Authd running?");
            val = -1;
            free(agent_id);
            return val;
        }
        val = auth_remove_agent(sock, agent_id, json_output);

        auth_close(sock);
        os_free(agent_id);
    } else {
        val = -1;
        return val;
    }

    return val;
}

int mon_send_agent_msg(char *agent, char *msg) {
    char header[OS_SIZE_256 + 1];
    char ag_name[OS_SIZE_128 + 1];
    int ag_id;
    char *ag_ip = NULL;
    char *found = agent;
    size_t name_size;
    static sqlite3 *db = NULL;
    sqlite3_stmt *stmt;
    int i;
    int error;

    while (found = strchr(found, '-'), found) {
        ag_ip = ++found;
    }

    if (name_size = strlen(agent) - strlen(ag_ip), name_size > OS_SIZE_128) {
        return 1;
    }

    snprintf(ag_name, name_size, "%s", agent);

    if (!db) {
        char dir[OS_FLSIZE + 1];
        snprintf(dir, OS_FLSIZE, "%s%s/%s", isChroot() ? "/" : "", WDB_DIR, WDB_GLOB_NAME);

        if (sqlite3_open_v2(dir, &db, SQLITE_OPEN_READONLY, NULL)) {
            sqlite3_close_v2(db);
            db = NULL;
            return 1;
        }
    }

    for (i = 0; i < GET_ID_QUERY_RETRIES; i++) {
        if (error = sqlite3_prepare_v2(db, GET_ID_QUERY, -1, &stmt, NULL), error == SQLITE_OK) {
            break;
        } else if (error != SQLITE_LOCKED && error != SQLITE_BUSY) {
            mdebug1("SQLite: %s", sqlite3_errmsg(db));
        }
        sleep(i);
    }

    if (i == GET_ID_QUERY_RETRIES) {
        merror("SQLite: %s", sqlite3_errmsg(db));
        return 1;
    }

    sqlite3_bind_text(stmt, 1, ag_name, -1, NULL);

    for (i = 0; (error = sqlite3_step(stmt)) == SQLITE_BUSY; i++) {
        if (i == GET_ID_QUERY_RETRIES) {
            return 1;
        }
    }

    if (error == SQLITE_ROW) {
        ag_id = sqlite3_column_int(stmt, 0);
        snprintf(header, OS_SIZE_256, "[%03d] (%s) %s", ag_id, ag_name, ag_ip);
        if (SendMSG(mond.a_queue, msg, header, SECURE_MQ) < 0) {
            merror(QUEUE_SEND);
            return 1;
        }
        sqlite3_finalize(stmt);
        return 0;
    } else {
        return 2;
    }

    return 1;
}
