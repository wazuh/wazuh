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

            /* Send disconnected message */
            snprintf(str, OS_SIZE_1024 - 1, OS_AG_DISCON, *cr_agents);
            if (SendMSG(mond.a_queue, str, ARGV0,
                        LOCALFILE_MQ) < 0) {
                merror(QUEUE_SEND);
            }

            if(mond.delete_old_agents > 0) {
                /* Delete old agent if time has passed */
                if(!delete_old_agent(*cr_agents)){
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
