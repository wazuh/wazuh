/* @(#) $Id: ./src/monitord/monitor_agents.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
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

    av_agents = get_agents(GA_ACTIVE);


    /* No agent saved */
    if(!mond.agents)
    {
        mond.agents = av_agents;
        return;
    }

    /* Checking if any of the previous available agents
     * are disconnected.
     */
    cr_agents = mond.agents;
    while(*cr_agents)
    {
        int available = 0;
        char **tmp_av;

        tmp_av = av_agents;
        while(tmp_av && *tmp_av)
        {
            if(strcmp(*cr_agents, *tmp_av) == 0)
            {
                available = 1;
                break;
            }
            tmp_av++;
        }

        /* Agent disconnected */
        if(available == 0)
        {
            char str[OS_SIZE_1024 +1];

            /* Sending disconnected message */
            snprintf(str, OS_SIZE_1024 -1, OS_AG_DISCON, *cr_agents);
            if(SendMSG(mond.a_queue, str, ARGV0,
                        LOCALFILE_MQ) < 0)
            {
                merror(QUEUE_SEND, ARGV0);
            }
        }

        cr_agents++;
    }


    /* Removing old agent list and adding currently one */
    free_agents(mond.agents);
    mond.agents = av_agents;
    return;
}

/* EOF */
