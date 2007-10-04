/* @(#) $Id$ */

/* Copyright (C) 2003-2007 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */



#ifndef __CRAGENT_H
#define __CRAGENT_H


/* Delete syscheck db */
int delete_syscheck(char *sk_name, char *sk_ip, int full_delete);

/* Delete agent information */
int delete_agentinfo(char *name);

/* Get all available agents */
char **get_agents(int flag);

/* Free the agent list */
void free_agents(char **agent_list);


#define GA_NOTACTIVE    2
#define GA_ACTIVE       3
#define GA_ALL          5    


#endif
