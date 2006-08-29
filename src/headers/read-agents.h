/* @(#) $Id$ */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#ifndef __CRAGENT_H
#define __CRAGENT_H


char **get_agents(int flag);

void free_agents(char **agent_list);


#define GA_NOTACTIVE    2
#define GA_ACTIVE       3
#define GA_ALL          5    


#endif
