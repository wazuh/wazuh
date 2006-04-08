/*   $OSSEC, mail-config.h, v0.1, 2006/04/06, Daniel B. Cid$   */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

 

#ifndef _MCCONFIG__H
#define _MCCONFIG__H


/* Mail config structure */
typedef struct _MailConfig
{
    char **to;
    char *from;
    char *smtpserver;
    int maxperhour;
}MailConfig;


#endif
