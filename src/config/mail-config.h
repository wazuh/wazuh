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
#include "shared.h"


/* Mail config structure */
typedef struct _MailConfig
{
    int mn;
    int maxperhour;
    int strict_checking;
    int groupping;
    int subject_full;
    char **to;
    char *from;
    char *smtpserver;

    /* Granular e-mail options */
    int *gran_level;
    int *gran_set;
    char **gran_to;
    OSMatch **gran_location;
}MailConfig;


#endif
