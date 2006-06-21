/* @(#) $Id$ */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"

#include "maild.h"
#include "config/config.h"


/* MailConf v0.1: 2005/04/01
 * Reads the Mail configuration
 */
int MailConf(int test_config, char *cfgfile, MailConfig *Mail)
{
    int modules = 0;

    modules|= CMAIL;

    Mail->to = NULL;
    Mail->from = NULL;
    Mail->smtpserver = NULL;
    Mail->mn = 0;
    Mail->maxperhour = 12;

    if(ReadConfig(modules, cfgfile, NULL, Mail) < 0)
        return(OS_INVALID);

    if(!Mail->mn)
    {
        if(!test_config)
        {
            verbose(MAIL_DIS, ARGV0);
        }
        exit(0);        
    }

    return(0);
}

/* EOF */
