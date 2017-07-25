/* Copyright (C) 2009 Trend Micro Inc.
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
#include "config/global-config.h"

/* Read the Mail configuration */
int MailConf(int test_config, const char *cfgfile, MailConfig *Mail)
{
    int modules = 0;
     _Config global;

    modules |= CMAIL;

    Mail->to = NULL;
    Mail->reply_to = NULL;
    Mail->from = NULL;
    Mail->idsname = NULL;
    Mail->smtpserver = NULL;
    Mail->heloserver = NULL;
    Mail->mn = 0;
    Mail->priority = 0;
    Mail->maxperhour = 12;
    Mail->gran_to = NULL;
    Mail->gran_id = NULL;
    Mail->gran_level = NULL;
    Mail->gran_location = NULL;
    Mail->gran_group = NULL;
    Mail->gran_set = NULL;
    Mail->gran_format = NULL;
    Mail->groupping = 1;
    Mail->strict_checking = 0;
    Mail->source = 0;
#ifdef LIBGEOIP_ENABLED
    Mail->geoip = 0;
#endif

    memset(&global, 0, sizeof(_Config));
    global.alerts_log = 1;

    if (ReadConfig(modules, cfgfile, NULL, Mail) < 0) {
        return (OS_INVALID);
    }

    if (ReadConfig(CGLOBAL, cfgfile, &global, NULL) < 0) {
        return (OS_INVALID);
    }

    if (!Mail->mn) {
        if (!test_config) {
            minfo(MAIL_DIS);
        }
        exit(0);
    }

    if (global.alerts_log) {
        Mail->source = MAIL_SOURCE_LOGS;
    } else if (global.jsonout_output) {
        Mail->source = MAIL_SOURCE_JSON;
    } else {
        merror("All alert formats are disabled.");
        return OS_INVALID;
    }

    return (0);
}
