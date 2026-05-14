/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2014 Daniel B. Cid
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "shared.h"

#ifndef CINTEGRATORCONFIG_H
#define CINTEGRATORCONFIG_H

#ifndef ARGV0
#define ARGV0 "wazuh-integrator"
#endif

/* Integrator Config Structure */
typedef struct _IntegratorConfig
{
    unsigned int level;
    unsigned int enabled;
    unsigned int *rule_id;
    unsigned int max_log;
    unsigned int timeout;
    unsigned int retries;

    char *name;
    char *apikey;
    char *hookurl;
    char *path;
    char *alert_format;
    char *group;
    char *options;
    OSMatch *location;
}IntegratorConfig;

#endif /* CINTEGRATORCONFIG_H */
