/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2014 Daniel B. Cid
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 */

#ifndef _INTEGRATORD_H
#define _INTEGRATORD_H

#include "config/integrator-config.h"

/** Prototypes **/

/* Read syslog config */
void **OS_ReadIntegratorConf(char *cfgfile, IntegratorConfig ***integrator_config);

/* Database inserting main function */
void OS_IntegratorD(IntegratorConfig **integrator_config);

extern IntegratorConfig **integrator_config;

// Read config
cJSON *getIntegratorConfig(void);

// Com request thread dispatcher
size_t intgcom_dispatch(char * command, char ** output);
size_t intgcom_getconfig(const char * section, char ** output);
void * intgcom_main(__attribute__((unused)) void * arg);

#endif
