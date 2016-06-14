/* Copyright (C) 2014 Daniel B. Cid
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

#endif
