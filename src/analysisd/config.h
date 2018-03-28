/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _CONFIG__H
#define _CONFIG__H

#include "config/config.h"
#include "config/global-config.h"
#include "config/active-response.h"
#ifdef LIBGEOIP_ENABLED
#include "GeoIP.h"
#endif


extern long int __crt_ftell; /* Global ftell pointer */
extern _Config Config;       /* Global Config structure */

#ifdef LIBGEOIP_ENABLED
GeoIP *geoipdb;
#endif

int GlobalConf(const char *cfgfile);
cJSON *getGlobalConfig(void);
cJSON *getARManagerConfig(void);
cJSON *getARCommandsConfig(void);
void * syscom_main(__attribute__((unused)) void * arg) ;
size_t syscom_dispatch(char *command, size_t length __attribute__ ((unused)), char *output);
size_t syscom_getconfig(const char * section, char * output);

#endif /* _CONFIG__H */
