/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
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
#include "eventinfo.h"
#include "analysisd/decoders/plugin_decoders.h"

#ifdef LIBGEOIP_ENABLED
#include "GeoIP.h"
#endif


extern long int __crt_ftell; /* Global ftell pointer */
extern _Config Config;       /* Global Config structure */

#ifdef LIBGEOIP_ENABLED
GeoIP *geoipdb;
#endif

int GlobalConf(const char *cfgfile);

// Read config
cJSON *getGlobalConfig(void);
cJSON *getARManagerConfig(void);
cJSON *getARCommandsConfig(void);
cJSON *getAlertsConfig(void);
cJSON *getDecodersConfig(void);
void _getDecodersListJSON(OSDecoderNode *list, cJSON *array);
cJSON *getRulesConfig(void);
void _getRulesListJSON(RuleNode *list, cJSON *array);
cJSON *getAnalysisInternalOptions(void);
cJSON *getManagerLabelsConfig(void);

#endif /* _CONFIG__H */
