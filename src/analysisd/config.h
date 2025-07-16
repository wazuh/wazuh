/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "../config/config.h"
#include "../config/global-config.h"
#include "../config/active-response.h"
#include "eventinfo.h"
#include "decoders/plugin_decoders.h"

#ifdef LIBGEOIP_ENABLED
#include "GeoIP.h"
#endif

extern _Config Config;       /* Global Config structure */

#ifdef LIBGEOIP_ENABLED
extern GeoIP *geoipdb;
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
void getActiveResponseInJSON(const Eventinfo *lf, const active_response *ar, char *extra_args, char *temp_msg, bool escape);

/**
 * @brief Get the value for the second part of the alert id
 *
 * @return long - The next value store for alert id
 * @note This function is thread-safe.
 * @warning this function not crate the id, previusly the id must be created with
 * the function set_global_alert_second_id
 */
long get_global_alert_second_id(void);

/**
 * @brief Set the value for the second part of the alert id
 *
 * @param v - The value to set
 * @note This function is thread-safe.
 */
void set_global_alert_second_id(long v);

#endif /* CONFIG_H */
