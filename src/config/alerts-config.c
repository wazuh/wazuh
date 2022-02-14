/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "global-config.h"
#include "config.h"
#include "../analysisd/logmsg.h"


int Read_Alerts(XML_NODE node, void *configp, void * list)
{
    int i = 0;

    /* XML definitions */
    const char *xml_email_level = "email_alert_level";
    const char *xml_log_level = "log_alert_level";

#ifdef LIBGEOIP_ENABLED
    /* GeoIP */
    const char *xml_log_geoip = "use_geoip";
#endif

    _Config *Config;
    Config = (_Config *)configp;
    OSList * list_msg = (OSList *) list;

    if (!Config) {
        smerror(list_msg, "Configuration handle is NULL.");
        return (OS_INVALID);
    }

    while (node[i]) {
        if (!node[i]->element) {
            smerror(list_msg, XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            smerror(list_msg, XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        }
        /* Mail notification */
        else if (strcmp(node[i]->element, xml_email_level) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                smerror(list_msg, XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

            Config->mailbylevel = (u_int8_t) atoi(node[i]->content);
        }
        /* Log alerts */
        else if (strcmp(node[i]->element, xml_log_level) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                smerror(list_msg, XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            Config->logbylevel  = (u_int8_t) atoi(node[i]->content);
        }
#ifdef LIBGEOIP_ENABLED
        /* Enable GeoIP */
        else if (strcmp(node[i]->element, xml_log_geoip) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                Config->loggeoip = 1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                Config->loggeoip = 0;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

        }
#endif
        else {
            smerror(list_msg, XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
        i++;
    }
    return (0);
}

