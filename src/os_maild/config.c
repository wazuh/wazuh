/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
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
    Mail->grouping = 1;
    Mail->strict_checking = 0;
    Mail->source = -1;
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

    if(Mail->source == -1){
        Mail->source = MAIL_SOURCE_JSON;
    }

    if(!global.alerts_log && !global.jsonout_output) {
        merror("All alert formats are disabled.");
        return OS_INVALID;
    }
    if(!global.alerts_log && (Mail->source == MAIL_SOURCE_LOGS)){
        merror("Alerts.log is disabled");
        return OS_INVALID;
    }
    if(!global.jsonout_output && (Mail->source == MAIL_SOURCE_JSON)){
        merror("Alerts.json is disabled");
        return OS_INVALID;
    }


    return (0);
}


cJSON *getMailConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *email = cJSON_CreateObject();
    unsigned int i;

    if (mail.to) {
        cJSON *mail_list = cJSON_CreateArray();
        for (i=0;mail.to[i];i++) {
            cJSON_AddItemToArray(mail_list,cJSON_CreateString(mail.to[i]));
        }
        cJSON_AddItemToObject(email,"email_to",mail_list);
    }
    if (mail.from) cJSON_AddStringToObject(email,"email_from",mail.from);
    if (mail.reply_to) cJSON_AddStringToObject(email,"email_reply_to",mail.reply_to);
    if (mail.idsname) cJSON_AddStringToObject(email,"email_idsname",mail.idsname);
    if (mail.smtpserver) cJSON_AddStringToObject(email,"smtp_server",mail.smtpserver);
    if (mail.heloserver) cJSON_AddStringToObject(email,"helo_server",mail.heloserver);
    if (mail.source < 0 || mail.source == MAIL_SOURCE_JSON) {
        cJSON_AddStringToObject(email,"email_log_source","alerts.json");
    } else {
        cJSON_AddStringToObject(email,"email_log_source","alerts.log");
    }

    cJSON_AddNumberToObject(email,"email_maxperhour",mail.maxperhour);

    cJSON_AddItemToObject(root,"global",email);

    return root;
}


cJSON *getMailAlertsConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *mail_list = cJSON_CreateArray();
    unsigned int i;

    if (mail.gran_to) {
        for (i=0;mail.gran_to[i];i++) {
            cJSON *email = cJSON_CreateObject();
            cJSON_AddItemToObject(email,"email_to",cJSON_CreateString(mail.gran_to[i]));

            cJSON_AddItemToObject(email,"level",cJSON_CreateNumber(mail.gran_level[i]));

            if (mail.gran_group[i]) {
                cJSON *list = cJSON_CreateArray();
                OSMatch *wl;
                wl = mail.gran_group[i];
                char **tmp_pts = wl->patterns;
                while (*tmp_pts) {
                    cJSON_AddItemToArray(list,cJSON_CreateString(*tmp_pts));
                    tmp_pts++;
                }
                cJSON_AddItemToObject(email,"group",list);
            }

            if (mail.gran_location[i]) {
                cJSON *list = cJSON_CreateArray();
                OSMatch *wl;
                wl = mail.gran_location[i];
                char **tmp_pts = wl->patterns;
                while (*tmp_pts) {
                    cJSON_AddItemToArray(list,cJSON_CreateString(*tmp_pts));
                    tmp_pts++;
                }
                cJSON_AddItemToObject(email,"location",list);
            }

            if (mail.gran_id[i]) {
                cJSON *list = cJSON_CreateArray();
                unsigned int j = 0;
                while (mail.gran_id[i][j]) {
                    cJSON_AddItemToArray(list,cJSON_CreateNumber(mail.gran_id[i][j]));
                    j++;
                }
                cJSON_AddItemToObject(email,"rule_id",list);
            }

            switch (mail.gran_format[i]) {
                case FULL_FORMAT:
                    cJSON_AddStringToObject(email,"format","full");
                    break;

                case SMS_FORMAT:
                    cJSON_AddStringToObject(email,"format","sms");
                    break;

                case FORWARD_NOW:
                    cJSON_AddStringToObject(email,"format","do_not_delay");
                    break;

                case DONOTGROUP:
                    cJSON_AddStringToObject(email,"format","do_not_group");
                    break;
            }

            cJSON_AddItemToArray(mail_list,email);
        }
    }

    cJSON_AddItemToObject(root,"email_alerts",mail_list);

    return root;
}

cJSON *getMailInternalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *internals = cJSON_CreateObject();
    cJSON *maild = cJSON_CreateObject();

    cJSON_AddNumberToObject(maild,"strict_checking",mail.strict_checking);
    cJSON_AddNumberToObject(maild,"grouping",mail.grouping);
#ifdef LIBGEOIP_ENABLED
    cJSON_AddNumberToObject(maild,"geoip",mail.geoip);
#endif

    cJSON_AddItemToObject(internals,"mail",maild);
    cJSON_AddItemToObject(root,"internal",internals);

    return root;
}
