/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "mail-config.h"
#include "config.h"

int Test_Maild(const char * path) {
    int fail = 0;
    MailConfig *mail_config;
    // _Config *global_config;

    os_calloc(1, sizeof(MailConfig), mail_config);
    // os_calloc(1, sizeof(_Config), global_config);

    if(ReadConfig(CMAIL, path, NULL, mail_config) < 0) {
        merror(RCONFIG_ERROR,"Granular_Maild", path);
		fail = 1;
    }
    /* else if(ReadConfig(CGLOBAL, path, global_config, NULL) < 0) {
        merror(RCONFIG_ERROR,"Global_Maild", path);
		fail = 1;
    }
    */

    /* Free memory */
    // config_free(global_config);
    freeMailConfig(mail_config);

    if(fail) {
        return -1;
    }

    return 0;
}

void freeMailConfig(MailConfig *mailConfig) {
    if(mailConfig) {
        int i = 0;
        os_free(mailConfig->reply_to);
        os_free(mailConfig->from);
        os_free(mailConfig->idsname);
        os_free(mailConfig->smtpserver);
        os_free(mailConfig->heloserver);
        if(mailConfig->to) {
            i = 0;
            while(mailConfig->to[i]) {
                os_free(mailConfig->to[i]);
                i++;
            }
            os_free(mailConfig->to);
        }

        os_free(mailConfig->gran_level);
        os_free(mailConfig->gran_set);
        os_free(mailConfig->gran_format);
        if(mailConfig->gran_id) {
            i = 0;
            while(mailConfig->gran_id[i]) {
                os_free(mailConfig->gran_id[i]);
                i++;
            }
            os_free(mailConfig->gran_id);
        }

        if(mailConfig->gran_to) {
            i = 0;
            while(mailConfig->gran_to[i]) {
                os_free(mailConfig->gran_to[i]);
                i++;
            }
            os_free(mailConfig->gran_to);
        }

        if(mailConfig->gran_location) {
            i = 0;
            while(mailConfig->gran_location[i]) {
                os_free(mailConfig->gran_location[i]);
                i++;
            }
            os_free(mailConfig->gran_location);
        }

        if(mailConfig->gran_group) {
            i = 0;
            while(mailConfig->gran_group[i]) {
                os_free(mailConfig->gran_group[i]);
                i++;
            }
            os_free(mailConfig->gran_group);
        }
    }
}
