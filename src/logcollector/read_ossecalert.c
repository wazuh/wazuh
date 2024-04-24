/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2012 Daniel B. Cid (http://dcid.me)
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "headers/read-alert.h"
#include "logcollector.h"
#include "os_crypto/sha1/sha1_op.h"


void *read_ossecalert(logreader *lf, __attribute__((unused)) int *rc, int drop_it) {
    alert_data *al_data;
    char user_msg[256];
    char srcip_msg[256];
    char syslog_msg[OS_SIZE_2048 + 1];

    *rc = 0;

    al_data = GetAlertData(0, lf->fp);
    if (!al_data) {
        return (NULL);
    }

    /* Obtain context to calculate hash */
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    os_sha1 output;
    int64_t current_position = w_ftell(lf->fp);

    if (OS_SHA1_File_Nbytes(lf->file, &context, output, OS_BINARY, current_position) < 0) {
        merror(FAIL_SHA1_GEN, lf->file);
    }

    w_update_file_status(lf->file, current_position, context);

    memset(syslog_msg, '\0', OS_SIZE_2048 + 1);

    /* Add source ip */
    if (!al_data->srcip ||
            ((al_data->srcip[0] == '(') &&
             (al_data->srcip[1] == 'n') &&
             (al_data->srcip[2] == 'o'))) {
        srcip_msg[0] = '\0';
    } else {
        snprintf(srcip_msg, 255, " srcip: %s;", al_data->srcip);
    }

    /* Add username */
    if (!al_data->user ||
            ((al_data->user[0] == '(') &&
             (al_data->user[1] == 'n') &&
             (al_data->user[2] == 'o'))) {
        user_msg[0] = '\0';
    } else {
        snprintf(user_msg, 255, " user: %s;", al_data->user);
    }

    if (al_data->log[1] == NULL) {
        /* Build syslog message */
        snprintf(syslog_msg, OS_SIZE_2048,
                 "ossec: Alert Level: %d; Rule: %d - %s; "
                 "Location: %s;%s%s  %s",
                 al_data->level, al_data->rule, al_data->comment,
                 al_data->location,
                 srcip_msg,
                 user_msg,
                 al_data->log[0]);
    } else {
        char *tmp_msg = NULL;
        short int j = 0;

        while (al_data->log[j] != NULL) {
            tmp_msg = os_LoadString(tmp_msg, al_data->log[j]);
            tmp_msg = os_LoadString(tmp_msg, "\n");
            if (tmp_msg == NULL) {
                FreeAlertData(al_data);
                return (NULL);
            }
            j++;
        }

        if (tmp_msg == NULL) {
            FreeAlertData(al_data);
            return (NULL);
        }

        if (strlen(tmp_msg) > 1596) {
            tmp_msg[1594] = '.';
            tmp_msg[1595] = '.';
            tmp_msg[1596] = '.';
            tmp_msg[1597] = '\0';
        }
        snprintf(syslog_msg, OS_SIZE_2048,
                 "ossec: Alert Level: %d; Rule: %d - %s; "
                 "Location: %s;%s%s  %s",
                 al_data->level, al_data->rule, al_data->comment,
                 al_data->location,
                 srcip_msg,
                 user_msg,
                 tmp_msg);

        free(tmp_msg);
    }

    /* Clear the memory */
    FreeAlertData(al_data);

    /* Check ignore and restrict log regex, if configured. */
    if (drop_it == 0 && !check_ignore_and_restrict(lf->regex_ignore, lf->regex_restrict, syslog_msg)) {
        /* Send message to queue */
        w_msg_hash_queues_push(syslog_msg, lf->file, strlen(syslog_msg) + 1, lf->log_target, LOCALFILE_MQ);
    }

    return (NULL);
}
