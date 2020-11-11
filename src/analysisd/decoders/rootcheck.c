/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Rootcheck decoder */

#include "config.h"
#include "os_regex/os_regex.h"
#include "eventinfo.h"
#include "alerts/alerts.h"
#include "decoder.h"
#include "rootcheck_op.h"
#include <pthread.h>

/* Rootcheck decoder */
static OSDecoderInfo *rootcheck_dec = NULL;


/* Initialize the necessary information to process the rootcheck information */
void RootcheckInit()
{
    /* Zero decoder */
    os_calloc(1, sizeof(OSDecoderInfo), rootcheck_dec);
    rootcheck_dec->id = getDecoderfromlist(ROOTCHECK_MOD);
    rootcheck_dec->type = OSSEC_RL;
    rootcheck_dec->name = ROOTCHECK_MOD;
    rootcheck_dec->fts = 0;

    /* New fields as dynamic */
    os_calloc(Config.decoder_order_size, sizeof(char *), rootcheck_dec->fields);
    rootcheck_dec->fields[RK_TITLE] = "title";
    rootcheck_dec->fields[RK_FILE] = "file";

    mdebug1("RootcheckInit completed.");

    return;
}

/* Special decoder for rootcheck
 * Not using the default rendering tools for simplicity
 * and to be less resource intensive
 */
int DecodeRootcheck(Eventinfo *lf)
{
    char response[OS_SIZE_6144] = {'\0'};
    int db_result = 0;
    int return_value = 0;

    db_result = send_rootcheck_log(lf->agent_id, (long int)lf->time.tv_sec, lf->log, response);

    switch (db_result) {
    case -2:
        // Fallthrough
    case -1:
        merror("Rootcheck decoder unexpected result: '%s'", response);
        break;
    default:
        return_value = 1;
        mdebug1("Rootcheck decoder response: '%s'", response);

        lf->decoder_info = rootcheck_dec;

        char *op_code = wstr_chr(response, ' ');
        if (op_code) {
            op_code++;
            if (op_code && strtol(op_code, NULL, 10) == 2) {
                // Entry was inserted
                lf->rootcheck_fts = FTS_DONE;
            }
        }

        lf->nfields = RK_NFIELDS;
        os_strdup(rootcheck_dec->fields[RK_TITLE], lf->fields[RK_TITLE].key);
        lf->fields[RK_TITLE].value = rk_get_title(lf->log);
        os_strdup(rootcheck_dec->fields[RK_FILE], lf->fields[RK_FILE].key);
        lf->fields[RK_FILE].value = rk_get_file(lf->log);

        break;
    }

    return return_value;
}
