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
#include "wazuh_db/wdb.h"
#include <pthread.h>

#define ROOTCHECK_DIR    "/queue/rootcheck"

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
    char *wazuhdb_query = NULL;
    char *response = NULL;
    int db_result = 0;
    int socket = -1;
    int return_value = 0;

    
    os_calloc(OS_SIZE_6144 + 1, sizeof(char), wazuhdb_query);
    snprintf(wazuhdb_query, OS_SIZE_6144, "agent %s rootcheck %li %s", lf->agent_id, (long int)lf->time.tv_sec, lf->log);
    os_calloc(OS_SIZE_6144, sizeof(char), response);
    db_result = wdbc_query_ex(&socket, wazuhdb_query, response, OS_SIZE_6144);

    switch (db_result) {
    case -2:
        merror("Rootcheck decoder: Bad load query: '%s'.", wazuhdb_query);
        // Fallthrough
    case -1:
        os_free(lf->data);
        return_value = -1;
        break;
    default:
        mdebug1("Rootcheck decoder response: %s", response);
        break;
    }
    
    os_free(response);
    os_free(wazuhdb_query);

    if (!return_value) {
        lf->decoder_info = rootcheck_dec;
        lf->nfields = RK_NFIELDS;
        os_strdup(rootcheck_dec->fields[RK_TITLE], lf->fields[RK_TITLE].key);
        lf->fields[RK_TITLE].value = rk_get_title(lf->log);
        os_strdup(rootcheck_dec->fields[RK_FILE], lf->fields[RK_FILE].key);
        lf->fields[RK_FILE].value = rk_get_file(lf->log);
    }

    return return_value;
}
