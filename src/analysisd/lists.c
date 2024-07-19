/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation.
 */

#include "config.h"
#include "eventinfo.h"


/* Initialize the cdb lookup lists */
void Lists_OP_CreateLists()
{
    OS_CreateListsList();
    return;
}

int Lists_OP_LoadList(char *listfile, ListNode **cdblists, OSList* log_msg)
{
    char *holder;
    char a_filename[OS_MAXSTR];
    char b_filename[OS_MAXSTR];
    ListNode *tmp_listnode_pt = NULL;

    a_filename[OS_MAXSTR - 2] = '\0';
    b_filename[OS_MAXSTR - 2] = '\0';

    tmp_listnode_pt = (ListNode *)calloc(1, sizeof(ListNode));
    if (tmp_listnode_pt == NULL) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    snprintf(a_filename, OS_MAXSTR, "%s", listfile);
    if ((strchr(a_filename, '/') == NULL)) {
        /* default to ruleset/rules/ if a path is not given */
        snprintf(b_filename, OS_MAXSTR, "ruleset/rules/%.65516s", a_filename);
        snprintf(a_filename, OS_MAXSTR, "%s", b_filename);
    }
    if ((holder = strstr(a_filename, ".cdb"))) {
        snprintf(b_filename, (size_t)(holder - a_filename) + 1, "%s", a_filename);
        snprintf(a_filename, OS_MAXSTR, "%s", b_filename);
    }

    snprintf(b_filename, OS_MAXSTR, "%.65531s.cdb", a_filename);

    /* Check if the CDB list file is actually available */
    FILE *txt_fd = wfopen(a_filename, "r");
    if (!txt_fd)
    {
        smwarn(log_msg, FOPEN_ERROR, a_filename, errno, strerror(errno));
        os_free(tmp_listnode_pt);
        return 0;
    }

    fclose(txt_fd);

    os_strdup(a_filename, tmp_listnode_pt->txt_filename);
    os_strdup(b_filename, tmp_listnode_pt->cdb_filename);

    tmp_listnode_pt->loaded = 0;
    tmp_listnode_pt->mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;

    OS_AddList(tmp_listnode_pt, cdblists);

    return 0;
}
