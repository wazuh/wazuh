/* @(#) $Id: ./src/analysisd/lists.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */



#include "config.h"
#include "eventinfo.h"



/* Lists_OP_CreateLists, v0.1, 2010/01/08
 * Will initilalize the cdb lookup lists
 */
void Lists_OP_CreateLists()
{
    OS_CreateListsList();
    return;
}

int Lists_OP_LoadList(char * listfile)
{
    /* XXX Jeremy: I hate this.  I think I'm missing something dumb here */
    char *holder;
    char a_filename[OS_MAXSTR];
    char b_filename[OS_MAXSTR];
    ListNode *tmp_listnode_pt = NULL;

    a_filename[OS_MAXSTR - 2] = '\0';
    b_filename[OS_MAXSTR - 2] = '\0';

    tmp_listnode_pt = (ListNode *)calloc(1,sizeof(ListNode));
    if (tmp_listnode_pt == NULL)
        ErrorExit(MEM_ERROR,ARGV0, errno, strerror(errno));
    snprintf(a_filename, OS_MAXSTR-1, "%s", listfile);
    if((strchr(a_filename, '/') == NULL))
    {
        /* default to rules/ if a path is not given */
        snprintf(b_filename, OS_MAXSTR-1, "rules/%s", a_filename);
        snprintf(a_filename, OS_MAXSTR-1, "%s", b_filename);
    }
    if((holder = strstr(a_filename, ".cdb")))
    {
        snprintf(b_filename, (int)(holder - a_filename) + 1, "%s", a_filename);
        snprintf(a_filename, OS_MAXSTR-1, "%s", b_filename);
    }
    snprintf(b_filename, OS_MAXSTR-1, "%s.cdb", a_filename);
    os_strdup(a_filename, tmp_listnode_pt->txt_filename);
    os_strdup(b_filename, tmp_listnode_pt->cdb_filename);
    tmp_listnode_pt->loaded = 0;
    OS_AddList(tmp_listnode_pt);
    return 0;
}
