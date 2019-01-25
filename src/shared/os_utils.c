/*
 * Shared functions for Rootcheck events decoding
 * Copyright (C) 2015-2019, Wazuh Inc.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "os_utils.h"

#ifndef WIN32

char *w_os_get_runps(const char *ps, int mpid)
{
    char *tmp_str, *nbuf;
    char buf[OS_SIZE_2048 + 1];
    char command[OS_SIZE_1024 + 1];
    FILE *fp;

    buf[0] = '\0';
    command[0] = '\0';
    command[OS_SIZE_1024] = '\0';

    snprintf(command, OS_SIZE_1024, "%s -p %d 2> /dev/null", ps, mpid);
    fp = popen(command, "r");
    if (fp) {
        while (fgets(buf, OS_SIZE_2048, fp) != NULL) {
            tmp_str = strchr(buf, ':');
            if (!tmp_str) {
                continue;
            }

            nbuf = tmp_str++;

            tmp_str = strchr(nbuf, ' ');
            if (!tmp_str) {
                continue;
            }
            tmp_str++;

            /* Remove whitespaces */
            while (*tmp_str == ' ') {
                tmp_str++;
            }

            nbuf = tmp_str;

            tmp_str = strchr(nbuf, '\n');
            if (tmp_str) {
                *tmp_str = '\0';
            }

            pclose(fp);
            return (strdup(nbuf));
        }

        pclose(fp);
    }

    return (NULL);
}

/* Get list of Unix processes */
OSList *w_os_get_process_list()
{
    int i = 1;
    pid_t max_pid = MAX_PID;
    OSList *p_list = NULL;
    char ps[OS_SIZE_1024 + 1];

    /* Check where ps is */
    memset(ps, '\0', OS_SIZE_1024 + 1);
    strncpy(ps, "/bin/ps", OS_SIZE_1024);
    if (!w_is_file(ps)) {
        strncpy(ps, "/usr/bin/ps", OS_SIZE_1024);
        if (!w_is_file(ps)) {
            mterror(ARGV0, "'ps' not found.");
            return (NULL);
        }
    }

    /* Create process list */
    p_list = OSList_Create();
    if (!p_list) {
        mterror(ARGV0, LIST_ERROR);
        return (NULL);
    }

    for (i = 1; i <= max_pid; i++) {
        /* Check if the pid is present */
        if ((!((getsid(i) == -1) && (errno == ESRCH))) &&
                (!((getpgid(i) == -1) && (errno == ESRCH)))) {
            W_Proc_Info *p_info;
            char *p_name;

            p_name = w_os_get_runps(ps, (int)i);
            if (!p_name) {
                continue;
            }

            os_calloc(1, sizeof(W_Proc_Info), p_info);
            p_info->p_path = p_name;
            p_info->p_name = NULL;
            OSList_AddData(p_list, p_info);
        }
    }

    return (p_list);
}

/* Check if a file exists */
int w_is_file(char *file)
{
    FILE *fp;
    fp = fopen(file, "r");
    if (fp) {
        fclose(fp);
        return (1);
    }
    return (0);
}

/* Delete the process list */
int w_del_plist(OSList *p_list)
{
    OSListNode *l_node;
    OSListNode *p_node = NULL;

    if (p_list == NULL) {
        return (0);
    }

    l_node = OSList_GetFirstNode(p_list);
    while (l_node) {
        W_Proc_Info *pinfo;

        pinfo = (W_Proc_Info *)l_node->data;

        if (pinfo->p_name) {
            free(pinfo->p_name);
        }

        if (pinfo->p_path) {
            free(pinfo->p_path);
        }

        free(l_node->data);

        if (p_node) {
            free(p_node);
            p_node = NULL;
        }
        p_node = l_node;

        l_node = OSList_GetNextNode(p_list);
    }

    if (p_node) {
        free(p_node);
        p_node = NULL;
    }

    free(p_list);

    return (1);
}

#endif