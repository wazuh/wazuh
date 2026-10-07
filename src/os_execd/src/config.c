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
#include "execd.h"
#include "wmodules.h"
#include "agentd.h"
#include "logcollector.h"
#include "rootcheck.h"
#include "os_net.h"

int is_disabled;
os_ip **ar_allowlist = NULL;
char **ar_manager_hosts = NULL;

/* Never blocked: loopback and unspecified. The manager is added from the agent's own configuration. */
static const char *AR_ALLOWLIST_DEFAULTS[] = {"127.0.0.0/8", "::1", "0.0.0.0", "::", NULL};

static int ar_allowlist_add(const char *entry)
{
    os_ip *ip = NULL;
    size_t n = 0;

    if (!entry || *entry == '!' || strcmp(entry, "any") == 0) {
        merror(XML_VALUEERR, "allowlist", entry ? entry : "");
        return -1;
    }

    os_calloc(1, sizeof(os_ip), ip);
    if (!OS_IsValidIP(entry, ip)) {
        merror(XML_VALUEERR, "allowlist", entry);
        w_free_os_ip(ip);
        return -1;
    }

    while (ar_allowlist && ar_allowlist[n]) {
        n++;
    }
    os_realloc(ar_allowlist, (n + 2) * sizeof(os_ip *), ar_allowlist);
    ar_allowlist[n] = ip;
    ar_allowlist[n + 1] = NULL;
    return 0;
}

static void ar_load_manager_hosts(const char *cfgfile)
{
    agent agt = { .server = NULL };
    size_t n = 0;

    if (ReadConfig(CCLIENT, cfgfile, &agt, NULL) < 0) {
        mwarn("Could not read the manager address. Active responses will only skip the configured allowlist.");
    }

    for (int i = 0; agt.server && agt.server[i].rip; i++) {
        os_realloc(ar_manager_hosts, (n + 2) * sizeof(char *), ar_manager_hosts);
        os_strdup(agt.server[i].rip, ar_manager_hosts[n]);
        // Legacy <server-hostname> entries carry a trailing "/".
        char *slash = strchr(ar_manager_hosts[n], '/');
        if (slash) {
            *slash = '\0';
        }
        ar_manager_hosts[++n] = NULL;
    }

    Free_Agent(&agt);
}

/* Read the config file */
int ExecdConfig(const char *cfgfile)
{
    is_disabled = 0;

    const char *(xmlf[]) = {WAZUHCONFIG, "active-response", "disabled", NULL};
    char *disable_entry;
    char *repeated_t = NULL;
    char **repeated_a;
    int i = 0;

    OS_XML xml;

    /* Read XML file */
    if (OS_ReadXML(cfgfile, &xml) < 0)
    {
        merror_exit(XML_ERROR, cfgfile, xml.err, xml.err_line);
    }

    /* We do not validate the xml in here. It is done by other processes. */
    disable_entry = OS_GetOneContentforElement(&xml, xmlf);
    if (disable_entry)
    {
        if (strcmp(disable_entry, "yes") == 0)
        {
            is_disabled = 1;
        }
        else if (strcmp(disable_entry, "no") == 0)
        {
            is_disabled = 0;
        }
        else
        {
            merror(XML_VALUEERR, "disabled", disable_entry);
            free(disable_entry);
            return (-1);
        }

        free(disable_entry);
    }

    XML_NODE node = OS_GetElementsbyNode(&xml, NULL);

    for (i = 0; node && node[i]; i++) {
        XML_NODE child = OS_GetElementsbyNode(&xml, node[i]);

        for (int j = 0; child && child[j]; j++) {
            if (strcmp(child[j]->element, "active-response") != 0) {
                continue;
            }

            XML_NODE child_attr = OS_GetElementsbyNode(&xml, child[j]);

            for (int p = 0; child_attr && child_attr[p]; p++) {
                if (!strcmp(child_attr[p]->element, "repeated_offenders")) {
                    if (!repeated_t) {
                        os_strdup(child_attr[p]->content, repeated_t);
                    }
                } else if (!strcmp(child_attr[p]->element, "allowlist")) {
                    if (ar_allowlist_add(child_attr[p]->content) < 0) {
                        OS_ClearNode(child_attr);
                        OS_ClearNode(child);
                        OS_ClearNode(node);
                        OS_ClearXML(&xml);
                        os_free(repeated_t);
                        return (-1);
                    }
                }
            }

            OS_ClearNode(child_attr);
        }

        OS_ClearNode(child);
    }

    OS_ClearNode(node);

    for (i = 0; AR_ALLOWLIST_DEFAULTS[i]; i++) {
        ar_allowlist_add(AR_ALLOWLIST_DEFAULTS[i]);
    }

    ar_load_manager_hosts(cfgfile);
    ar_resolve_manager_hosts();

    //repeated_t = OS_GetOneContentforElement(&xml, blocks);
    if (repeated_t)
    {
        int i = 0;
        int j = 0;
        repeated_a = OS_StrBreak(',', repeated_t, 6);
        if (!repeated_a)
        {
            merror(XML_VALUEERR, "repeated_offenders", repeated_t);
            free(repeated_t);
            return (-1);
        }

        while (repeated_a[i] != NULL)
        {
            char *tmpt = repeated_a[i];
            while (*tmpt != '\0')
            {
                if (*tmpt == ' ' || *tmpt == '\t')
                {
                    tmpt++;
                }
                else
                {
                    break;
                }
            }

            if (*tmpt == '\0')
            {
                i++;
                continue;
            }

            repeated_offenders_timeout[j] = atoi(tmpt);
            minfo("Adding offenders timeout: %d (for #%d)",
                repeated_offenders_timeout[j], j + 1);
            j++;
            repeated_offenders_timeout[j] = 0;
            if (j >= 6)
            {
                break;
            }
            i++;
        }

        free(repeated_t);

        for (i = 0; repeated_a[i]; i++)
        {
            free(repeated_a[i]);
        }

        free(repeated_a);
    }

    OS_ClearXML(&xml);

    return (is_disabled);
}

cJSON *getARConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *ar = cJSON_CreateObject();
    unsigned int i;

    if (is_disabled) cJSON_AddStringToObject(ar,"disabled","yes"); else cJSON_AddStringToObject(ar,"disabled","no");
    if (*repeated_offenders_timeout) {
        cJSON *rot = cJSON_CreateArray();
        for (i=0;repeated_offenders_timeout[i];i++) {
            cJSON_AddItemToArray(rot,cJSON_CreateNumber(repeated_offenders_timeout[i]));
        }
        cJSON_AddItemToObject(ar,"repeated_offenders",rot);
    }

    if (ar_allowlist) {
        cJSON *allowlist = cJSON_CreateArray();
        for (i = 0; ar_allowlist[i]; i++) {
            cJSON_AddItemToArray(allowlist, cJSON_CreateString(ar_allowlist[i]->ip));
        }
        cJSON_AddItemToObject(ar, "allowlist", allowlist);
    }

    cJSON_AddItemToObject(root,"active-response",ar);

    return root;
}


cJSON *getExecdInternalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *internals = cJSON_CreateObject();
    cJSON *execd = cJSON_CreateObject();

    cJSON_AddNumberToObject(execd,"request_timeout",req_timeout);
    cJSON_AddNumberToObject(execd,"max_restart_lock",max_restart_lock);

    cJSON_AddItemToObject(internals,"execd",execd);
    cJSON_AddItemToObject(root,"internal",internals);

    return root;
}


cJSON *getClusterConfig(void) {

#ifndef WIN32
    char req[] = "get_config";
    char *buffer = NULL;
    int sock = -1;
    char sockname[PATH_MAX + 1];
    ssize_t length;

    cJSON *cluster_config_cJSON;

    strcpy(sockname, CLUSTER_SOCK);

    if (sock = external_socket_connect(sockname, WAZUH_IPC_TIMEOUT), sock < 0) {
        switch (errno) {
        case ECONNREFUSED:
            merror("At getClusterConfig(): Could not connect to socket '%s': %s (%d).", sockname, strerror(errno), errno);
            break;

        default:
            merror("At getClusterConfig(): Could not connect to socket '%s': %s (%d).", sockname, strerror(errno), errno);
        }
        return NULL;
    }

    if (OS_SendSecureTCPCluster(sock, req, "", 0) != 0) {
        merror("send(): %s", strerror(errno));
        close(sock);
        return NULL;
    }

    os_calloc(OS_MAXSTR,sizeof(char),buffer);

    switch (length = OS_RecvSecureClusterTCP(sock, buffer, OS_MAXSTR), length) {
    case -2:
        merror("Cluster error detected");
        free(buffer);
        close(sock);
        return NULL;

    case -1:
        merror("At wcom_main(): OS_RecvSecureClusterTCP(): %s", strerror(errno));
        free(buffer);
        close(sock);
        return NULL;

    case 0:
        mdebug1("Empty message from local client.");
        free(buffer);
        close(sock);
        return NULL;

    case OS_MAXLEN:
        merror("Received message > %i", OS_MAXSTR);
        free(buffer);
        close(sock);
        return NULL;

    default:
        close(sock);
    }

    const char *jsonErrPtr;
    cluster_config_cJSON = cJSON_ParseWithOpts(buffer, &jsonErrPtr, 0);
    if (!cluster_config_cJSON) {
        mdebug1("Error parsing JSON event. %s", buffer);
        free(buffer);
        return NULL;
    }

    free(buffer);
    return cluster_config_cJSON;
#else
    return NULL;
#endif
}
