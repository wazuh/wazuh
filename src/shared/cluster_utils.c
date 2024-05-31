/*
 * URL download support library
 * Copyright (C) 2015, Wazuh Inc.
 * October 26, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "../config/config.h"
#include "../config/global-config.h"

int w_is_worker(void) {
    OS_XML xml;
    const char * xmlf[] = {"ossec_config", "cluster", NULL};
    const char * xmlf2[] = {"ossec_config", "cluster", "node_type", NULL};
    const char * xmlf3[] = {"ossec_config", "cluster", "disabled", NULL};
    const char *cfgfile = OSSECCONF;
    int is_worker = OS_INVALID;

    if (OS_ReadXML(cfgfile, &xml) < 0) {
        mdebug1(XML_ERROR, cfgfile, xml.err, xml.err_line);
    } else {
        char * cl_config = OS_GetOneContentforElement(&xml, xmlf);
        if (cl_config && cl_config[0] != '\0') {
            char * cl_type = OS_GetOneContentforElement(&xml, xmlf2);
                if (cl_type && cl_type[0] != '\0') {
                    char * cl_status = OS_GetOneContentforElement(&xml, xmlf3);
                    if(cl_status && cl_status[0] != '\0'){
                        if (!strcmp(cl_status, "no")) {
                            if (!strcmp(cl_type, "client") || !strcmp(cl_type, "worker")) {
                                is_worker = 1;
                            } else {
                                is_worker = 0;
                            }
                        } else {
                            is_worker = 0;
                        }
                    } else {
                        if (!strcmp(cl_type, "client") || !strcmp(cl_type, "worker")) {
                            is_worker = 1;
                        } else {
                            is_worker = 0;
                        }
                    }
                    free(cl_status);
                    free(cl_type);
                }
            free(cl_config);
        } else {
            is_worker = 0;
        }
    }
    OS_ClearXML(&xml);

    return is_worker;
}

int w_is_single_node(int* is_worker) {
    OS_XML xml;
    const char * xmlf[] = {"ossec_config", "cluster", NULL};
    const char * xmlf2[] = {"ossec_config", "cluster", "node_type", NULL};
    const char * xmlf3[] = {"ossec_config", "cluster", "disabled", NULL};
    const char *cfgfile = OSSECCONF;
    int _is_worker = OS_INVALID;
    int is_single_node = OS_INVALID;

    if (OS_ReadXML(cfgfile, &xml) < 0) {
        mdebug1(XML_ERROR, cfgfile, xml.err, xml.err_line);
    } else {
        char * cl_config = OS_GetOneContentforElement(&xml, xmlf);
        if (cl_config && cl_config[0] != '\0') {
            char * cl_type = OS_GetOneContentforElement(&xml, xmlf2);
            if (cl_type && cl_type[0] != '\0') {
                char * cl_status = OS_GetOneContentforElement(&xml, xmlf3);
                if(cl_status && cl_status[0] != '\0'){
                    if (!strcmp(cl_status, "no")) {
                        is_single_node = 0;
                        if (!strcmp(cl_type, "client") || !strcmp(cl_type, "worker")) {
                            _is_worker = 1;
                        } else {
                            _is_worker = 0;
                        }
                    } else {
                        is_single_node = 1;
                    }
                } else {
                    is_single_node = 1;
                }
                free(cl_status);
                free(cl_type);
            } else {
                is_single_node = 1;
            }
            free(cl_config);
        } else {
            is_single_node = 1;
        }
    }
    OS_ClearXML(&xml);

    if (is_worker) {
        *is_worker = _is_worker;
    }

    return is_single_node;
}

char *get_master_node(void) {
    OS_XML xml;
    const char * xmlf[] = {"ossec_config", "cluster", "nodes", "node", NULL};
    const char *cfgfile = OSSECCONF;
    char *master_node = NULL;

    if (OS_ReadXML(cfgfile, &xml) < 0) {
        mdebug1(XML_ERROR, cfgfile, xml.err, xml.err_line);
    } else {
        master_node = OS_GetOneContentforElement(&xml, xmlf);
    }

    OS_ClearXML(&xml);

    if (!master_node) {
        master_node = strdup("undefined");
    }

    return master_node;
}

char *get_node_name(void) {
    OS_XML xml;
    const char * xmlf[] = {"ossec_config", "cluster", "node_name", NULL};
    const char *cfgfile = OSSECCONF;
    char *node_name = NULL;

    if (OS_ReadXML(cfgfile, &xml) < 0) {
        mdebug1(XML_ERROR, cfgfile, xml.err, xml.err_line);
    } else {
        node_name = OS_GetOneContentforElement(&xml, xmlf);
    }

    OS_ClearXML(&xml);

    if (!node_name) {
        node_name = strdup("undefined");
    }

    return node_name;
}

char *get_cluster_name(void) {
    OS_XML xml;
    const char * xmlf[] = {"ossec_config", "cluster", "name", NULL};
    const char *cfgfile = OSSECCONF;
    char *cluster_name = NULL;

    if (OS_ReadXML(cfgfile, &xml) < 0) {
        mdebug1(XML_ERROR, cfgfile, xml.err, xml.err_line);
    } else {
        cluster_name = OS_GetOneContentforElement(&xml, xmlf);
    }

    OS_ClearXML(&xml);

    if (!cluster_name) {
        cluster_name = strdup("undefined");
    }

    return cluster_name;
}

/**
 * Get the cluster status
 * @return true if the cluster is enabled, false otherwise
 */
bool get_cluster_status(void) {
    OS_XML xml;
    const char * xmlf[] = {"ossec_config", "cluster", "disabled", NULL};
    const char *cfgfile = OSSECCONF;
    bool cluster_status = false;

    if (OS_ReadXML(cfgfile, &xml) < 0) {
        mdebug1(XML_ERROR, cfgfile, xml.err, xml.err_line);
    } else {
        char *status = OS_GetOneContentforElement(&xml, xmlf);
        if (status) {
            if (strcmp(status, "no") == 0) {
                cluster_status = true;
            }
            free(status);
        }
    }

    OS_ClearXML(&xml);

    return cluster_status;
}
