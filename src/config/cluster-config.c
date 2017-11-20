/*
 * Cluster settings manager
 * Copyright (C) 2017 Wazuh Inc.
 * Oct 16, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "config.h"
#include "global-config.h"


int Read_Cluster(XML_NODE node, void *d1, __attribute__((unused)) void *d2) {

    static const char *cluster_name = "name";
    static const char *node_name = "node_name";
    static const char *node_type = "node_type";
    static const char *key = "key";
    static const char *interval = "interval";
    static const char *nodes = "nodes";
    static const char *hidden = "hidden";
    static const char *port = "port";
    static const char *bind_addr = "bind_addr";


    _Config *Config;
    Config = (_Config *)d1;
    int i;

     for (i = 0; node[i]; i++) {
         if (!node[i]->element) {
             merror(XML_ELEMNULL);
             return OS_INVALID;
         } else if (!node[i]->content) {
             merror(XML_VALUENULL, node[i]->element);
             return OS_INVALID;
         } else if (!strcmp(node[i]->element, cluster_name)) {
             os_strdup(node[i]->content, Config->cluster_name);
         } else if (!strcmp(node[i]->element, node_name)) {
             os_strdup(node[i]->content, Config->node_name);
         } else if (!strcmp(node[i]->element, node_type)) {
         } else if (!strcmp(node[i]->element, key)) {
         } else if (!strcmp(node[i]->element, hidden)) {
             Config->hide_cluster_info = 1;
         } else if (!strcmp(node[i]->element, interval)) {
         } else if (!strcmp(node[i]->element, nodes)) {
         } else if (!strcmp(node[i]->element, port)) {
         } else if (!strcmp(node[i]->element, bind_addr)) {
         } else {
             merror(XML_INVELEM, node[i]->element);
             return OS_INVALID;
         }
     }

     return 0;
 }
