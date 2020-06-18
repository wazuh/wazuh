/*
 * Wazuh Integration with Osquery Wazuh fork
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuh_modules/wmodules.h"
#include <stdio.h>

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER
#endif

static const char *XML_DISABLED = "disabled";
static const char *XML_QUERY = "query";
static const char *XML_TABLE_NAME = "table_name";
static const char *XML_REFRESH_TIME = "refresh_time";
static const time_t DEFAULT_REFRESH_TIME = 60*60;
static const char *SQL_SELECT = "SELECT * FROM ";
static const char *SQL_SENTENCE_TERMINATOR = ";";

static short eval_bool(const char *str)
{
    return !str ? OS_INVALID : !strcmp(str, "yes") ? 1 : !strcmp(str, "no") ? 0 : OS_INVALID;
}


void task_osquery_push(task_osquery_t* head, char* table, time_t refresh_rate) {
	if (NULL != head && NULL != table) {
        if (is_string_alphanumeric(table)) {
            task_osquery_t* current = head;
            while (NULL != current->next) {
                current = current->next;
            }

            current->next = (task_osquery_t*)malloc(sizeof(task_osquery_t));
            memset(current->next, 0, sizeof(task_osquery_t));
                
            size_t string_size = strlen(SQL_SELECT)+strlen(table)+strlen(SQL_SENTENCE_TERMINATOR);
            current->next->sql_string = (char *)malloc(string_size + 1);
            memset(current->next->sql_string, 0, string_size + 1);

            strcat(current->next->sql_string, SQL_SELECT);
            strcat(current->next->sql_string, table);
            strcat(current->next->sql_string, SQL_SENTENCE_TERMINATOR);

            size_t table_string_size = strlen(table);
            current->next->table = (char *)malloc(table_string_size + 1);
            memset(current->next->table, 0, table_string_size + 1);

            strncpy(current->next->table, table, table_string_size);

            current->next->refresh_rate = refresh_rate;
            current->next->last_refresh.tv_sec = 0;

            current->next->next = NULL;
        }
	}
}

void task_osquery_delete_list(task_osquery_t *head) {
	task_osquery_t* current = head;
	task_osquery_t* next;

	while (NULL != current) {
		next = current->next;
		free(current->sql_string);
        free(current->table);
		free(current);
		current = next;
	}
}

// module configuration reader
int wm_osquery_native_configuration_reader(
    const OS_XML *xml,
    xml_node **nodes, 
    wmodule *module)
{
    int i;
    int ret_val = 0;

    UNREFERENCED_PARAMETER(nodes);

    wm_osquery_native_t *osquery_native_config = NULL;

    os_calloc(1, sizeof(wm_osquery_native_t), osquery_native_config);
    osquery_native_config->disable = FALSE;
    osquery_native_config->task_list = (task_osquery_t *) malloc(sizeof(task_osquery_t));
	memset(osquery_native_config->task_list, 0, sizeof(task_osquery_t));

    osquery_native_config->remote_ondemand_call = NULL;
    module->context = &WM_OSQUERYNATIVE_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = osquery_native_config;

    if (!nodes)
        return 0;

    for(i = 0; nodes[i]; ++i)
    {
        if(!nodes[i]->element)
        {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        }
        else if (!strcmp(nodes[i]->element, XML_DISABLED))
        {
            if (osquery_native_config->disable = eval_bool(nodes[i]->content), osquery_native_config->disable == OS_INVALID) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_DISABLED, WM_OSQUERYNATIVE_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_QUERY)) {
            if (wm_osquery_read_query(xml, nodes[i], osquery_native_config->task_list)) {
                return OS_INVALID;
            }
        }
        else {
            mwarn("No such tag <%s> at module '%s'.", nodes[i]->element, WM_OSQUERYNATIVE_CONTEXT.name);
        }

    }

    return ret_val;
}


int wm_osquery_read_query(const OS_XML *xml, xml_node *node, task_osquery_t* tasks) {
    char* table_name = NULL;
    XML_NODE chld_node = NULL;
    time_t refresh_time = DEFAULT_REFRESH_TIME;
    int j;

    int ret_val = 0;

    if (table_name = wm_osquery_read_table_name(node), NULL == table_name) {
        mwarn("Empty %s name.", XML_TABLE_NAME);
        return OS_INVALID;
    }

    if (chld_node = OS_GetElementsbyNode(xml, node), NULL == chld_node) {
        merror(XML_INVELEM, node->element);
        return OS_INVALID;
    }

    for (j = 0; chld_node[j]; ++j) {
        if (!strcmp(chld_node[j]->element, XML_REFRESH_TIME)) {
            refresh_time = string_to_time_t(chld_node[j]->content, DEFAULT_REFRESH_TIME);
        }
    }

    task_osquery_push(tasks, table_name, refresh_time);

    OS_ClearNode(chld_node);
    return ret_val;
}

char* wm_osquery_read_table_name(xml_node* node) {
    int i;

    for (i = 0; node->attributes && node->attributes[i]; i++) {
        if (!strcmp(node->attributes[i], XML_TABLE_NAME)) {
            return node->values[i];
        }
    }

    return NULL;
}