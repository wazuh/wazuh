/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../headers/shared.h"

#ifndef WM_OSQUERYNATIVE
#define WM_OSQUERYNATIVE

#define WM_OSQUERYNATIVE_LOGTAG ARGV0 ":osquery_native"

extern const wm_context WM_OSQUERYNATIVE_CONTEXT;

typedef struct task_osquery {
	char* sql_string;
    char* table;
	void* function;
	time_t refresh_rate;
	struct timespec last_refresh;
	struct task_osquery * next;
} task_osquery_t;



typedef struct wm_osquery_native_t {
   char *bin_path;
   char *config_path;
   int disable;
   task_osquery_t * task_list;
   int msg_delay;
   int queue_fd;
   void *remote_ondemand_call;
} wm_osquery_native_t;

int wm_osquery_native_configuration_reader(const OS_XML *xml, xml_node **nodes, wmodule *module);
void task_osquery_push(task_osquery_t* head, char* table, time_t refresh_rate);
void task_osquery_delete_list(task_osquery_t *head);
int wm_osquery_read_query(const OS_XML *xml, xml_node *node, task_osquery_t* tasks);
char* wm_osquery_read_table_name(xml_node* node);
#endif