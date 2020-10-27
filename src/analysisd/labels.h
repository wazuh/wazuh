/*
 * Label data cache
 * Copyright (C) 2015-2020, Wazuh Inc.
 * February 27, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef LABELS_H
#define LABELS_H

#include <pthread.h>

typedef struct wlabel_data_t {
    wlabel_t *labels;
    time_t mtime;
} wlabel_data_t;

/* Initialize label cache */
int labels_init();

/* Finalize label cache */
void labels_finalize();

/**
 * @brief Finds the label array of an agent that generated an event.
 * 
 * @param agent_id The ID of the agent for whom the labels are requested.
 * @param sock The Wazuh DB socket connection.
 * @retval The agent's labels array on success. NULL on error.
 */
wlabel_t* labels_find(char *agent_id, int *sock);

#endif
