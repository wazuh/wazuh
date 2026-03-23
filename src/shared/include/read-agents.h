/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef CRAGENT_H
#define CRAGENT_H

#include <cJSON.h>

/* Status */
typedef enum agent_status_t {
    GA_STATUS_ACTIVE = 12,
    GA_STATUS_NACTIVE,
    GA_STATUS_NEVER,
    GA_STATUS_PENDING,
    GA_STATUS_UNKNOWN
} agent_status_t;

/* Unique key for each agent */
typedef struct _agent_info {
    char *last_keepalive;
    char *syscheck_time;
    char *syscheck_endtime;
    char *os;
    char *version;
    char *config_sum;
    char *merged_sum;
    agent_status_t connection_status;
} agent_info;

/* Delete diff folders */
void delete_diff(const char *name);

#ifndef WIN32
/* Return the unix permission string
 * Returns a pointer to a local static array
 */
char *agent_file_perm(mode_t mode);
#endif

#endif /* CRAGENT_H */
