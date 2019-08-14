/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _AGENTLESSDCONFIG_H
#define _AGENTLESSDCONFIG_H

/* Entry states */
#define LESSD_STATE_CONNECTED       0x001
#define LESSD_STATE_PERIODIC        0x002
#define LESSD_STATE_DIFF            0x004
#define LESSD_USE_SU                0x010
#define LESSD_USE_SUDO              0x020

/* Structure for each entry */
typedef struct _agentlessd_entries {
    short int state;

    int frequency;
    time_t current_state;
    int port;
    int error_flag;

    char *type;
    char **server;
    const char *options;
    char *command;

} agentlessd_entries;

/* Configuration structure */
typedef struct _agentlessd_config {
    int queue;
    agentlessd_entries **entries;

} agentlessd_config;

#endif /* _AGENTLESSDCONFIG_H */

