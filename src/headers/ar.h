/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Active Response shared headers */

#ifndef AR_H
#define AR_H

/* Recipient agents */
#define ALL_AGENTS      0000001
#define REMOTE_AGENT    0000002
#define SPECIFIC_AGENT  0000004
#define AS_ONLY         0000010

/* We now also support non Active Response messages in here */
#define NO_AR_MSG       0000020

#define ALL_AGENTS_C     'A'
#define REMOTE_AGENT_C   'R'
#define SPECIFIC_AGENT_C 'S'
#define NONE_C           'N'
#define NO_AR_C          '!'

/* AR Queues to use */
#define REMOTE_AR       00001
#define LOCAL_AR        00002

#endif /* AR_H */
