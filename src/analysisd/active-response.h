/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef ACTIVE_RESPONSE_H
#define ACTIVE_RESPONSE_H

#include "../config/active-response.h"
#include "../config/config.h"
#include "list_op.h"

/* Initialize active response */
void AR_Init(void);

/* Read active response configuration and write it
 * to the appropriate lists.
 */
int AR_ReadConfig(const char *cfgfile);

/* Active response information */
extern OSList *active_responses;
extern OSList *ar_commands;

#endif /* ACTIVE_RESPONSE_H */
