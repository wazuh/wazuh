/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _AR__H
#define _AR__H

#include "config/active-response.h"
#include "config/config.h"
#include "list_op.h"

/* Initialize active response */
void AR_Init(void);

/* Read active response configuration and write it
 * to the appropriate lists.
 */
int AR_ReadConfig(const char *cfgfile);

/* Active response information */
extern OSList *active_responses;

#endif /* _AR__H */

