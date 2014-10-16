/* @(#) $Id: ./src/analysisd/active-response.h, 2011/09/08 dcid Exp $
 */

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

#include "config/config.h"
#include "config/active-response.h"
#include "list_op.h"


/** void AR_Init()
 * Initializing active response.
  */
void AR_Init();

/** int AR_ReadConfig(const char *cfgfile)
 * Reads active response configuration and write them
 * to the appropriate lists.
 */
int AR_ReadConfig(const char *cfgfile);


/* Active response commands */
OSList *ar_commands;

/* Active response information */
OSList *active_responses;


#endif
