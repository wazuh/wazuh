/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#ifdef PRELUDE_OUTPUT_ENABLED

#ifndef PRELUDE_H
#define PRELUDE_H

#include "eventinfo.h"

/* Start Prelude client */
void prelude_start(const char *profile, int argc, char **argv);

/* Log to Prelude */
void OS_PreludeLog(const Eventinfo *lf);

#endif /* PRELUDE_H */

#endif /* PRELUDE_OUTPUT_ENABLED */
