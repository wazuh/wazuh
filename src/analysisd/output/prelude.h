/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef PRELUDE_OUTPUT_ENABLED

#ifndef _PRELUDE_H_
#define _PRELUDE_H_

#include "eventinfo.h"

/* Start Prelude client */
void prelude_start(const char *profile, int argc, char **argv);

/* Log to Prelude */
void OS_PreludeLog(const Eventinfo *lf);

#endif /* _PRELUDE_H_ */

#endif /* PRELUDE_OUTPUT_ENABLED */
