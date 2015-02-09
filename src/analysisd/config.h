/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _CONFIG__H
#define _CONFIG__H

#include "config/config.h"
#include "config/global-config.h"

extern long int __crt_ftell; /* Global ftell pointer */
extern _Config Config;       /* Global Config structure */

int GlobalConf(const char *cfgfile);

#endif /* _CONFIG__H */

