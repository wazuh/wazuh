/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef SEECHANGES_WRAPPERS_H
#define SEECHANGES_WRAPPERS_H

char *__wrap_seechanges_addfile(const char *filename);

char *__wrap_seechanges_get_diff_path(char *path);

#endif
