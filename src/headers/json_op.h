/*
 * JSON support library
 * Copyright (C) 2018 Wazuh Inc.
 * May 11, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef JSON_OP_H
#define JSON_OP_H

#define JSON_MAX_FSIZE 4194304
#define JSON_MAX_FSIZE_TEXT "4 MiB"

#include <external/cJSON/cJSON.h>

cJSON * json_fread(const char * path);
int json_fwrite(const char * path, const cJSON * item);

#endif
