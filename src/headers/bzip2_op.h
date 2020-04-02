/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 * December 18, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "../external/bzip2/bzlib.h"
#include "../error_messages/error_messages.h"

int bzip2_compress(const char *file, const char *filebz2);
int bzip2_uncompress(const char *file, const char *filebz2);
