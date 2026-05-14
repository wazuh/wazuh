/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef STDIO_WRAPPERS_LIBPLIST_H
#define STDIO_WRAPPERS_LIBPLIST_H

#include "external/libplist/include/plist/plist.h"

#undef plist_from_bin
#define plist_from_bin wrap_plist_from_bin
#undef plist_to_xml
#define plist_to_xml wrap_plist_to_xml
#undef plist_free
#define plist_free wrap_plist_free

void wrap_plist_from_bin (char * bin, size_t size, plist_t *node);
void wrap_plist_to_xml (plist_t *node, char ** xml, uint32_t *size);
void wrap_plist_free(plist_t node);

#endif