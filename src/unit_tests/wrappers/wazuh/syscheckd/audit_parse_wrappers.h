/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef AUDIT_PARSE_WRAPPERS
#define AUDIT_PARSE_WRAPPERS

void __wrap_audit_parse(char *buffer);

#endif // AUDIT_PARSE_WRAPPERS
