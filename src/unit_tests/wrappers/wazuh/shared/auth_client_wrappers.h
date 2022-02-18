/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef AUTH_CLIENT_WRAPPERS_H
#define AUTH_CLIENT_WRAPPERS_H

int __wrap_auth_remove_agent(__attribute__((unused)) int sock, const char *id, __attribute__((unused)) int json_format);

#endif
