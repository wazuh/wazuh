/* Copyright (C) Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef LEGACY_TARGET_NAME_H
#define LEGACY_TARGET_NAME_H

#include <stdbool.h>

#include "client-config.h"

/* How a manager is named in the legacy <client> warnings, and the key two of them are
 * compared by.
 *
 * `dialed` is host:port/prefix the way the other log lines print the manager: an IPv6 host
 * expanded and bracketed as the agent stores it, with its zone when it has one. `key` is the
 * same target with what doesn't change the peer folded away: hostname case, and the short
 * forms of an address the URL parser rewrites (127.1). Both are allocated; free them. */

/**
 * @brief Name a raw legacy target. An <endpoint> is parsed without logging; one that doesn't
 *        parse is named, and compared, by its raw text.
 */
void w_legacy_name_target(const char *value, bool is_endpoint, char **dialed, char **key);

/**
 * @brief Name the manager entry the agent is set to use.
 */
void w_legacy_name_server(const agent_server *server, char **dialed, char **key);

#endif /* LEGACY_TARGET_NAME_H */
