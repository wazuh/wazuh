/*
 * Wazuh Shared Configuration Manager
 * Copyright (C) 2015, Wazuh Inc.
 * April 3, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef REQUEST_WRAPPERS_H
#define REQUEST_WRAPPERS_H

int __wrap_req_save(const char * counter, const char * buffer, size_t length);

int __wrap_req_send_and_wait(const char * agent_id, const char * payload, size_t length, char ** response, int timeout_sec);

#endif /* REQUEST_WRAPPERS_H */
