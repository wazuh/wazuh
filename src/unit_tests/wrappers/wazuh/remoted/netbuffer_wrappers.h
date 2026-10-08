/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WIN32

#ifndef NETBUFFER_WRAPPERS_H
#define NETBUFFER_WRAPPERS_H

#include "../../../../remoted/include/remoted.h"

void __wrap_nb_close(__attribute__((unused)) netbuffer_t * buffer, int sock);

void __wrap_nb_open(__attribute__((unused)) netbuffer_t * buffer, int sock, const struct sockaddr_storage * peer_info);

int __wrap_nb_queue(__attribute__((unused)) netbuffer_t * buffer, int socket, char * crypt_msg, ssize_t msg_size, char * agent_id);

int __wrap_nb_recv(__attribute__((unused)) netbuffer_t * buffer, int sock);

int __wrap_nb_send(__attribute__((unused)) netbuffer_t * buffer, int sock);

int __wrap_nb_queue_nowait(__attribute__((unused)) netbuffer_t * buffer, int socket, const char * msg, size_t msg_size);

void __wrap_nb_set_authenticated(__attribute__((unused)) netbuffer_t * buffer, int sock);

size_t __wrap_nb_unauthenticated_count(__attribute__((unused)) netbuffer_t * buffer);

int * __wrap_nb_collect_unauthenticated(__attribute__((unused)) netbuffer_t * buffer, time_t deadline, size_t * count);

#endif

#endif
