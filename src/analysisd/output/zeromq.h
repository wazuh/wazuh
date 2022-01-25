/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2015 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#ifdef ZEROMQ_OUTPUT_ENABLED

#ifndef ZEROMQ_H
#define ZEROMQ_H

#include "eventinfo.h"
#include <czmq.h>

void zeromq_output_event(const Eventinfo *lf);
#if CZMQ_VERSION_MAJOR == 2
void zeromq_output_start(const char *uri);
#elif CZMQ_VERSION_MAJOR >= 3
void zeromq_output_start(const char *uri, const char *client_cert_path, const char *server_cert_path);
#endif
void zeromq_output_end(void);

#endif /* ZEROMQ_H */

#endif /* ZEROMQ_OUTPUT_ENABLED */
