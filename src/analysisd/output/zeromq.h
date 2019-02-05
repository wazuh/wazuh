/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2015 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#ifdef ZEROMQ_OUTPUT_ENABLED

#ifndef _ZEROMQ_H_
#define _ZEROMQ_H_

#include "eventinfo.h"
#include <czmq.h>

void zeromq_output_event(const Eventinfo *lf);
#if CZMQ_VERSION_MAJOR == 2
void zeromq_output_start(const char *uri);
#elif CZMQ_VERSION_MAJOR >= 3
void zeromq_output_start(const char *uri, const char *client_cert_path, const char *server_cert_path);
#endif
void zeromq_output_end(void);


#endif /* _ZEROMQ_H_ */

#endif /* ZEROMQ_OUTPUT_ENABLED */
