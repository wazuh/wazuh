/* Copyright (C) 2015 Trend Micro Inc.
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

void zeromq_output_event(const Eventinfo *lf);
void zeromq_output_start(const char *uri);
void zeromq_output_end(void);


#endif /* _ZEROMQ_H_ */

#endif /* ZEROMQ_OUTPUT_ENABLED */
