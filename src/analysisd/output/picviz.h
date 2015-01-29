/* Copyright (C) 2009 Sebastien Tricaud
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifdef PICVIZ_OUTPUT_ENABLED

#ifndef _PICVIZ_H_
#define _PICVIZ_H_

#include "eventinfo.h"

void OS_PicvizOpen(const char *socket);
void OS_PicvizLog(const Eventinfo *lf);
void OS_PicvizClose(void);

#endif /* _PICVIZ_H_ */

#endif /* PICVIZ_OUTPUT_ENABLED */
