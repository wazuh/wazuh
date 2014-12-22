/* @(#) $Id: ./src/analysisd/picviz.h, 2011/09/08 dcid Exp $
 */

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

#include <stdio.h>
#include "eventinfo.h"

#ifndef _PICVIZ_H_
#define _PICVIZ_H_

void OS_PicvizOpen(char *socket);
void OS_PicvizLog(Eventinfo *lf);
void OS_PicvizClose(void);

#endif /* _PICVIZ_H_ */

#endif
