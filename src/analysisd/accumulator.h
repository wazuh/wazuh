/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __ACCUMULATOR_H
#define __ACCUMULATOR_H

#include "eventinfo.h"

/* Accumulator Functions */
int Accumulate_Init(void);
Eventinfo *Accumulate(Eventinfo *lf);
void Accumulate_CleanUp(void);

#endif /* __ACCUMULATOR_H */

