/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#ifndef ACCUMULATOR_H
#define ACCUMULATOR_H

#include "eventinfo.h"

/* Accumulator Functions */
int Accumulate_Init(void);
Eventinfo *Accumulate(Eventinfo *lf);
void Accumulate_CleanUp(void);

#endif /* ACCUMULATOR_H */
