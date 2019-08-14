/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2015 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DODIFF_H_
#define _DODIFF_H_

#include "rules.h"
#include "eventinfo.h"

int doDiff(RuleInfo *rule, Eventinfo *lf);


#endif /* _DODIFF_H_ */
