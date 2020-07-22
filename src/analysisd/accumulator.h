/* Copyright (C) 2015-2020, Wazuh Inc.
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


/**
 * @brief Hash where save data which have same id
 *
 * Only for Analysisd use
 */
OSHash *os_analysisd_acm_store;

/**
 * @brief Counter of the number of times purge
 *
 * Only for Analysisd use
 */
int os_analysisd_acm_lookups;

/**
 * @brief Counter of interval time since the last purge
 *
 * Only for Analysisd use
 */
time_t os_analysisd_acm_purge_ts;

/**
 * @brief Initialize accumulator engine
 *
 * @param acm_store
 * @param acm_purge_ts
 * @return 1 on succes, otherwise 0
 */
int Accumulate_Init(OSHash **acm_store, int *acm_lookups, time_t *acm_purge_ts);

/**
 * @brief Accumulate data from events sharing the same ID
 *
 * @param lf EventInfo to proccess
 * @param acm_store Hash where save data which have same ID
 * @param acm_lookups
 * @param acm_purge_ts
 * @return EventInfo passed from input
 */
Eventinfo *Accumulate(Eventinfo *lf, OSHash **acm_store, int *acm_lookups, time_t *acm_purge_ts);

/**
 * @brief Purge the cache as needed
 *
 * @param acm_store
 * @param acm_lookups
 * @param acm_purge_ts
 */
void Accumulate_CleanUp(OSHash **acm_store, int *acm_lookups, time_t *acm_purge_ts);

#endif /* ACCUMULATOR_H */
