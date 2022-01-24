/* Copyright (C) 2015, Wazuh Inc.
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
 * @brief Counter of the number of times purged
 *
 * Only for Analysisd use
 */
extern int os_analysisd_acm_lookups;

/**
 * @brief Counter of interval time since the last purge
 *
 * Only for Analysisd use
 */
extern time_t os_analysisd_acm_purge_ts;

/**
 * @brief Initialize accumulator engine
 * @param acm_store Hash to save data which have the same id
 * @param acm_lookups counter of the number of times purged
 * @param acm_purge_ts counter of interval time since the last purge
 * @return 1 on succes, otherwise 0
 */
int Accumulate_Init(OSHash **acm_store, int *acm_lookups, time_t *acm_purge_ts);

/**
 * @brief Accumulate data from events sharing the same ID
 * @param lf EventInfo to proccess
 * @param acm_store Hash to save data which have the same id
 * @param acm_lookups counter of the number of times purged
 * @param acm_purge_ts counter of interval time since the last purge
 * @return EventInfo passed from input
 */
Eventinfo *Accumulate(Eventinfo *lf, OSHash **acm_store, int *acm_lookups, time_t *acm_purge_ts);

/**
 * @brief Purge the cache as needed
 * @param acm_store Hash to save data which have the same id
 * @param acm_lookups counter of the number of times purged
 * @param acm_purge_ts counter of interval time since the last purge
 */
void Accumulate_CleanUp(OSHash **acm_store, int *acm_lookups, time_t *acm_purge_ts);

/**
 * @brief Free accumulate hash table
 * 
 * @param acm_store accumulate hash table to free
 */
void w_analysisd_accumulate_free(OSHash **acm_store);

#endif /* ACCUMULATOR_H */
