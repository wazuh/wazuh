/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef FTS_H
#define FTS_H

#include "eventinfo.h"

/* FTS queues */
#define FTS_QUEUE "queue/fts/fts-queue"
#define IG_QUEUE  "queue/fts/ig-queue"

/**
 * @brief Structure to save previous fts events
 */
extern OSList *os_analysisd_fts_list;

/**
 * @brief Structure to save fts values processed
 */
extern OSHash *os_analysisd_fts_store;


/**
 * @brief Initialize FTS engine
 * @param threads number of analysisd threads
 * @param fts_list List which save fts previous events
 * @param fts_store Hash table which save fts values processed previously
 * @return 1 on success, 0 on failure
 */
int FTS_Init(int threads, OSList **fts_list, OSHash **fts_store);

/**
 * @brief Save fts value in queue/fts/ig-queue to ignore it next time
 *
 * It only use for Analysisd
 *
 * @param lf Event to add to ignore
 * @param pos Position of ignore file in fp_ignore
 */
void AddtoIGnore(Eventinfo *lf, int pos);

/**
 * @brief Check if the event is to be ignored
 * @param lf Event to check if must be ignored
 * @param pos Position of ignore file in fp_ignore
 * @return if must be ignored return 1, otherwise return 0
 */
int IGnore(Eventinfo *lf, int pos);

/**
 * @brief Check if fts value was present in previous events
 * @param lf Event to process
 * @param fts_list List which save fts previous events
 * @param fts_store hash table which save fts values processed previously
 * @return Null if FTS is already present or in case of failure, otherwise return value
 */
char * FTS(Eventinfo *lf, OSList **fts_list, OSHash **fts_store);

/**
 * @brief Save value in fts-queue
 * @param _line Value to print in fts-queue
 */
void FTS_Fprintf(char * _line);

/**
 * @brief Flush file fts-queue
 */
void FTS_Flush();

/**
 * @brief Reload FTS engine
 * @param fts_list List which save fts previous events (*fts_list should be NULL)
 * @param fts_store Hash table which save fts values processed previously (*fts_store should be NULL)
 * @return 1 on success
 * @return 0 on success but with not loaded fts-queue from file
 * @return -1 on failure
 */
int FTS_HotReload(OSList **fts_list, OSHash **fts_store);


/* Global variables */
extern unsigned int fts_minsize_for_str;
extern int fts_list_size;

#endif /* FTS_H */
