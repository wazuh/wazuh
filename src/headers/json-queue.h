/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef JSON_QUEUE_H
#define JSON_QUEUE_H

#include <external/cJSON/cJSON.h>
#include "file-queue.h"

// Initializes queue. Equivalent to initialize every field to 0.
void jqueue_init(file_queue * queue);

/*
 * Open queue with the JSON alerts log file.
 * Returns 0 on success or -1 on error.
 */
int jqueue_open(file_queue * queue, int tail);

/*
 * Return next JSON object from the queue, or NULL if it is not available.
 * If no more data is available and the day has changed, queue is reloaded.
 */
cJSON * jqueue_next(file_queue * queue);

// Close queue
void jqueue_close(file_queue * queue);

/**
 * @brief Validate and parse a JSON object from a buffer
 *
 * @param queue pointer to the file_queue struct
 * @param buffer string with the JSON to be parsed
 * @param current_pos File position located as a backup
 * @return cJSON object with the read JSON, NULL in the JSON is invalid
 */
cJSON * jqueue_parse_json(file_queue * queue, char * buffer, int64_t current_pos);

#endif
