/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef JSON_QUEUE_H
#define JSON_QUEUE_H

#include <cJSON.h>
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
 * @brief Read and validate a JSON alert from the file queue
 *
 * @param queue pointer to the file_queue struct
 * @post The flag variable may be set to CRALERT_READ_FAILED if the read operation got no data.
 * @post The read position is restored if failed to get a JSON object.
 * @retval NULL No data read or could not get a valid JSON object. Pointer to the JSON object otherwise.
 */
cJSON * jqueue_parse_json(file_queue * queue);

#endif
