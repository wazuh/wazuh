/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef JSON_QUEUE_WRAPPERS_H
#define JSON_QUEUE_WRAPPERS_H

#include "../headers/shared.h"

int __wrap_jqueue_open(__attribute__((unused)) file_queue *queue, __attribute__((unused)) int tail);

cJSON * __wrap_jqueue_next(__attribute__((unused)) file_queue * queue);

#endif