/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef LIMITS_H
#define LIMITS_H

#include <stdbool.h>
#include <semaphore.h>

/* EPS limits struct */
typedef struct _limits_t {
    unsigned int eps;
    unsigned int timeframe;
    unsigned int current_cell;
    unsigned int * circ_buf;
    bool enabled;
} limits_t;

/**
 * @brief Load the limits structure
 * @param eps eps amount
 * @param timeframe timeframe size
 * @param maximum_found eps amount block found
 */
void load_limits(unsigned int eps, unsigned int timeframe, bool maximum_found);

/**
 * @brief Update and validate limits
 */
void update_limits(void);

/**
 * @brief Get a credit to process an event
 */
void get_eps_credit(void);

/**
 * @brief Check if the limit has been reached
 * @param value store the current available credits
 * @return true if limit reached, false otherwise
 */
bool limit_reached(unsigned int *value);

#endif /* LIMITS_H */
