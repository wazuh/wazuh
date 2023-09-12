/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef LIMITS_OP_H
#define LIMITS_OP_H

#include <stdbool.h>
#include <semaphore.h>

/* EPS limits struct */
typedef struct _limits_t {
    unsigned int eps;
    unsigned int timeframe;
    unsigned int current_cell;
    unsigned int * circ_buf;
    bool enabled;
    pthread_mutex_t limit_eps_mutex;
    sem_t credits_eps_semaphore;
} limits_t;

/**
 * @brief Initialize a limits_t struct with the given eps and timeframe settings.
 *
 * @param eps Number of events per second configured (credits).
 * @param timeframe Frequency (seconds) at which the structure credits will be updated.
 * @return Pointer to the limits_t initialized.
 */
limits_t *init_limits(unsigned int eps, unsigned int timeframe);

/**
 * @brief Update and validate limits
 *
 * @param limits Pointer to the limits_t struct.
 */
void update_limits(limits_t *limits);

/**
 * @brief Get a credit to process an event
 *
 * @param limits Pointer to the limits_t struct.
 */
void get_eps_credit(limits_t *limits);

/**
 * @brief Check if the limit has been reached
 *
 * @param limits Pointer to the limits_t struct.
 * @param value store the current available credits
 * @return true if limit reached, false otherwise
 */
bool limit_reached(limits_t *limits, unsigned int *value);

/**
 * @brief Initialize a limits_t struct with the given eps and timeframe settings.
 *
 * @param limits Pointer to the limits_t pointer struct to freed.
 */
void free_limits(limits_t **limits);

#endif /* LIMITS_OP_H */
