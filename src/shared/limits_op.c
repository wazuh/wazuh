/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2010-2012 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include "shared.h"
#include "limits_op.h"

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

/**
 * @brief Add 'credits' to the semaphore
 *
 * @param limits Pointer to the limits_t struct.
 * This is a private function.
 */
STATIC void generate_eps_credits(limits_t *limits);

/**
 * @brief Increments the current cell eps counter
 *
 * @param limits Pointer to the limits_t struct.
 * This is a private function.
 */
STATIC void increase_event_counter(limits_t *limits);

limits_t *init_limits(unsigned int eps, unsigned int timeframe) {
    limits_t *limits = NULL;
    os_malloc(sizeof(limits_t), limits);

    if (eps > 0 && timeframe > 0) {
        limits->eps = eps;
        limits->timeframe = timeframe;
        limits->current_cell = 0;
        limits->limit_eps_mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;

        os_calloc(limits->timeframe, sizeof(unsigned int), limits->circ_buf);

        sem_init(&limits->credits_eps_semaphore, 0, limits->eps * limits->timeframe);

        limits->enabled = true;
        minfo("EPS limit enabled, EPS: '%d', timeframe: '%d'", eps, timeframe);
    } else {
        limits->enabled = false;
        minfo("EPS limit disabled");
    }

    return limits;
}

void update_limits(limits_t *limits) {
    if (limits->enabled) {
        w_mutex_lock(&limits->limit_eps_mutex);

        if (limits->current_cell < limits->timeframe - 1) {
            limits->current_cell++;
        } else {
            if (limits->circ_buf[0]) {
                generate_eps_credits(limits);
            }
            memmove(limits->circ_buf, limits->circ_buf + 1, (limits->timeframe - 1) * sizeof(unsigned int));
            limits->circ_buf[limits->current_cell] = 0;
        }

        w_mutex_unlock(&limits->limit_eps_mutex);
    }
}

void get_eps_credit(limits_t *limits) {
    if (limits && limits->enabled) {
        sem_wait(&limits->credits_eps_semaphore);
        increase_event_counter(limits);
    }
}

bool limit_reached(limits_t *limits, unsigned int *value) {
    if (limits->enabled) {
        int credits = 0;

        sem_getvalue(&limits->credits_eps_semaphore, &credits);

        if (value) {
            *value = credits >= 0 ? (unsigned int)credits : 0;
        }

        if (credits <= 0) {
            return true;
        }
    }

    return false;
}

void free_limits(limits_t **limits) {
    if ((*limits)->enabled) {
        os_free((*limits)->circ_buf);
    }
    os_free((*limits));
}

STATIC void generate_eps_credits(limits_t *limits) {
    for(unsigned int i = 0; i < limits->circ_buf[0]; i++) {
        sem_post(&limits->credits_eps_semaphore);
    }
}

STATIC void increase_event_counter(limits_t *limits) {
    w_mutex_lock(&limits->limit_eps_mutex);
    limits->circ_buf[limits->current_cell]++;
    w_mutex_unlock(&limits->limit_eps_mutex);
}
