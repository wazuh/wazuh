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

/**
 * @brief Add 'credits' to the semaphore
 *
 * This is a private function.
 * @param credits to increase.
 */
void generate_eps_credits(unsigned int credits);

/**
 * @brief Increments the current cell eps counter
 *
 * This is a private function.
 */
void increase_event_counter(void);

/** Global definitions **/
limits_t limits;

bool load_limits(unsigned int eps, unsigned int timeframe) {
    if (eps > 0 && timeframe > 0) {

        limits_t *limits;
        os_malloc(sizeof(limits_t), limits);
        v->vector = (char **)malloc(initialSize * sizeof(char *));
        v->used = 0;
        v->size = initialSize;
        return v;

        limits.eps = eps;
        limits.timeframe = timeframe;
        limits.current_cell = 0;

        os_calloc(limits.timeframe, sizeof(unsigned int), limits.circ_buf);

        sem_init(&limits.credits_eps_semaphore, 0, limits.eps * limits.timeframe);

        limits.enabled = true;
        minfo("EPS limit enabled, EPS: '%d', timeframe: '%d'", eps, timeframe);
    } else {
        limits.enabled = false;
        minfo("EPS limit disabled");
    }
    
    return limits.enabled;
}

void update_limits(void) {
    if (limits.enabled) {
        w_mutex_lock(&limits.limit_eps_mutex);

        if (limits.current_cell < limits.timeframe - 1) {
            limits.current_cell++;
        } else {
            if (limits.circ_buf[0]) {
                generate_eps_credits(limits.circ_buf[0]);
            }
            memmove(limits.circ_buf, limits.circ_buf + 1, (limits.timeframe - 1) * sizeof(unsigned int));
            limits.circ_buf[limits.current_cell] = 0;
        }

        w_mutex_unlock(&limits.limit_eps_mutex);
    }
}

void get_eps_credit(void) {
    if (limits.enabled) {
        sem_wait(&limits.credits_eps_semaphore);
        increase_event_counter();
    }
}

bool limit_reached(unsigned int *value) {
    if (limits.enabled) {
        int credits = 0;

        sem_getvalue(&limits.credits_eps_semaphore, &credits);

        if (value) {
            *value = credits >= 0 ? (unsigned int)credits : 0;
        }

        if (credits <= 0) {
            return true;
        }
    }

    return false;
}

STATIC void generate_eps_credits(unsigned int credits) {
    for(unsigned int i = 0; i < credits; i++) {
        sem_post(&limits.credits_eps_semaphore);
    }
}

STATIC void increase_event_counter(void) {
    w_mutex_lock(&limits.limit_eps_mutex);
    limits.circ_buf[limits.current_cell]++;
    w_mutex_unlock(&limits.limit_eps_mutex);
}
