/***************************************************************************
 *   Copyright (C) 2007 International Business Machines  Corp.             *
 *   All Rights Reserved.                                                  *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 *                                                                         *
 * Authors:                                                                *
 *   Klaus Heinrich Kiwi <klausk@br.ibm.com>                               *
 *   based on code by Steve Grubb <sgrubb@redhat.com>                      *
 ***************************************************************************/

#include "zos-remote-queue.h"

#include <stdlib.h>
#include <pthread.h>
#include <syslog.h>
#include "zos-remote-log.h"

static volatile BerElement **q;
static pthread_mutex_t queue_lock;
static pthread_cond_t queue_nonempty;
static unsigned int q_next, q_last, q_depth;


int init_queue(unsigned int size)
{
    unsigned int i;

    q_next = 0;
    q_last = 0;
    q_depth = size;
    q = malloc(q_depth * sizeof(BerElement *));
    if (q == NULL)
        return -1;

    for (i=0; i<q_depth; i++) 
        q[i] = NULL;

    /* Setup IPC mechanisms */
    pthread_mutex_init(&queue_lock, NULL);
    pthread_cond_init(&queue_nonempty, NULL);

    return 0;
}

void enqueue(BerElement *ber)
{
    unsigned int n, retry_cnt = 0;

retry:
    /* We allow 3 retries and then its over */
    if (retry_cnt > 3) {
        log_err("queue is full - dropping event");
        return;
    }
    pthread_mutex_lock(&queue_lock);

    /* OK, have lock add event */
    n = q_next%q_depth;
    if (q[n] == NULL) {
        q[n] = ber;
        q_next = (n+1) % q_depth;
        pthread_cond_signal(&queue_nonempty);
        pthread_mutex_unlock(&queue_lock);
    } else {
        pthread_mutex_unlock(&queue_lock);
        pthread_yield(); /* Let dequeue thread run to clear queue */
        retry_cnt++;
        goto retry;
    }
}

BerElement *dequeue(void)
{
    BerElement *ber;
    unsigned int n;

    /* Wait until its got something in it */
    pthread_mutex_lock(&queue_lock);
    n = q_last%q_depth;
    if (q[n] == NULL) {
        pthread_cond_wait(&queue_nonempty, &queue_lock);
        n = q_last%q_depth;
    }

    /* OK, grab the next event */
    if (q[n] != NULL) {
        ber = (BerElement *) q[n];
        q[n] = NULL;
        q_last = (n+1) % q_depth;
    } else
        ber = NULL;

    pthread_mutex_unlock(&queue_lock);

    /* Process the event */
    return ber;
}

void nudge_queue(void)
{
    pthread_cond_signal(&queue_nonempty);
}

void increase_queue_depth(unsigned int size)
{
    pthread_mutex_lock(&queue_lock);
    if (size > q_depth) {
        unsigned int i;
        void *tmp_q;

        tmp_q = realloc(q, size * sizeof(BerElement *));
        q = tmp_q;
        for (i=q_depth; i<size; i++)
            q[i] = NULL;
        q_depth = size;
    }
    pthread_mutex_unlock(&queue_lock);
}

void destroy_queue(void)
{
    unsigned int i;

    for (i=0; i<q_depth; i++) {
        ber_free(q[i], 1);
    }

    free(q);
}

