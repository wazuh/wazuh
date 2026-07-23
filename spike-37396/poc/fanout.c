/* Copyright (C) 2015, Wazuh Inc. — spike #37396 throwaway PoC. */
#include "fanout.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void* consumer_loop(void* arg) {
    poc_consumer* c = (poc_consumer*)arg;
    while (c->running) {
        poc_event e;
        int got = 0;
        pthread_mutex_lock(&c->lock);
        while (c->running && c->tail == c->head) {
            /* wait up to 200ms so we can observe the running flag */
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += 200 * 1000 * 1000;
            if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
            pthread_cond_timedwait(&c->cv, &c->lock, &ts);
        }
        if (c->tail != c->head) {
            e = c->ring[c->tail % POC_QUEUE_CAP];
            c->tail++;
            got = 1;
        }
        pthread_mutex_unlock(&c->lock);

        if (got) {
            if (c->slow_us) usleep(c->slow_us);   /* simulate a slow consumer */
            c->delivered++;
            if (c->sink) c->sink(c->name, &e);
        }
    }
    return NULL;
}

void poc_dispatcher_init(poc_dispatcher* d) {
    memset(d, 0, sizeof(*d));
}

void poc_dispatcher_add(poc_dispatcher* d, poc_consumer* c) {
    c->head = c->tail = 0;
    c->delivered = c->dropped = 0;
    pthread_mutex_init(&c->lock, NULL);
    pthread_cond_init(&c->cv, NULL);
    d->consumers[d->n++] = c;
}

void poc_dispatcher_start(poc_dispatcher* d) {
    for (size_t i = 0; i < d->n; i++) {
        poc_consumer* c = d->consumers[i];
        c->running = 1;
        pthread_create(&c->thread, NULL, consumer_loop, c);
    }
}

void poc_dispatch(poc_dispatcher* d, const poc_event* e) {
    d->produced++;
    for (size_t i = 0; i < d->n; i++) {
        poc_consumer* c = d->consumers[i];
        if (c->filter && !c->filter(e, c->filter_user))
            continue;   /* per-consumer filter: independent interests */

        pthread_mutex_lock(&c->lock);
        size_t used = c->head - c->tail;
        if (used >= POC_QUEUE_CAP) {
            /* Bounded queue full: DROP for THIS consumer only.
             * The producer is not blocked; other consumers are untouched. */
            c->dropped++;
        } else {
            c->ring[c->head % POC_QUEUE_CAP] = *e;
            c->head++;
            pthread_cond_signal(&c->cv);
        }
        pthread_mutex_unlock(&c->lock);
    }
}

void poc_dispatcher_stop(poc_dispatcher* d) {
    for (size_t i = 0; i < d->n; i++) d->consumers[i]->running = 0;
    for (size_t i = 0; i < d->n; i++) {
        poc_consumer* c = d->consumers[i];
        pthread_cond_signal(&c->cv);
        pthread_join(c->thread, NULL);
    }
    fprintf(stderr, "\n=== fan-out stats ===\n");
    fprintf(stderr, "produced: %llu\n", (unsigned long long)d->produced);
    for (size_t i = 0; i < d->n; i++) {
        poc_consumer* c = d->consumers[i];
        fprintf(stderr, "  consumer '%s': delivered=%llu dropped=%llu%s\n",
                c->name,
                (unsigned long long)c->delivered,
                (unsigned long long)c->dropped,
                c->slow_us ? "  (slow)" : "");
    }
}
