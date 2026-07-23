/* Copyright (C) 2015, Wazuh Inc. — spike #37396 throwaway PoC.
 *
 * Pure-userspace multi-consumer fan-out core. Deliberately decoupled from
 * BPF so it can be exercised WITHOUT root/BTF (sim mode) and reused by the
 * real ringbuf path. Proves: one source -> N consumers with independent
 * filters, per-consumer bounded queue, a slow consumer never stalls the
 * others or the producer (drop-on-full instead).
 */
#ifndef POC_FANOUT_H
#define POC_FANOUT_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#define POC_PATH_MAX   256
#define POC_QUEUE_CAP  1024   /* per-consumer bounded ring */
#define POC_MAX_CONSUMERS 8

/* The "raw event" — a stand-in for rt_event_header+rt_file_payload.
 * Note cgroup_id: the whole point of the correlation key living on the
 * raw event (0 == host / unknown). */
typedef struct {
    uint32_t pid;
    uint64_t cgroup_id;
    char     path[POC_PATH_MAX];
} poc_event;

typedef int (*poc_filter_fn)(const poc_event* e, void* user);
typedef void (*poc_sink_fn)(const char* consumer_name, const poc_event* e);

typedef struct {
    const char*   name;
    poc_filter_fn filter;      /* return non-zero to accept */
    void*         filter_user;
    poc_sink_fn   sink;        /* what the consumer does with an accepted event */
    unsigned      slow_us;     /* artificial per-event delay to simulate a slow consumer */

    /* per-consumer bounded queue (single-producer/single-consumer ring) */
    poc_event     ring[POC_QUEUE_CAP];
    volatile size_t head;      /* written by dispatcher */
    volatile size_t tail;      /* read by consumer thread */
    pthread_mutex_t lock;
    pthread_cond_t  cv;

    uint64_t        delivered;
    uint64_t        dropped;   /* per-consumer drop count (bounded queue full) */
    pthread_t       thread;
    volatile int    running;
} poc_consumer;

typedef struct {
    poc_consumer* consumers[POC_MAX_CONSUMERS];
    size_t        n;
    uint64_t      produced;
} poc_dispatcher;

void poc_dispatcher_init(poc_dispatcher* d);
void poc_dispatcher_add(poc_dispatcher* d, poc_consumer* c);
void poc_dispatcher_start(poc_dispatcher* d);   /* spawn consumer threads */
/* Called by the producer (ringbuf poll thread OR sim harness) for each event.
 * Non-blocking: pushes to every matching consumer's queue, drops-on-full.
 * The producer is NEVER blocked by a slow consumer. */
void poc_dispatch(poc_dispatcher* d, const poc_event* e);
void poc_dispatcher_stop(poc_dispatcher* d);    /* join, print stats */

#endif /* POC_FANOUT_H */
