/*
 * Multi-threaded PoC driver — SPIKE #37738, D5 concurrency model.
 *
 * Demonstrates the "one thread per endpoint so they don't block each other"
 * model (D5 lean M-a + E-a): three endpoint worker threads plus a dispatcher.
 *   - intake      : feeds events into the accumulator (stands in for EventForward)
 *   - stateless   : flushes the batch on an interval  (POST /stateless)
 *   - stateful    : ships a sync session              (POST /stateful)  <- made SLOW
 *   - control     : periodic Notify + hands tasks off (POST /control)
 *   - dispatcher  : runs tasks so /control never blocks on task execution
 *
 * The mock manager is started with --slow-stateful, so one /stateful call holds
 * its request open for several seconds. The timestamped output shows /stateless
 * and /control continuing to complete DURING that window: proof the endpoints
 * don't block each other.
 *
 * Usage: hc_poc_mt <base_url> <agent_id> <key_hex> <ca_path> <run_seconds>
 */

#include "hc_client.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>

static struct timespec T0;
static pthread_mutex_t PR = PTHREAD_MUTEX_INITIALIZER;   /* serialize prints */
static _Atomic int RUNNING = 1;                          /* C11 atomic stop flag */

static long el_ms(void) {
    struct timespec n; clock_gettime(CLOCK_MONOTONIC, &n);
    return (n.tv_sec - T0.tv_sec) * 1000 + (n.tv_nsec - T0.tv_nsec) / 1000000;
}
static void say(const char *thread, const char *fmt, ...) {
    char msg[512]; va_list ap; va_start(ap, fmt); vsnprintf(msg, sizeof msg, fmt, ap); va_end(ap);
    pthread_mutex_lock(&PR);
    printf("  [+%5ld ms] %-10s %s\n", el_ms(), thread, msg);
    fflush(stdout);
    pthread_mutex_unlock(&PR);
}
static void nap_ms(long ms) { struct timespec t = { ms/1000, (ms%1000)*1000000L }; nanosleep(&t, NULL); }

/* ---- a tiny task queue: control thread pushes, dispatcher pops ---- */
#define QN 32
static char *TQ[QN]; static int qh, qt;
static pthread_mutex_t QL = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  QC = PTHREAD_COND_INITIALIZER;
static void q_push(const char *s) {
    pthread_mutex_lock(&QL);
    if ((qt + 1) % QN != qh) { TQ[qt] = strdup(s); qt = (qt + 1) % QN; pthread_cond_signal(&QC); }
    pthread_mutex_unlock(&QL);
}

/* ---- client callbacks ---- */
static void on_log(int lvl, const char *m) { say(lvl>=2?"client!":"client", "%s", m); }
static void on_state(hc_conn_state_t s) { (void)s; }
static void on_startup(bool ok, const char *meta) { (void)meta; say("main", "startup %s", ok?"ACCEPTED":"REJECTED"); }
static void on_task(const char *type, const char *id, const char *payload) {
    (void)id; (void)payload;
    /* /control thread hands off to the dispatcher and returns immediately */
    q_push(type);
}

/* ---- threads ---- */
static hc_handle *H;

static void *intake_thread(void *_) { (void)_;
    int n = 0;
    while (RUNNING) {
        char ev[64]; snprintf(ev, sizeof ev, "1:/var/log/syslog:event-%d", n++);
        hc_submit_event(H, (const uint8_t*)ev, strlen(ev));
        nap_ms(250);
    }
    return NULL;
}
static void *stateless_thread(void *_) { (void)_;
    while (RUNNING) {
        nap_ms(1000);                                  /* demo batch interval */
        if (!RUNNING) break;
        say("stateless", "flush begin");
        hc_flush_events(H);
        say("stateless", "flush done");
    }
    return NULL;
}
static void *stateful_thread(void *_) { (void)_;
    /* ship one session shortly after start; the mock makes it SLOW */
    nap_ms(700);
    size_t n = 8192; unsigned char *sess = malloc(n);
    memcpy(sess, "FULLSESSION:syscollector:", 25); memset(sess+25, 'D', n-25);
    char *res = NULL;
    say("stateful", "POST /stateful begin (manager will hold it open)...");
    hc_submit_sync_session(H, sess, n, "sess-mt-1", &res);
    say("stateful", "POST /stateful DONE: %s", res ? res : "(no body)");
    free(sess); free(res);
    /* a second, also slow */
    if (RUNNING) {
        nap_ms(200); char *res2 = NULL;
        say("stateful", "POST /stateful #2 begin...");
        hc_submit_sync_session(H, (const uint8_t*)"FULLSESSION:fim:xx", 18, "sess-mt-2", &res2);
        say("stateful", "POST /stateful #2 DONE");
        free(res2);
    }
    return NULL;
}
static void *control_thread(void *_) { (void)_;
    while (RUNNING) {
        nap_ms(1500);                                  /* demo notify interval */
        if (!RUNNING) break;
        say("control", "notify begin");
        hc_notify(H);
        say("control", "notify done (tasks handed to dispatcher)");
    }
    return NULL;
}
static void *dispatcher_thread(void *_) { (void)_;
    while (RUNNING) {
        pthread_mutex_lock(&QL);
        while (RUNNING && qh == qt) {
            struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); ts.tv_sec += 1;
            pthread_cond_timedwait(&QC, &QL, &ts);
        }
        char *task = NULL;
        if (qh != qt) { task = TQ[qh]; qh = (qh + 1) % QN; }
        pthread_mutex_unlock(&QL);
        if (task) {
            say("dispatch", "running task (%s) -> execd/module/restart...", task);
            nap_ms(500);                               /* simulated task work */
            say("dispatch", "task done -> would POST /control response");
            free(task);
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "usage: %s <base_url> <id> <key_hex> <ca> <seconds>\n", argv[0]); return 2; }
    int secs = atoi(argv[5]);
    clock_gettime(CLOCK_MONOTONIC, &T0);

    hc_config_t cfg = {
        .base_url = argv[1], .agent_id = argv[2], .agent_key_hex = argv[3],
        .verify_mode = HC_VERIFY_FULL, .ca_path = argv[4],
        .batch_size_bytes = 1u<<20, .batch_interval_ms = 1000,
        .version = "5.1.0", .config_checksum = "d41d8cd98f00b204e9800998ecf8427e",
        .backoff_base_ms = 1000, .backoff_cap_ms = 60000, .request_timeout_ms = 30000,
    };
    hc_callbacks_t cb = { .log=on_log, .on_startup_result=on_startup, .on_task=on_task, .on_state_change=on_state };
    H = hc_create(&cfg, &cb);

    say("main", "startup (must register before streams begin)");
    if (hc_startup(H) != HC_OK) { say("main", "startup failed; abort"); hc_destroy(H); return 1; }

    say("main", "spawning: intake + stateless + stateful(SLOW) + control + dispatcher");
    pthread_t th[5];
    pthread_create(&th[0], NULL, intake_thread, NULL);
    pthread_create(&th[1], NULL, stateless_thread, NULL);
    pthread_create(&th[2], NULL, stateful_thread, NULL);
    pthread_create(&th[3], NULL, control_thread, NULL);
    pthread_create(&th[4], NULL, dispatcher_thread, NULL);

    nap_ms((long)secs * 1000);
    say("main", "stopping (hc_stop: set flags, join all threads)");
    RUNNING = 0;
    pthread_cond_broadcast(&QC);
    for (int i = 0; i < 5; i++) pthread_join(th[i], NULL);

    hc_destroy(H);
    say("main", "done — all threads joined, handle destroyed");
    return 0;
}
