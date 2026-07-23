/* Copyright (C) 2015, Wazuh Inc. — spike #37396 throwaway PoC.
 *
 * Userspace dispatcher. Two run modes:
 *   --sim        : NO kernel needed. Feeds synthetic file_open events through
 *                  the SAME fan-out core. Proves the multi-consumer decoupling
 *                  logic and slow-consumer isolation on any box (incl. this WSL2).
 *   (default)    : loads file_open.bpf.o, autoloads LSM or kprobe, polls the
 *                  ring buffer, and fans out real kernel events. Needs root +
 *                  BTF. Use --kprobe to force the fallback path.
 *
 * TWO mock consumers with DIFFERENT filters:
 *   "fim"         : accepts paths under /etc  (prefix filter)     — slow (5ms/ev)
 *   "syscollector": accepts ALL paths         (no filter)         — fast
 * Each prints (path, cgroup_id). The slow consumer must NOT stall the fast one
 * nor the producer: it drops from its own bounded queue instead.
 */
#include "fanout.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>

static volatile int g_stop = 0;
static void on_sigint(int s) { (void)s; g_stop = 1; }

/* ---- consumer filters (independent interests) ---- */
static int filter_prefix(const poc_event* e, void* user) {
    const char* prefix = (const char*)user;
    return strncmp(e->path, prefix, strlen(prefix)) == 0;
}
static int filter_all(const poc_event* e, void* user) { (void)e; (void)user; return 1; }

static void sink_print(const char* who, const poc_event* e) {
    printf("[%-12s] pid=%-6u cgroup_id=%-12llu path=%s\n",
           who, e->pid, (unsigned long long)e->cgroup_id, e->path);
}

/* quiet sink for sim mode: print only the first few, then stay silent so the
 * measurement reflects queue behavior, not stdout throughput. */
static _Atomic int g_printed;
static void sink_quiet(const char* who, const poc_event* e) {
    if (g_printed < 8) { g_printed++; sink_print(who, e); }
}

static poc_consumer c_fim = {
    .name = "fim", .filter = filter_prefix, .filter_user = (void*)"/etc",
    .sink = sink_print, .slow_us = 5000 /* 5ms -> deliberately slow */
};
static poc_consumer c_sys = {
    .name = "syscollector", .filter = filter_all,
    .sink = sink_print, .slow_us = 0
};

/* ================= SIM MODE ================= */
static void run_sim(poc_dispatcher* d) {
    const char* paths[] = { "/etc/passwd", "/etc/shadow", "/var/log/x",
                            "/tmp/a", "/etc/hosts", "/home/u/f" };
    const int N = 30000;
    /* Use the quiet sink so throughput reflects queueing, not stdout. */
    c_fim.sink = sink_quiet;
    c_sys.sink = sink_quiet;
    printf("SIM: feeding %d events, paced (~10us/ev). 'fim' is slow (5ms/ev).\n", N);
    for (int i = 0; i < N && !g_stop; i++) {
        poc_event e = {0};
        e.pid = 1000 + (i % 7);
        e.cgroup_id = (i % 3 == 0) ? 0 /* host */ : 100000ull + (i % 5);
        snprintf(e.path, sizeof(e.path), "%s", paths[i % 6]);
        poc_dispatch(d, &e);   /* NEVER blocks, even though 'fim' is slow */
        usleep(10);            /* pace: fast consumer keeps up, slow one can't */
    }
    /* let the fast consumer fully drain */
    usleep(300 * 1000);
}

/* ============== REAL BPF MODE ============== */
#ifndef POC_SIM_ONLY
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static poc_dispatcher* g_d;   /* for the ringbuf callback */

static int on_bpf_event(void* ctx, void* data, size_t sz) {
    (void)ctx; (void)sz;
    poc_dispatch(g_d, (const poc_event*)data);   /* one source -> fan-out */
    return 0;
}

static int run_bpf(poc_dispatcher* d, int force_kprobe) {
    g_d = d;
    /* Pre-5.11 kernels (and 5.10-class backports like Amazon Linux 2's 5.10)
     * charge BPF maps against RLIMIT_MEMLOCK (default 64 KiB) instead of memcg.
     * An 8 MiB ring buffer then fails to create with EPERM. Raise memlock to
     * infinity before load — mandatory for the 5.10 floor. */
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r))
        fprintf(stderr, "warning: setrlimit(MEMLOCK) failed: %s\n", strerror(errno));

    struct bpf_object* obj = bpf_object__open_file("file_open.bpf.o", NULL);
    if (!obj) { fprintf(stderr, "open .o failed\n"); return 1; }

    /* Autoload exactly ONE program family: mirror the real engine's choice. */
    int lsm_active = 0;
    FILE* f = fopen("/sys/kernel/security/lsm", "r");
    if (f) { char b[256]={0}; if (fgets(b,sizeof b,f)) lsm_active = strstr(b,"bpf")!=NULL; fclose(f);}
    if (force_kprobe) lsm_active = 0;
    fprintf(stderr, "attach strategy: %s\n", lsm_active ? "lsm/file_open" : "kprobe/vfs_open");

    struct bpf_program* prog;
    bpf_object__for_each_program(prog, obj) {
        const char* sec = bpf_program__section_name(prog);
        int keep = lsm_active ? (strncmp(sec,"lsm/",4)==0)
                              : (strncmp(sec,"kprobe/",7)==0);
        bpf_program__set_autoload(prog, keep);
    }
    if (bpf_object__load(obj)) { fprintf(stderr,"load failed (need root+BTF)\n"); return 1; }

    struct bpf_program* p2;
    bpf_object__for_each_program(p2, obj) {
        if (bpf_program__autoload(p2) && !bpf_program__attach(p2)) {
            fprintf(stderr, "attach failed for %s\n", bpf_program__section_name(p2));
            return 1;
        }
    }

    int rb_fd = bpf_object__find_map_fd_by_name(obj, "rb");
    struct ring_buffer* rbuf = ring_buffer__new(rb_fd, on_bpf_event, NULL, NULL);
    if (!rbuf) { fprintf(stderr,"ringbuf new failed\n"); return 1; }

    fprintf(stderr, "running. touch files (e.g. `touch /etc/poc_test`), Ctrl-C to stop.\n");
    while (!g_stop) {
        int n = ring_buffer__poll(rbuf, 200 /* ms */);
        if (n < 0 && n != -EINTR) break;
    }
    ring_buffer__free(rbuf);
    bpf_object__close(obj);
    return 0;
}
#endif /* !POC_SIM_ONLY */

int main(int argc, char** argv) {
    signal(SIGINT, on_sigint);
    int sim = 0, kprobe = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--sim")) sim = 1;
        else if (!strcmp(argv[i], "--kprobe")) kprobe = 1;
    }

    poc_dispatcher d;
    poc_dispatcher_init(&d);
    poc_dispatcher_add(&d, &c_fim);
    poc_dispatcher_add(&d, &c_sys);
    poc_dispatcher_start(&d);

    int rc = 0;
    if (sim) {
        run_sim(&d);
    } else {
#ifdef POC_SIM_ONLY
        fprintf(stderr, "built sim-only; re-run with --sim\n"); rc = 2;
#else
        rc = run_bpf(&d, kprobe);
#endif
    }

    poc_dispatcher_stop(&d);
    /* Proof points printed by poc_dispatcher_stop():
     *  - syscollector.delivered >> fim.delivered  (different filters)
     *  - fim.dropped > 0 under load, syscollector.dropped == 0
     *    => the slow consumer isolates its own loss; fast consumer & producer
     *       are never stalled. */
    return rc;
}
