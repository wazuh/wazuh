// libproc poller: listening TCP and bound UDP sockets with PID and uid.
// Usage: ports <interval_ms>. Prints "+"/"-" diffs as JSON lines until SIGTERM, then scan stats.
#include <libproc.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#define MAXK 8192
static char cur[MAXK][96], prev[MAXK][96];
static int ncur, nprev;
static volatile sig_atomic_t stop;

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static int has(char (*set)[96], int n, const char *k) {
    for (int i = 0; i < n; i++)
        if (!strcmp(set[i], k))
            return 1;
    return 0;
}

static void scan(void) {
    static pid_t pids[16384];
    static struct proc_fdinfo fds[4096];
    int np = proc_listallpids(pids, sizeof pids) ;
    ncur = 0;
    for (int i = 0; i < np; i++) {
        int nb = proc_pidinfo(pids[i], PROC_PIDLISTFDS, 0, fds, sizeof fds);
        for (int j = 0; j < nb / (int)sizeof(struct proc_fdinfo); j++) {
            if (fds[j].proc_fdtype != PROX_FDTYPE_SOCKET)
                continue;
            struct socket_fdinfo si;
            if (proc_pidfdinfo(pids[i], fds[j].proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof si) != sizeof si)
                continue;
            const char *proto;
            int port;
            if (si.psi.soi_kind == SOCKINFO_TCP && si.psi.soi_proto.pri_tcp.tcpsi_state == TSI_S_LISTEN) {
                proto = "tcp";
                port = ntohs(si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
            } else if (si.psi.soi_kind == SOCKINFO_IN && si.psi.soi_protocol == IPPROTO_UDP) {
                proto = "udp";
                port = ntohs(si.psi.soi_proto.pri_in.insi_lport);
            } else
                continue;
            if (!port || ncur == MAXK)
                continue;
            struct proc_bsdshortinfo bi = {0};
            proc_pidinfo(pids[i], PROC_PIDT_SHORTBSDINFO, 0, &bi, sizeof bi);
            snprintf(cur[ncur], 96, "\"proto\":\"%s\",\"port\":%d,\"pid\":%d,\"uid\":%u,\"name\":\"%s\"", proto, port, pids[i],
                     bi.pbsi_uid, bi.pbsi_comm);
            if (!has(cur, ncur, cur[ncur]))
                ncur++;
        }
    }
}

static void on_term(int s) { (void)s; stop = 1; }

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);
    int ms = argc > 1 ? atoi(argv[1]) : 1000, scans = 0;
    double busy = 0;
    while (!stop) {
        double t0 = now();
        scan();
        busy += now() - t0;
        scans++;
        for (int i = 0; i < ncur; i++)
            if (!has(prev, nprev, cur[i]))
                printf("{\"op\":\"+\",\"ts\":%.6f,%s}\n", t0, cur[i]);
        for (int i = 0; i < nprev; i++)
            if (!has(cur, ncur, prev[i]))
                printf("{\"op\":\"-\",\"ts\":%.6f,%s}\n", t0, prev[i]);
        memcpy(prev, cur, sizeof cur);
        nprev = ncur;
        usleep(ms * 1000);
    }
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    printf("{\"op\":\"stats\",\"interval_ms\":%d,\"scans\":%d,\"avg_scan_ms\":%.3f,\"cpu_s\":%.3f,\"maxrss_kb\":%ld,\"sockets\":%d}\n", ms,
           scans, busy * 1000 / scans, ru.ru_utime.tv_sec + ru.ru_stime.tv_sec + (ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1e6,
           ru.ru_maxrss / 1024, ncur);
}
