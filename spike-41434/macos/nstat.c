// NetworkStatistics (private framework behind nettop): socket add/describe/remove in real time.
// Usage: nstat. Prints one JSON line per source event until SIGTERM.
#include <CoreFoundation/CoreFoundation.h>
#include <arpa/inet.h>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <libproc.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

typedef void *Mgr, *Src;
static Mgr (*Create)(CFAllocatorRef, dispatch_queue_t, void (^)(Src, void *));
static void (*AddAllTCP)(Mgr), (*AddAllUDP)(Mgr), (*QueryDesc)(Src);
static void (*SetDescBlock)(Src, void (^)(CFDictionaryRef));
static void (*SetRemovedBlock)(Src, void (^)(void));

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

// Print every key so the field names can be discovered on each macOS version.
static void kv(const void *k, const void *v, void *ctx) {
    char key[128], val[256] = "";
    CFStringGetCString(k, key, sizeof key, kCFStringEncodingUTF8);
    CFTypeID t = CFGetTypeID(v);
    if (t == CFNumberGetTypeID()) {
        long long n = 0;
        CFNumberGetValue(v, kCFNumberLongLongType, &n);
        snprintf(val, sizeof val, "%lld", n);
    } else if (t == CFStringGetTypeID()) {
        val[0] = '"';
        CFStringGetCString(v, val + 1, sizeof val - 2, kCFStringEncodingUTF8);
        strcat(val, "\"");
    } else if (t == CFDataGetTypeID() && CFDataGetLength(v) >= (CFIndex)sizeof(struct sockaddr_in)) {
        const struct sockaddr *sa = (const void *)CFDataGetBytePtr(v);
        char a[64] = "?";
        int port = 0;
        if (sa->sa_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, a, sizeof a);
            port = ntohs(((struct sockaddr_in *)sa)->sin_port);
        } else if (sa->sa_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, a, sizeof a);
            port = ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
        }
        snprintf(val, sizeof val, "\"%s|%d\"", a, port);
    } else if (t == CFBooleanGetTypeID())
        snprintf(val, sizeof val, "%s", CFBooleanGetValue(v) ? "true" : "false");
    else
        snprintf(val, sizeof val, "\"<%lu>\"", t);
    printf(",\"%s\":%s", key, val);
    (void)ctx;
}

static void on_term(int s) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    printf("{\"ev\":\"stats\",\"cpu_s\":%.3f,\"maxrss_kb\":%ld}\n",
           ru.ru_utime.tv_sec + ru.ru_stime.tv_sec + (ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1e6, ru.ru_maxrss / 1024);
    exit(s == SIGTERM ? 0 : 1);
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGTERM, on_term);
    void *h = dlopen("/System/Library/PrivateFrameworks/NetworkStatistics.framework/NetworkStatistics", RTLD_NOW);
    if (!h) {
        printf("{\"ev\":\"error\",\"msg\":\"dlopen: %s\"}\n", dlerror());
        return 1;
    }
    Create = dlsym(h, "NStatManagerCreate");
    AddAllTCP = dlsym(h, "NStatManagerAddAllTCP");
    AddAllUDP = dlsym(h, "NStatManagerAddAllUDP");
    QueryDesc = dlsym(h, "NStatSourceQueryDescription");
    SetDescBlock = dlsym(h, "NStatSourceSetDescriptionBlock");
    SetRemovedBlock = dlsym(h, "NStatSourceSetRemovedBlock");
    printf("{\"ev\":\"symbols\",\"create\":%d,\"tcp\":%d,\"udp\":%d,\"query\":%d,\"desc\":%d,\"removed\":%d}\n", !!Create, !!AddAllTCP,
           !!AddAllUDP, !!QueryDesc, !!SetDescBlock, !!SetRemovedBlock);
    if (!Create || !AddAllTCP || !AddAllUDP || !QueryDesc || !SetDescBlock || !SetRemovedBlock)
        return 1;
    dispatch_queue_t q = dispatch_queue_create("nstat", NULL);
    Mgr m = Create(kCFAllocatorDefault, q, ^(Src s, void *u) {
        (void)u;
        static int seq;
        int id = ++seq; // source pointers get reused, so tag each source
        printf("{\"ev\":\"add\",\"ts\":%.6f,\"src\":%d}\n", now(), id);
        SetDescBlock(s, ^(CFDictionaryRef d) {
            // No uid in the description: resolve it from the PID right away (-1 if the process is gone).
            CFNumberRef pn = CFDictionaryGetValue(d, CFSTR("processID"));
            int pid = 0;
            struct proc_bsdshortinfo bi;
            if (pn)
                CFNumberGetValue(pn, kCFNumberIntType, &pid);
            int ok = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &bi, sizeof bi) == sizeof bi;
            printf("{\"ev\":\"desc\",\"ts\":%.6f,\"src\":%d,\"uid_live\":%d", now(), id, ok ? (int)bi.pbsi_uid : -1);
            CFDictionaryApplyFunction(d, kv, NULL);
            printf("}\n");
        });
        SetRemovedBlock(s, ^{ printf("{\"ev\":\"rm\",\"ts\":%.6f,\"src\":%d}\n", now(), id); });
        QueryDesc(s);
    });
    AddAllTCP(m);
    AddAllUDP(m);
    dispatch_main();
}
