// Change notifications for the Syscollector inventories, none of them needs an entitlement:
// FSEvents (packages, services, browser extensions, local directory), SCDynamicStore and the
// PF_ROUTE socket (network), and Darwin notify keys (directory cache, logins).
// Usage: inv <path>... Prints one JSON line per notification until SIGTERM.
#include <CoreServices/CoreServices.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <net/if.h>
#include <net/route.h>
#include <notify.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void on_fsevent(ConstFSEventStreamRef s, void *ctx, size_t n, void *paths, const FSEventStreamEventFlags flags[],
                       const FSEventStreamEventId ids[]) {
    for (size_t i = 0; i < n; i++)
        printf("{\"src\":\"fsevents\",\"ts\":%.6f,\"key\":\"%s\",\"flags\":%u}\n", now(), ((char **)paths)[i], flags[i]);
}

static void on_store(SCDynamicStoreRef s, CFArrayRef keys, void *info) {
    for (CFIndex i = 0; i < CFArrayGetCount(keys); i++) {
        char k[256];
        CFStringGetCString(CFArrayGetValueAtIndex(keys, i), k, sizeof k, kCFStringEncodingUTF8);
        printf("{\"src\":\"scdynamicstore\",\"ts\":%.6f,\"key\":\"%s\"}\n", now(), k);
    }
}

static void on_term(int s) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    printf("{\"src\":\"stats\",\"cpu_s\":%.3f,\"maxrss_kb\":%ld}\n",
           ru.ru_utime.tv_sec + ru.ru_stime.tv_sec + (ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1e6, ru.ru_maxrss / 1024);
    _exit(0);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGTERM, on_term);
    dispatch_queue_t q = dispatch_queue_create("inv", NULL);

    CFMutableArrayRef paths = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    for (int i = 1; i < argc; i++)
        if (access(argv[i], F_OK) == 0)
            CFArrayAppendValue(paths, CFStringCreateWithCString(NULL, argv[i], kCFStringEncodingUTF8));
    FSEventStreamRef fs = FSEventStreamCreate(NULL, on_fsevent, NULL, paths, kFSEventStreamEventIdSinceNow, 0.1,
                                              kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer);
    FSEventStreamSetDispatchQueue(fs, q);
    printf("{\"src\":\"init\",\"fsevents_paths\":%ld,\"fsevents_start\":%d", CFArrayGetCount(paths), FSEventStreamStart(fs));

    SCDynamicStoreRef ds = SCDynamicStoreCreate(NULL, CFSTR("inv"), on_store, NULL);
    const void *pats[] = {CFSTR("State:/Network/Interface"), CFSTR("State:/Network/Interface/.*/(IPv4|IPv6|Link)"),
                          CFSTR("State:/Network/Global/.*"), CFSTR("Setup:/Network/.*")};
    CFArrayRef pa = CFArrayCreate(NULL, pats, 4, &kCFTypeArrayCallBacks);
    printf(",\"scdynamicstore\":%d", SCDynamicStoreSetNotificationKeys(ds, NULL, pa) && SCDynamicStoreSetDispatchQueue(ds, q));

    int rs = socket(PF_ROUTE, SOCK_RAW, 0);
    dispatch_source_t rsrc = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, rs, 0, q);
    dispatch_source_set_event_handler(rsrc, ^{
        char buf[4096], name[IF_NAMESIZE] = "";
        if (read(rs, buf, sizeof buf) <= 0)
            return;
        const struct if_msghdr *h = (const void *)buf; // same index offset for if_msghdr and ifa_msghdr
        if (h->ifm_type == RTM_NEWADDR || h->ifm_type == RTM_DELADDR || h->ifm_type == RTM_IFINFO)
            if_indextoname(h->ifm_index, name);
        printf("{\"src\":\"route\",\"ts\":%.6f,\"key\":\"type%d:%s\"}\n", now(), h->ifm_type, name);
    });
    dispatch_resume(rsrc);
    printf(",\"route\":%d", rs >= 0);

    const char *keys[] = {"com.apple.system.DirectoryService.InvalidateCache", "com.apple.system.DirectoryService.InvalidateCache.user",
                          "com.apple.system.DirectoryService.InvalidateCache.group", "com.apple.system.utmpx",
                          "com.apple.system.config.network_change"};
    for (int i = 0; i < 5; i++) {
        const char *k = keys[i];
        int tok;
        notify_register_dispatch(k, &tok, q, ^(int t) { printf("{\"src\":\"notify\",\"ts\":%.6f,\"key\":\"%s\"}\n", now(), k); });
    }
    printf("}\n");
    dispatch_main();
}
