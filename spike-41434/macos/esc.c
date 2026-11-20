// Minimal Endpoint Security client: exec/fork/exit, plus the undocumented macOS 26.4+ NOTIFY bind (152)
// and connect (154) events. Prints JSON lines until SIGTERM. Usage: esc [seconds]
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>

#define NOTIFY_BIND 152    // ES_EVENT_TYPE_RESERVED_4
#define NOTIFY_CONNECT 154 // ES_EVENT_TYPE_RESERVED_6

// ponytail: layout reverse-engineered by Phorion (macOS 26.4), not an Apple API.
struct bind_addr { uint32_t family; uint8_t addr[16]; uint32_t port; };
struct bind_inner { struct bind_addr *addr; uint32_t unk, type, proto; };

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void on_term(int s) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    printf("{\"t\":\"stats\",\"cpu_s\":%.3f,\"maxrss_kb\":%ld}\n",
           ru.ru_utime.tv_sec + ru.ru_stime.tv_sec + (ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1e6, ru.ru_maxrss / 1024);
    exit(s == SIGTERM ? 0 : 1);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGTERM, on_term);
    es_client_t *client;
    es_new_client_result_t r = es_new_client(&client, ^(es_client_t *c, const es_message_t *m) {
        double t = m->time.tv_sec + m->time.tv_nsec / 1e9;
        audit_token_t tk = m->process->audit_token;
        printf("{\"time\":%.6f,\"recv\":%.6f,\"gseq\":%llu,\"pid\":%d,\"euid\":%u,", t, now(), m->global_seq_num,
               audit_token_to_pid(tk), audit_token_to_euid(tk));
        switch ((int)m->event_type) {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            tk = m->event.exec.target->audit_token;
            printf("\"t\":\"exec\",\"tpid\":%d,\"teuid\":%u,\"ppid\":%d,\"path\":\"%s\"}\n", audit_token_to_pid(tk),
                   audit_token_to_euid(tk), m->event.exec.target->ppid, m->event.exec.target->executable->path.data);
            break;
        case ES_EVENT_TYPE_NOTIFY_FORK:
            printf("\"t\":\"fork\",\"child\":%d}\n", audit_token_to_pid(m->event.fork.child->audit_token));
            break;
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            printf("\"t\":\"exit\",\"stat\":%d}\n", m->event.exit.stat);
            break;
        case NOTIFY_BIND: {
            const struct bind_inner *in = *(struct bind_inner *const *)&m->event;
            printf("\"t\":\"bind\",\"family\":%u,\"port\":%u,\"type\":%u,\"proto\":%u}\n", in->addr->family, in->addr->port, in->type,
                   in->proto);
            break;
        }
#define NAMED(ev, f) printf("\"t\":\"" #ev "\",\"name\":\"%.*s\"}\n", (int)m->event.ev->f.length, m->event.ev->f.data)
        case ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER: NAMED(od_create_user, user_name); break;
        case ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER: NAMED(od_delete_user, user_name); break;
        case ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP: NAMED(od_create_group, group_name); break;
        case ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP: NAMED(od_delete_group, group_name); break;
        case ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD: NAMED(od_group_add, group_name); break;
        case ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE: NAMED(od_group_remove, group_name); break;
        case ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET: NAMED(od_attribute_set, record_name); break;
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
            printf("\"t\":\"btm_add\",\"name\":\"%s\"}\n", m->event.btm_launch_item_add->item->item_url.data);
            break;
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE:
            printf("\"t\":\"btm_remove\",\"name\":\"%s\"}\n", m->event.btm_launch_item_remove->item->item_url.data);
            break;
        default:
            printf("\"t\":\"ev%d\",\"path\":\"%s\"}\n", m->event_type, m->process->executable->path.data);
        }
    });
    const char *names[] = {"SUCCESS", "ERR_INVALID_ARGUMENT", "ERR_INTERNAL", "ERR_NOT_ENTITLED",
                           "ERR_NOT_PERMITTED", "ERR_NOT_PRIVILEGED", "ERR_TOO_MANY_CLIENTS"};
    printf("{\"t\":\"init\",\"es_new_client\":\"%s\"}\n", r < 7 ? names[r] : "?");
    if (r != ES_NEW_CLIENT_RESULT_SUCCESS)
        return 1;
    es_event_type_t ev[] = {ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT, NOTIFY_BIND, NOTIFY_CONNECT,
                            ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER, ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER, ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP,
                            ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP, ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD, ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE,
                            ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET, ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
                            ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE};
    for (int i = 0; i < (int)(sizeof ev / sizeof *ev); i++)
        printf("{\"t\":\"subscribe\",\"event\":%d,\"ok\":%d}\n", ev[i], es_subscribe(client, &ev[i], 1) == ES_RETURN_SUCCESS);
    for (es_event_type_t e = 148; e < 157; e++) { // probe RESERVED_* types (not the AUTH 151/153), then drop them again
        if (e == 151 || e == 153)
            continue;
        int ok = es_subscribe(client, &e, 1) == ES_RETURN_SUCCESS;
        printf("{\"t\":\"probe\",\"event\":%d,\"ok\":%d}\n", e, ok);
        if (ok && e != NOTIFY_BIND && e != NOTIFY_CONNECT)
            es_unsubscribe(client, &e, 1);
    }
    if (argc > 1)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, atoi(argv[1]) * NSEC_PER_SEC), dispatch_get_main_queue(), ^{ exit(0); });
    dispatch_main();
}
