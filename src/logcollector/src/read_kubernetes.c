/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32

#include "shared.h"
#include "localfile-config.h"
#include "read_kubernetes.h"
#include "logcollector.h"

#include <cJSON.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define K8S_LOG_TAG          "logcollector:kubernetes"
#define K8S_PODS_DIR_DEFAULT "/var/log/pods"
#define K8S_IPC_SOCKET       "queue/sockets/container_connector"
#define K8S_IPC_TIMEOUT_MS   500
#define K8S_IPC_MAX_RESPONSE 65536
#define K8S_RESCAN_INTERVAL  5   /* seconds between filesystem rescans */
#define K8S_STATE_FILE       "/var/ossec/queue/k8s-logs/state.json"
#define K8S_STATE_DIR        "/var/ossec/queue/k8s-logs"
#define K8S_FLUSH_INTERVAL   10  /* seconds between state persists */
#define K8S_PARTIAL_MAX      (48 * 1024) /* reassembled-line cap: stays well under the
                                          * OS_MAXSTR queue payload limit incl. metadata */

/* One entry per (pod_uid, container_name) currently tracked. */
typedef struct k8s_tracked_container {
    char  *pod_uid;
    char  *namespace_;
    char  *pod_name;
    char  *container_name;
    char  *container_id;     /* resolved via IPC; may be empty if lookup failed */
    char  *image;
    char  *log_path;         /* /var/log/pods/<dir>/<container_name>/<N>.log */

    FILE  *fp;               /* opened lazily on first tail; closed on rotation/stop */
    ino_t  inode;            /* inode of the file currently in fp; used to detect rotation */
    off_t  offset;           /* last persisted byte offset; updated after each drain */
    char  *partial_buf;      /* accumulator for CRI 'P' (partial) lines until next 'F' */
    size_t partial_len;
    int    partial_truncated; /* reassembly hit K8S_PARTIAL_MAX: emit with marker */
    int    open_from_start;  /* container appeared after the initial scan: its log file
                              * is seconds old, so reading from byte 0 captures the
                              * startup lines without replaying history */
} k8s_tracked_t;

typedef struct k8s_runtime {
    k8s_tracked_t **tracked;    /* NULL-terminated array */
    size_t          tracked_n;
    time_t          last_scan;
    time_t          last_flush;  /* last time we persisted state.json */
    int             state_loaded; /* 1 once we tried loading state at startup */
    int             initial_scan_done; /* containers seen on the very first scan are
                                        * cold-start (tail from end unless checkpointed);
                                        * containers seen later are new (read from 0) */
} k8s_runtime_t;

/* ============================================================
 * IPC client (C) — minimal request/response over Unix socket.
 * Returns a heap-allocated JSON string (caller frees) or NULL.
 * ============================================================ */

static char *k8s_ipc_round_trip(const char *request_line)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return NULL;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    /* Always use the absolute path; logcollector may not have chrooted yet. */
    snprintf(addr.sun_path, sizeof(addr.sun_path), "/var/ossec/%s", K8S_IPC_SOCKET);

    /* Non-blocking connect with select() timeout. */
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno != EINPROGRESS) { close(fd); return NULL; }
        fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
        struct timeval tv = { K8S_IPC_TIMEOUT_MS / 1000, (K8S_IPC_TIMEOUT_MS % 1000) * 1000 };
        if (select(fd + 1, NULL, &wfds, NULL, &tv) <= 0) { close(fd); return NULL; }
        int err = 0; socklen_t err_len = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0 || err != 0) {
            close(fd); return NULL;
        }
    }

    /* Write request + newline. */
    const size_t  rlen = strlen(request_line);
    char         *wire;
    os_calloc(rlen + 2, 1, wire);
    memcpy(wire, request_line, rlen);
    wire[rlen] = '\n';

    fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
    struct timeval tv = { K8S_IPC_TIMEOUT_MS / 1000, (K8S_IPC_TIMEOUT_MS % 1000) * 1000 };
    if (select(fd + 1, NULL, &wfds, NULL, &tv) <= 0) { os_free(wire); close(fd); return NULL; }
    ssize_t wn = write(fd, wire, rlen + 1);
    os_free(wire);
    if (wn != (ssize_t)(rlen + 1)) { close(fd); return NULL; }

    /* Read response until newline. */
    char  *buf;
    size_t buf_cap = 1024, buf_len = 0;
    os_calloc(buf_cap, 1, buf);
    while (buf_len < K8S_IPC_MAX_RESPONSE) {
        fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
        struct timeval tv2 = { K8S_IPC_TIMEOUT_MS / 1000, (K8S_IPC_TIMEOUT_MS % 1000) * 1000 };
        if (select(fd + 1, &rfds, NULL, NULL, &tv2) <= 0) break;
        char chunk[1024];
        ssize_t n = read(fd, chunk, sizeof(chunk));
        if (n <= 0) break;
        if (buf_len + (size_t)n + 1 > buf_cap) {
            buf_cap = (buf_len + n + 1) * 2;
            os_realloc(buf, buf_cap, buf);
        }
        memcpy(buf + buf_len, chunk, n);
        buf_len += (size_t)n;
        buf[buf_len] = '\0';
        if (memchr(buf, '\n', buf_len) != NULL) break;
    }
    close(fd);

    if (buf_len == 0) { os_free(buf); return NULL; }
    char *nl = memchr(buf, '\n', buf_len);
    if (nl) *nl = '\0';
    return buf;
}

/* Returns the parsed cJSON object of the IPC response, or NULL. */
static cJSON *k8s_ipc_lookup_by_pod_uid_container(const char *pod_uid, const char *container_name)
{
    /* The IPC currently supports lookup_container_id and lookup_cgroup_id;
     * to find a container starting from (pod_uid, container_name) we extend
     * here by listing the cache. As of T-K5b.9 we use lookup_container_id
     * combined with reading containerID from /var/log/containers symlinks,
     * but for the first iteration we just query container_id from the
     * containerID file kubelet writes alongside the log directory. */
    (void)pod_uid; (void)container_name;
    return NULL;  /* Placeholder; resolved per-log-file path below. */
}

static cJSON *k8s_ipc_lookup_by_container_id(const char *container_id)
{
    if (!container_id || !*container_id) return NULL;
    char *req = NULL;
    os_calloc(strlen(container_id) + 64, 1, req);
    snprintf(req, strlen(container_id) + 64,
             "{\"op\":\"lookup_container_id\",\"id\":\"%s\"}", container_id);
    char *resp = k8s_ipc_round_trip(req);
    os_free(req);
    if (!resp) return NULL;
    cJSON *j = cJSON_Parse(resp);
    os_free(resp);
    if (!j) return NULL;
    cJSON *ok = cJSON_GetObjectItem(j, "ok");
    if (!cJSON_IsTrue(ok)) { cJSON_Delete(j); return NULL; }
    return j;
}

/* ============================================================
 * Path helpers
 * ============================================================ */

/* Parse the kubelet pod log directory name: "<namespace>_<pod>_<uid>"
 * (uid contains dashes but no underscores → splitting on the LAST two
 * underscores recovers the parts). Returns 1 on success. */
static int k8s_parse_pod_dir(const char *dir_name, char **ns, char **pod, char **uid)
{
    const char *last_underscore  = strrchr(dir_name, '_');
    if (!last_underscore || last_underscore == dir_name) return 0;
    /* The second-to-last underscore separates ns from pod. */
    size_t base_len = last_underscore - dir_name;
    char *tmp = strndup(dir_name, base_len);
    const char *first_underscore = strchr(tmp, '_');
    if (!first_underscore) { free(tmp); return 0; }
    size_t ns_len = first_underscore - tmp;
    *ns  = strndup(tmp, ns_len);
    *pod = strdup(first_underscore + 1);
    *uid = strdup(last_underscore + 1);
    free(tmp);
    return 1;
}

/* Resolve the container_id by scanning /var/log/containers/ for the symlink
 * whose target matches log_path. Each entry there is named
 * "<container>_<ns>_<pod>-<runtime>-<container_id>.log" and points back to
 * the /var/log/pods/<dir>/<container>/<N>.log file. The pods/.log file
 * itself is a regular file on k3s and similar runtimes, so readlink() does
 * not give us the container_id directly.
 *
 * Strategy: iterate /var/log/containers/, readlink each symlink, compare
 * against log_path; on a match, extract the trailing hex run before ".log".
 * Returns a heap-allocated string (caller frees) or NULL.
 */
static char *k8s_resolve_container_id_from_log(const char *log_path)
{
    if (!log_path) return NULL;

    /* Try the cheap path first: readlink() in case the file IS a symlink
     * (older kubelet versions did this). */
    char target[PATH_MAX];
    ssize_t n = readlink(log_path, target, sizeof(target) - 1);
    if (n > 0) {
        target[n] = '\0';
        const char *base = strrchr(target, '/');
        base = base ? base + 1 : target;
        size_t len = strlen(base);
        if (len > 5 && strcmp(base + len - 4, ".log") == 0) {
            size_t end = len - 4, i = end;
            while (i > 0) {
                char c = base[i - 1];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) break;
                i--;
            }
            if (end - i >= 32) return strndup(base + i, end - i);
        }
    }

    /* Fallback: scan /var/log/containers/ for a symlink that points back at
     * log_path. */
    DIR *d = opendir("/var/log/containers");
    if (!d) return NULL;

    char *result = NULL;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char entry_path[PATH_MAX];
        snprintf(entry_path, sizeof(entry_path), "/var/log/containers/%s", e->d_name);

        char link_target[PATH_MAX];
        ssize_t ln = readlink(entry_path, link_target, sizeof(link_target) - 1);
        if (ln <= 0) continue;
        link_target[ln] = '\0';
        if (strcmp(link_target, log_path) != 0) continue;

        /* Match — extract the longest trailing hex run before ".log" in
         * e->d_name. Filename shape:
         *   <container>_<ns>_<pod>-<runtime>-<container_id>.log
         * The runtime prefix (containerd-, crio-, docker-) is optional and
         * already not part of the hex run, so trailing-hex extraction is
         * sufficient. */
        size_t len = strlen(e->d_name);
        if (len > 5 && strcmp(e->d_name + len - 4, ".log") == 0) {
            size_t end = len - 4, i = end;
            while (i > 0) {
                char c = e->d_name[i - 1];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) break;
                i--;
            }
            if (end - i >= 32) {
                result = strndup(e->d_name + i, end - i);
            }
        }
        break;  /* one match is enough */
    }
    closedir(d);
    return result;
}

/* ============================================================
 * Filter logic
 * ============================================================ */

static int k8s_label_set_matches(const cJSON *labels_obj, const char *needle)
{
    if (!labels_obj || !cJSON_IsObject(labels_obj) || !needle) return 0;
    const char *eq = strchr(needle, '=');
    if (!eq) return 0;
    char *key = strndup(needle, eq - needle);
    const char *expect = eq + 1;
    cJSON *got = cJSON_GetObjectItem(labels_obj, key);
    int ok = (got && cJSON_IsString(got) && strcmp(got->valuestring, expect) == 0);
    free(key);
    return ok;
}

static int k8s_filters_match(const w_k8s_log_config_t *cfg, const cJSON *meta)
{
    if (!cfg || !meta) return 0;
    const cJSON *pod = cJSON_GetObjectItem(meta, "pod");

    const char *container_name = cJSON_GetStringValue(cJSON_GetObjectItem(meta, "name"));
    const char *image          = cJSON_GetStringValue(cJSON_GetObjectItem(meta, "image"));
    const char *ns             = pod ? cJSON_GetStringValue(cJSON_GetObjectItem(pod, "namespace")) : NULL;
    const char *pod_name       = pod ? cJSON_GetStringValue(cJSON_GetObjectItem(pod, "name"))      : NULL;
    const cJSON *labels        = pod ? cJSON_GetObjectItem(pod, "labels")                          : NULL;

    if (cfg->container_name_match && container_name &&
        !OSMatch_Execute(container_name, strlen(container_name), cfg->container_name_match)) return 0;
    if (cfg->image_name_match && image &&
        !OSMatch_Execute(image, strlen(image), cfg->image_name_match)) return 0;
    if (cfg->namespace_ && ns && strcmp(cfg->namespace_, ns) != 0) return 0;
    if (cfg->pod_name && pod_name && strcmp(cfg->pod_name, pod_name) != 0) return 0;
    if (cfg->labels) {
        for (int i = 0; cfg->labels[i]; i++) {
            if (!k8s_label_set_matches(labels, cfg->labels[i])) return 0;
        }
    }
    return 1;
}

/* ============================================================
 * Tracking
 * ============================================================ */

static int k8s_tracked_eq(const k8s_tracked_t *a, const char *pod_uid, const char *container_name)
{
    return a && a->pod_uid && a->container_name &&
           strcmp(a->pod_uid, pod_uid) == 0 &&
           strcmp(a->container_name, container_name) == 0;
}

static k8s_tracked_t *k8s_tracked_find(k8s_runtime_t *rt, const char *pod_uid, const char *container_name)
{
    for (size_t i = 0; i < rt->tracked_n; i++) {
        if (k8s_tracked_eq(rt->tracked[i], pod_uid, container_name)) return rt->tracked[i];
    }
    return NULL;
}

static void k8s_tracked_free(k8s_tracked_t *t)
{
    if (!t) return;
    if (t->fp) fclose(t->fp);
    os_free(t->pod_uid);
    os_free(t->namespace_);
    os_free(t->pod_name);
    os_free(t->container_name);
    os_free(t->container_id);
    os_free(t->image);
    os_free(t->log_path);
    os_free(t->partial_buf);
    os_free(t);
}

static void k8s_tracked_append(k8s_runtime_t *rt, k8s_tracked_t *t)
{
    os_realloc(rt->tracked, (rt->tracked_n + 2) * sizeof(k8s_tracked_t *), rt->tracked);
    rt->tracked[rt->tracked_n++] = t;
    rt->tracked[rt->tracked_n]   = NULL;
}

static void k8s_tracked_remove_at(k8s_runtime_t *rt, size_t idx)
{
    if (idx >= rt->tracked_n) return;
    k8s_tracked_free(rt->tracked[idx]);
    memmove(&rt->tracked[idx], &rt->tracked[idx + 1],
            (rt->tracked_n - idx) * sizeof(k8s_tracked_t *));
    rt->tracked_n--;
}

/* ============================================================
 * Scan + reconcile
 * ============================================================ */

/* Pick the latest <N>.log file under a container directory (kubelet rotates,
 * leaving 0.log .. N.log). Returns a heap-allocated path or NULL. */
static char *k8s_latest_log_file(const char *container_dir)
{
    DIR *d = opendir(container_dir);
    if (!d) return NULL;
    int    best_n = -1;
    char  *best   = NULL;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strstr(e->d_name, ".log") == NULL) continue;
        int n = atoi(e->d_name);
        if (n > best_n) {
            best_n = n;
            os_free(best);
            size_t sz = strlen(container_dir) + 1 + strlen(e->d_name) + 1;
            os_calloc(sz, 1, best);
            snprintf(best, sz, "%s/%s", container_dir, e->d_name);
        }
    }
    closedir(d);
    return best;
}

static void k8s_consider_container(logreader *lf, k8s_runtime_t *rt,
                                   const char *ns, const char *pod, const char *uid,
                                   const char *container_name, const char *container_dir)
{
    /* If already tracked, just refresh the log_path in case kubelet rotated
     * to a new <N>.log due to an in-pod container restart (same pod_uid, new
     * container_id, new log file). Reset inode to 0 to force k8s_open_or_reopen
     * to close the stale fp and pick up the new file from its start. */
    k8s_tracked_t *existing = k8s_tracked_find(rt, uid, container_name);
    if (existing) {
        char *latest = k8s_latest_log_file(container_dir);
        if (latest && existing->log_path && strcmp(latest, existing->log_path) != 0) {
            mtinfo(K8S_LOG_TAG,
                   "Container restart detected (log rotation): pod=%s container=%s old=%s new=%s",
                   pod, container_name, existing->log_path, latest);
            os_free(existing->log_path);
            existing->log_path = latest;
            existing->inode = 0;  /* force reopen: open_or_reopen drains the old fp first */
            existing->offset = 0; /* new file, no offset to resume from */
            existing->open_from_start = 1; /* new incarnation: never skip its head */
            latest = NULL;
        }
        os_free(latest);
        return;
    }

    char *log_path = k8s_latest_log_file(container_dir);
    if (!log_path) return;

    char *container_id = k8s_resolve_container_id_from_log(log_path);

    /* IPC enrichment + filtering. */
    cJSON *resp = container_id ? k8s_ipc_lookup_by_container_id(container_id) : NULL;
    cJSON *meta = resp ? cJSON_GetObjectItem(resp, "meta") : NULL;

    if (!meta) {
        /* No metadata yet (container-connector cache cold, or container_id
         * could not be resolved). Skip — next scan will retry. */
        os_free(log_path);
        os_free(container_id);
        if (resp) cJSON_Delete(resp);
        return;
    }

    if (!k8s_filters_match(lf->k8s_log, meta)) {
        os_free(log_path);
        os_free(container_id);
        cJSON_Delete(resp);
        return;
    }

    /* Matched — start tracking. */
    k8s_tracked_t *t = NULL;
    os_calloc(1, sizeof(k8s_tracked_t), t);
    t->open_from_start = rt->initial_scan_done;
    os_strdup(uid,             t->pod_uid);
    os_strdup(ns,              t->namespace_);
    os_strdup(pod,             t->pod_name);
    os_strdup(container_name,  t->container_name);
    if (container_id) os_strdup(container_id, t->container_id);
    const char *image = cJSON_GetStringValue(cJSON_GetObjectItem(meta, "image"));
    if (image) os_strdup(image, t->image);
    t->log_path = log_path;
    log_path = NULL;
    k8s_tracked_append(rt, t);

    mtinfo(K8S_LOG_TAG, "Tracking container ns=%s pod=%s container=%s image=%s log=%s",
           t->namespace_, t->pod_name, t->container_name,
           t->image ? t->image : "?", t->log_path);

    os_free(container_id);
    cJSON_Delete(resp);
    os_free(log_path);
}

static void k8s_scan_once(logreader *lf, k8s_runtime_t *rt)
{
    const char *pods_dir = K8S_PODS_DIR_DEFAULT;
    DIR *d = opendir(pods_dir);
    if (!d) {
        /* Deployment error (missing hostPath mount, not running as root):
         * collection is silently dead without a loud, rate-limited warning. */
        static time_t last_warn = 0;
        const time_t warn_now = time(NULL);
        if (warn_now - last_warn >= 60) {
            last_warn = warn_now;
            mtwarn(K8S_LOG_TAG, "Cannot open %s: %s — container log collection is not running.",
                   pods_dir, strerror(errno));
        }
        return;
    }

    /* First pass: visit every <ns>_<pod>_<uid>/ and its <container>/ subdirs. */
    struct dirent *e;
    /* Build the set of (pod_uid, container_name) seen this scan. */
    char **seen_keys = NULL;
    size_t seen_n = 0;

    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char *ns = NULL, *pod = NULL, *uid = NULL;
        if (!k8s_parse_pod_dir(e->d_name, &ns, &pod, &uid)) continue;

        size_t pod_path_sz = strlen(pods_dir) + 1 + strlen(e->d_name) + 1;
        char  *pod_path;
        os_calloc(pod_path_sz, 1, pod_path);
        snprintf(pod_path, pod_path_sz, "%s/%s", pods_dir, e->d_name);

        DIR *pd = opendir(pod_path);
        if (pd) {
            struct dirent *ce;
            while ((ce = readdir(pd))) {
                if (ce->d_name[0] == '.') continue;
                size_t cont_path_sz = strlen(pod_path) + 1 + strlen(ce->d_name) + 1;
                char *cont_path;
                os_calloc(cont_path_sz, 1, cont_path);
                snprintf(cont_path, cont_path_sz, "%s/%s", pod_path, ce->d_name);

                struct stat st;
                if (stat(cont_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                    k8s_consider_container(lf, rt, ns, pod, uid, ce->d_name, cont_path);

                    /* Mark as seen for later removal pass. */
                    size_t key_sz = strlen(uid) + 1 + strlen(ce->d_name) + 1;
                    char *key;
                    os_calloc(key_sz, 1, key);
                    snprintf(key, key_sz, "%s/%s", uid, ce->d_name);
                    os_realloc(seen_keys, (seen_n + 1) * sizeof(char *), seen_keys);
                    seen_keys[seen_n++] = key;
                }
                os_free(cont_path);
            }
            closedir(pd);
        }
        os_free(pod_path);
        os_free(ns); os_free(pod); os_free(uid);
    }
    closedir(d);

    /* Second pass: drop tracked entries whose pod/container no longer exists. */
    for (size_t i = 0; i < rt->tracked_n; ) {
        const k8s_tracked_t *t = rt->tracked[i];
        bool found = false;
        size_t key_sz = strlen(t->pod_uid) + 1 + strlen(t->container_name) + 1;
        char *want;
        os_calloc(key_sz, 1, want);
        snprintf(want, key_sz, "%s/%s", t->pod_uid, t->container_name);
        for (size_t j = 0; j < seen_n; j++) {
            if (strcmp(seen_keys[j], want) == 0) { found = true; break; }
        }
        os_free(want);
        if (!found) {
            mtinfo(K8S_LOG_TAG, "Stopped tracking container ns=%s pod=%s container=%s (pod removed).",
                   t->namespace_, t->pod_name, t->container_name);
            k8s_tracked_remove_at(rt, i);
            continue;
        }
        i++;
    }

    for (size_t i = 0; i < seen_n; i++) os_free(seen_keys[i]);
    os_free(seen_keys);
}

/* ============================================================
 * Checkpoint state (T-K7.5)
 *
 * Persists (pod_uid, container_name) → (log_path, inode, offset) to
 * K8S_STATE_FILE so a restart of wazuh-agent resumes tailing from the
 * last reported byte instead of seeking to end. The draft spec requires
 * "no missing events during agent restarts".
 *
 * Reliability bound: between drain and the next flush (every 10s) the
 * persisted offset lags the actual stream position, so a crash inside
 * that window may produce at most ~10s of duplicates. The manager-side
 * consumer can dedup by (timestamp, container_id) — duplicates are
 * preferable to data loss for security telemetry.
 * ============================================================ */

/* Pending recovered entries, populated by k8s_load_state and consumed by
 * k8s_open_or_reopen on the first open of each tracked container. */
typedef struct {
    char  *pod_uid;
    char  *container_name;
    char  *log_path;
    ino_t  inode;
    off_t  offset;
} k8s_state_entry_t;

static k8s_state_entry_t *g_pending_state = NULL;
static size_t             g_pending_n     = 0;

/* Shutdown persistence: the logcollector exits through exit() (signal handler
 * included), so an atexit hook is the reliable flush point — mirrors the
 * w_save_file_status() registration in logcollector.c. Single-runtime only:
 * multiple kubernetes <localfile> blocks are not supported by the prototype
 * (see the config warning emitted at init). */
static k8s_runtime_t *g_atexit_runtime = NULL;

static void k8s_save_state(const k8s_runtime_t *rt);

static void k8s_atexit_save(void)
{
    if (g_atexit_runtime) {
        k8s_save_state(g_atexit_runtime);
    }
}

static void k8s_state_free_pending(void)
{
    for (size_t i = 0; i < g_pending_n; i++) {
        os_free(g_pending_state[i].pod_uid);
        os_free(g_pending_state[i].container_name);
        os_free(g_pending_state[i].log_path);
    }
    os_free(g_pending_state);
    g_pending_n = 0;
}

/* Try to recover (inode, offset) for a (pod_uid, container_name) pair from
 * the loaded state. Returns 1 on hit (fills *inode and *offset and removes
 * the entry from the pending list), 0 on miss. */
static int k8s_state_consume(const char *pod_uid, const char *container_name,
                             const char *log_path, ino_t *out_inode, off_t *out_offset)
{
    if (!pod_uid || !container_name) return 0;
    for (size_t i = 0; i < g_pending_n; i++) {
        const k8s_state_entry_t *e = &g_pending_state[i];
        if (!e->pod_uid || !e->container_name) continue;
        if (strcmp(e->pod_uid, pod_uid) != 0) continue;
        if (strcmp(e->container_name, container_name) != 0) continue;
        /* Same logical container. The entry is returned even when log_path
         * changed (restart-count bump while the agent was down): the caller
         * anchors recovery on the inode, not the path. */
        (void)log_path;
        *out_inode  = e->inode;
        *out_offset = e->offset;
        /* Remove from pending so we don't reuse it. */
        os_free(g_pending_state[i].pod_uid);
        os_free(g_pending_state[i].container_name);
        os_free(g_pending_state[i].log_path);
        memmove(&g_pending_state[i], &g_pending_state[i + 1],
                (g_pending_n - i - 1) * sizeof(k8s_state_entry_t));
        g_pending_n--;
        return 1;
    }
    return 0;
}

static void k8s_load_state(void)
{
    k8s_state_free_pending();

    FILE *f = fopen(K8S_STATE_FILE, "r");
    if (!f) {
        /* No state file is the common cold-start case; do not warn. */
        return;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 16 * 1024 * 1024) {  /* 16 MiB sanity cap */
        fclose(f);
        return;
    }
    char *buf = NULL;
    os_calloc((size_t)sz + 1, 1, buf);
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (n != (size_t)sz) { os_free(buf); return; }

    cJSON *root = cJSON_Parse(buf);
    os_free(buf);
    if (!root) {
        mtwarn(K8S_LOG_TAG, "Malformed %s; starting cold (all containers will tail from end).",
               K8S_STATE_FILE);
        return;
    }

    cJSON *arr = cJSON_GetObjectItem(root, "containers");
    if (!arr || !cJSON_IsArray(arr)) {
        cJSON_Delete(root);
        return;
    }

    const int count = cJSON_GetArraySize(arr);
    if (count > 0) {
        os_calloc((size_t)count, sizeof(k8s_state_entry_t), g_pending_state);
    }
    g_pending_n = 0;
    cJSON *e;
    cJSON_ArrayForEach(e, arr) {
        if (!cJSON_IsObject(e)) continue;
        const char *uid  = cJSON_GetStringValue(cJSON_GetObjectItem(e, "pod_uid"));
        const char *cn   = cJSON_GetStringValue(cJSON_GetObjectItem(e, "container_name"));
        const char *lp   = cJSON_GetStringValue(cJSON_GetObjectItem(e, "log_path"));
        cJSON *ino_j     = cJSON_GetObjectItem(e, "inode");
        cJSON *off_j     = cJSON_GetObjectItem(e, "offset");
        if (!uid || !cn || !lp || !cJSON_IsNumber(ino_j) || !cJSON_IsNumber(off_j)) continue;

        k8s_state_entry_t *slot = &g_pending_state[g_pending_n++];
        os_strdup(uid, slot->pod_uid);
        os_strdup(cn,  slot->container_name);
        os_strdup(lp,  slot->log_path);
        slot->inode  = (ino_t)ino_j->valuedouble;
        slot->offset = (off_t)off_j->valuedouble;
    }
    cJSON_Delete(root);
    mtinfo(K8S_LOG_TAG, "Loaded checkpoint state with %zu container entries.", g_pending_n);
}

static void k8s_save_state(const k8s_runtime_t *rt)
{
    /* Ensure directory exists (idempotent). */
    struct stat st;
    if (stat(K8S_STATE_DIR, &st) != 0) {
        if (mkdir(K8S_STATE_DIR, 0750) != 0 && errno != EEXIST) {
            mtdebug2(K8S_LOG_TAG, "mkdir(%s) failed: %s", K8S_STATE_DIR, strerror(errno));
            return;
        }
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", 1);
    cJSON *arr = cJSON_AddArrayToObject(root, "containers");

    for (size_t i = 0; i < rt->tracked_n; i++) {
        const k8s_tracked_t *t = rt->tracked[i];
        if (!t || !t->pod_uid || !t->container_name || !t->log_path) continue;
        cJSON *e = cJSON_CreateObject();
        cJSON_AddStringToObject(e, "pod_uid",        t->pod_uid);
        cJSON_AddStringToObject(e, "container_name", t->container_name);
        cJSON_AddStringToObject(e, "log_path",       t->log_path);
        cJSON_AddNumberToObject(e, "inode",          (double)t->inode);
        cJSON_AddNumberToObject(e, "offset",         (double)t->offset);
        cJSON_AddItemToArray(arr, e);
    }

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) return;

    /* Atomic write: temp file + fsync + rename. */
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s.tmp", K8S_STATE_FILE);
    FILE *f = fopen(tmp, "w");
    if (!f) {
        mtdebug2(K8S_LOG_TAG, "Cannot open %s for write: %s", tmp, strerror(errno));
        free(json_str);
        return;
    }
    size_t to_write = strlen(json_str);
    size_t wn = fwrite(json_str, 1, to_write, f);
    free(json_str);
    if (wn != to_write) {
        fclose(f);
        unlink(tmp);
        return;
    }
    fflush(f);
    fsync(fileno(f));
    fclose(f);
    if (rename(tmp, K8S_STATE_FILE) != 0) {
        unlink(tmp);
        mtdebug2(K8S_LOG_TAG, "rename(%s -> %s) failed: %s", tmp, K8S_STATE_FILE, strerror(errno));
    }
}

/* ============================================================
 * Tail + emit (T-K7.3 / T-K7.4)
 * ============================================================ */

/* CRI containerd log line format:
 *   "<RFC3339Nano-ts> <stdout|stderr> <P|F> <message>\n"
 * Parses in place. Returns 1 on success, 0 on malformed line. */
static int k8s_parse_cri_line(char *line,
                              const char **out_ts, const char **out_stream,
                              char *out_flag, const char **out_text)
{
    if (!line || !*line) return 0;
    char *p = line;

    *out_ts = p;
    char *sp1 = strchr(p, ' ');
    if (!sp1) return 0;
    *sp1 = '\0';
    p = sp1 + 1;

    *out_stream = p;
    char *sp2 = strchr(p, ' ');
    if (!sp2) return 0;
    *sp2 = '\0';
    p = sp2 + 1;

    if (*p != 'F' && *p != 'P') return 0;
    *out_flag = *p;
    if (p[1] != ' ' && p[1] != '\0') return 0;
    p += (p[1] == ' ') ? 2 : 1;

    *out_text = p;
    /* Strip trailing newline if present. */
    char *nl = strchr(p, '\n');
    if (nl) *nl = '\0';
    return 1;
}

/* Build the K8s log event JSON and push it to the manager queue.
 * Returns 0 when the line no longer needs to be retried (sent, empty, or
 * unbuildable) and -1 only on queue backpressure, so the caller can rewind
 * the file position instead of silently losing the line. */
static int k8s_emit_line(const k8s_tracked_t *t, const char *ts, const char *stream,
                         const char *text, int truncated, logreader *lf)
{
    if (!t || !text || !*text) return 0;

    cJSON *root = cJSON_CreateObject();
    if (!root) return 0;
    cJSON_AddStringToObject(root, "collector", "logcollector");
    cJSON_AddStringToObject(root, "module",    "kubernetes");

    cJSON *data = cJSON_AddObjectToObject(root, "data");
    cJSON_AddStringToObject(data, "log_line", text);
    if (stream) cJSON_AddStringToObject(data, "stream", stream);
    if (ts)     cJSON_AddStringToObject(data, "timestamp", ts);

    cJSON *k8s = cJSON_AddObjectToObject(data, "kubernetes");
    if (t->namespace_)     cJSON_AddStringToObject(k8s, "namespace",      t->namespace_);
    if (t->pod_name)       cJSON_AddStringToObject(k8s, "pod_name",       t->pod_name);
    if (t->pod_uid)        cJSON_AddStringToObject(k8s, "pod_uid",        t->pod_uid);
    if (t->container_name) cJSON_AddStringToObject(k8s, "container_name", t->container_name);
    if (t->container_id)   cJSON_AddStringToObject(k8s, "container_id",   t->container_id);
    if (t->image)          cJSON_AddStringToObject(k8s, "image",          t->image);
    if (truncated)         cJSON_AddTrueToObject(data, "truncated");

    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json_str) return 0;

    /* Use the container_name as the source label so analysisd correlation
     * can attribute the line to the right container. lf->log_target carries
     * the configured targets (typically "agent"). */
    const char *source = t->container_name ? t->container_name : "kubernetes";
    mtdebug2(K8S_LOG_TAG, "Emitting K8s log event: %s", json_str);
    const int rc = w_msg_hash_queues_push(json_str, (char *)source, strlen(json_str) + 1,
                                          lf->log_target, LOCALFILE_MQ);
    free(json_str);
    return rc;
}

/* Append a P/F fragment to the reassembly buffer, bounded by
 * K8S_PARTIAL_MAX: fragments beyond the cap are dropped and the joined
 * message is flagged truncated, so a newline-less container can never grow
 * agent memory (or exceed the queue payload limit) without bound. */
static void k8s_partial_append(k8s_tracked_t *t, const char *text)
{
    size_t add = strlen(text);
    if (t->partial_len >= K8S_PARTIAL_MAX) {
        t->partial_truncated = 1;
        return;
    }
    if (t->partial_len + add > K8S_PARTIAL_MAX) {
        add = K8S_PARTIAL_MAX - t->partial_len;
        t->partial_truncated = 1;
    }
    os_realloc(t->partial_buf, t->partial_len + add + 1, t->partial_buf);
    memcpy(t->partial_buf + t->partial_len, text, add);
    t->partial_len += add;
    t->partial_buf[t->partial_len] = '\0';
}

/* Drain available bytes from t->fp, emitting each complete CRI line. Honours
 * the partial ('P') / full ('F') flag — partials accumulate in t->partial_buf
 * until a final 'F' arrives, then the joined message is emitted.
 *
 * The file offset is an acknowledgement pointer: it only moves past a line
 * once its event was accepted by the queue. On backpressure the position is
 * rewound (to the start of the whole P-chain when reassembling) and the
 * drain stops; the next pass retries from there. */
static void k8s_drain_one(k8s_tracked_t *t, logreader *lf)
{
    if (!t || !t->fp) return;

    char line[OS_MAXSTR];
    long line_start  = ftell(t->fp);
    long chain_start = -1;   /* file position of the first 'P' of the open chain */

    while (fgets(line, sizeof(line), t->fp)) {
        if (!strchr(line, '\n') && strlen(line) + 1 < sizeof(line)) {
            /* Incomplete line at EOF: we caught kubelet mid-append. Defer it
             * to the next pass instead of emitting a torn fragment whose
             * remainder would then parse as a malformed line. (A line larger
             * than the buffer still falls through chunked, pre-existing.) */
            fseek(t->fp, line_start, SEEK_SET);
            break;
        }
        const char *ts = NULL, *stream = NULL, *text = NULL;
        char flag = 0;
        if (!k8s_parse_cri_line(line, &ts, &stream, &flag, &text)) {
            /* Malformed line — emit raw for forensic visibility. */
            char *nl = strchr(line, '\n');
            if (nl) *nl = '\0';
            if (k8s_emit_line(t, NULL, NULL, line, 0, lf) != 0) {
                fseek(t->fp, line_start, SEEK_SET);
                break;
            }
            line_start = ftell(t->fp);
            continue;
        }

        if (flag == 'P') {
            if (chain_start < 0) chain_start = line_start;
            k8s_partial_append(t, text);
            line_start = ftell(t->fp);
            continue;
        }

        /* flag == 'F' — flush the partial buffer if any, then emit. */
        if (t->partial_len > 0) {
            k8s_partial_append(t, text);
            const int rc = k8s_emit_line(t, ts, stream, t->partial_buf,
                                         t->partial_truncated, lf);
            os_free(t->partial_buf);
            t->partial_len = 0;
            t->partial_truncated = 0;
            if (rc != 0) {
                /* Re-read the whole chain next pass. */
                fseek(t->fp, chain_start >= 0 ? chain_start : line_start, SEEK_SET);
                chain_start = -1;
                break;
            }
            chain_start = -1;
        } else {
            if (k8s_emit_line(t, ts, stream, text, 0, lf) != 0) {
                fseek(t->fp, line_start, SEEK_SET);
                break;
            }
        }
        line_start = ftell(t->fp);
    }

    /* Update the persisted offset to reflect the bytes we have already
     * consumed (and successfully queued) from this stream. The next
     * k8s_save_state() will persist it. */
    long pos = ftell(t->fp);
    if (pos >= 0) t->offset = (off_t)pos;

    /* Always clear the EOF/error state so the next call to fgets() actually
     * issues a fresh read() against the kernel. Without this, glibc caches
     * the EOF flag and subsequent invocations return NULL immediately even
     * when kubelet has appended new lines to the file. */
    clearerr(t->fp);
}

/* ------------------------------------------------------------------
 * Rotated-file recovery (across agent restarts)
 *
 * kubelet rotation: "<N>.log" is renamed to "<N>.log.<timestamp>" and a
 * fresh "<N>.log" is created; older rotated files are gzipped and finally
 * deleted (containerLogMaxFiles). N itself bumps on container restart.
 * Plain rotated files keep their inode, which lets us anchor the saved
 * checkpoint to the renamed file and finish reading it.
 * ------------------------------------------------------------------ */

typedef struct {
    char *path;
    ino_t inode;
    long  n;        /* "<N>" restart-count prefix */
    char *suffix;   /* rotation timestamp suffix, NULL for the live "<N>.log" */
} k8s_logfile_t;

/* Chronological order: ascending N; within one N, rotated files in suffix
 * (timestamp) order, then the live "<N>.log" last. */
static int k8s_logfile_cmp(const void *va, const void *vb)
{
    const k8s_logfile_t *a = va, *b = vb;
    if (a->n != b->n) return (a->n < b->n) ? -1 : 1;
    if (!a->suffix && !b->suffix) return 0;
    if (!a->suffix) return 1;   /* live file is newest of its N */
    if (!b->suffix) return -1;
    return strcmp(a->suffix, b->suffix);
}

/* Enumerate plain (non-gz) "<N>.log[.<suffix>]" files in dir, sorted
 * chronologically. Caller frees with k8s_logfiles_free(). */
static k8s_logfile_t *k8s_list_log_files(const char *dir, size_t *out_n)
{
    *out_n = 0;
    DIR *d = opendir(dir);
    if (!d) return NULL;

    k8s_logfile_t *files = NULL;
    size_t n = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        const char *dotlog = strstr(e->d_name, ".log");
        if (!dotlog) continue;
        size_t name_len = strlen(e->d_name);
        if (name_len > 3 && strcmp(e->d_name + name_len - 3, ".gz") == 0) continue;

        char *endp = NULL;
        long file_n = strtol(e->d_name, &endp, 10);
        if (endp == e->d_name || strncmp(endp, ".log", 4) != 0) continue;

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;

        os_realloc(files, (n + 1) * sizeof(k8s_logfile_t), files);
        memset(&files[n], 0, sizeof(k8s_logfile_t));
        os_strdup(path, files[n].path);
        files[n].inode = st.st_ino;
        files[n].n     = file_n;
        if (endp[4] == '.') {
            os_strdup(endp + 5, files[n].suffix);
        }
        n++;
    }
    closedir(d);

    if (files) qsort(files, n, sizeof(k8s_logfile_t), k8s_logfile_cmp);
    *out_n = n;
    return files;
}

static void k8s_logfiles_free(k8s_logfile_t *files, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        os_free(files[i].path);
        os_free(files[i].suffix);
    }
    os_free(files);
}

/* Drain one on-disk file [start_offset, EOF) through the normal emit path,
 * using a temporary fp on the tracked entry. */
static void k8s_drain_file(k8s_tracked_t *t, logreader *lf, const char *path, off_t start_offset)
{
    FILE *prev = t->fp;
    t->fp = fopen(path, "r");
    if (!t->fp) {
        mtwarn(K8S_LOG_TAG, "Recovery: cannot open '%s': %s", path, strerror(errno));
        t->fp = prev;
        return;
    }
    if (start_offset > 0 && fseek(t->fp, start_offset, SEEK_SET) != 0) {
        fseek(t->fp, 0, SEEK_SET);
    }
    k8s_drain_one(t, lf);
    fclose(t->fp);
    t->fp = prev;
}

/* The checkpointed inode is not the live file: it was rotated (renamed) or
 * the restart count bumped while the agent was down. Finish the checkpointed
 * file from the saved offset, then drain every newer plain file, in order.
 * The caller then opens the live file from byte 0.
 *
 * If the inode is gone (rotated away to gzip or GC'd), everything still on
 * disk is newer than the checkpoint except pre-checkpoint content of plain
 * files that never rotated — we accept bounded duplicates over loss and
 * drain all plain siblings from 0 (the gzip tier is specified in the spike's
 * checkpoint doc and intentionally not implemented in this prototype). */
static void k8s_recover_rotated(k8s_tracked_t *t, logreader *lf,
                                ino_t want_inode, off_t want_offset)
{
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", t->log_path);
    char *slash = strrchr(dir, '/');
    if (!slash) return;
    *slash = '\0';

    size_t n = 0;
    k8s_logfile_t *files = k8s_list_log_files(dir, &n);
    if (!files) return;

    ssize_t anchor = -1;
    for (size_t i = 0; i < n; i++) {
        if (files[i].inode == want_inode) { anchor = (ssize_t)i; break; }
    }

    if (anchor < 0) {
        mtwarn(K8S_LOG_TAG,
               "Recovery: checkpointed file for pod=%s container=%s no longer on disk "
               "(rotation window exceeded); collecting the retained plain files — "
               "lines rotated to gzip or deleted during the downtime are lost.",
               t->pod_name, t->container_name);
    }

    for (size_t i = (anchor < 0) ? 0 : (size_t)anchor; i < n; i++) {
        if (strcmp(files[i].path, t->log_path) == 0) continue;  /* live file: caller's job */
        off_t start = ((ssize_t)i == anchor) ? want_offset : 0;
        mtinfo(K8S_LOG_TAG, "Recovery: draining rotated file '%s' from offset %lld "
               "(pod=%s container=%s).",
               files[i].path, (long long)start, t->pod_name, t->container_name);
        k8s_drain_file(t, lf, files[i].path, start);
    }

    k8s_logfiles_free(files, n);
}

/* Open (or re-open after rotation) the log file for a tracked container.
 *
 * Open strategy (in order of preference):
 *   1. fp open and inode unchanged: nothing to do.
 *   2. fp open and inode changed (in-run rotation / restart bump): drain the
 *      old fp to EOF first — it still reads the renamed file — then continue
 *      on the new file from byte 0.
 *   3. First open with a checkpoint entry: same inode -> exact resume at the
 *      saved offset; different inode -> rotated-file recovery ladder, then
 *      the live file from byte 0.
 *   4. No checkpoint: byte 0 for containers born after the initial scan,
 *      SEEK_END for cold-start containers (no history replay).
 */
static int k8s_open_or_reopen(k8s_tracked_t *t, logreader *lf)
{
    struct stat st;
    int rotated_while_open = 0;

    if (t->fp) {
        if (stat(t->log_path, &st) == 0 && st.st_ino == t->inode) {
            return 0;  /* still the same file */
        }
        /* The open fp still points at the renamed (or previous-incarnation)
         * file: drain whatever was appended after our last read. */
        k8s_drain_one(t, lf);
        fclose(t->fp);
        t->fp = NULL;
        rotated_while_open = 1;
        /* If the new file cannot be opened right away (rename/create race),
         * make sure the eventual open starts from byte 0. */
        t->open_from_start = 1;
    }

    t->fp = fopen(t->log_path, "r");
    if (!t->fp) {
        mtdebug2(K8S_LOG_TAG, "fopen('%s') failed: %s", t->log_path, strerror(errno));
        return -1;
    }
    if (fstat(fileno(t->fp), &st) == 0) {
        t->inode = st.st_ino;
    }

    if (rotated_while_open) {
        fseek(t->fp, 0, SEEK_SET);
        t->offset = 0;
        mtinfo(K8S_LOG_TAG,
               "Rotation: drained previous file, continuing on '%s' from start "
               "(pod=%s container=%s).", t->log_path, t->pod_name, t->container_name);
        return 0;
    }

    /* First open after a (re)start: try to resume from the checkpoint. */
    ino_t recovered_inode = 0;
    off_t recovered_offset = 0;
    int resumed = 0;
    if (k8s_state_consume(t->pod_uid, t->container_name, t->log_path,
                          &recovered_inode, &recovered_offset)) {
        if (recovered_inode == t->inode && recovered_offset <= (off_t)st.st_size) {
            if (fseek(t->fp, recovered_offset, SEEK_SET) == 0) {
                t->offset = recovered_offset;
                resumed = 1;
                mtinfo(K8S_LOG_TAG,
                       "Resumed tail at offset %lld: pod=%s container=%s file=%s",
                       (long long)recovered_offset, t->pod_name, t->container_name, t->log_path);
            }
        } else {
            mtinfo(K8S_LOG_TAG,
                   "Checkpoint inode mismatch (rotation while stopped): pod=%s container=%s "
                   "file=%s; recovering rotated files.",
                   t->pod_name, t->container_name, t->log_path);
            k8s_recover_rotated(t, lf, recovered_inode, recovered_offset);
            fseek(t->fp, 0, SEEK_SET);
            t->offset = 0;
            resumed = 1;
        }
    }

    if (!resumed) {
        if (t->open_from_start) {
            /* Container born after our initial scan: read its log from byte 0
             * so startup lines (often the only lines a crash-looping container
             * ever writes) are collected. The file is at most a few scan
             * intervals old, so there is no history-replay risk. */
            fseek(t->fp, 0, SEEK_SET);
            t->offset = 0;
            mtinfo(K8S_LOG_TAG, "Opened log for tail (from start): pod=%s container=%s file=%s",
                   t->pod_name, t->container_name, t->log_path);
        } else {
            fseek(t->fp, 0, SEEK_END);
            t->offset = ftell(t->fp);
            mtinfo(K8S_LOG_TAG, "Opened log for tail (from end): pod=%s container=%s file=%s",
                   t->pod_name, t->container_name, t->log_path);
        }
    }
    return 0;
}

static void k8s_tail_all(k8s_runtime_t *rt, logreader *lf)
{
    for (size_t i = 0; i < rt->tracked_n; i++) {
        k8s_tracked_t *t = rt->tracked[i];
        if (!t || !t->log_path) continue;
        if (k8s_open_or_reopen(t, lf) != 0) continue;
        k8s_drain_one(t, lf);
    }
}

/* ============================================================
 * Public reader entry point
 * ============================================================ */

void *read_kubernetes(logreader *lf, int *rc, int drop_it)
{
    (void)drop_it;
    if (rc) *rc = 0;
    if (!lf || !lf->k8s_log) return NULL;

    /* Lazy-init runtime state. */
    if (!lf->k8s_log->runtime) {
        k8s_runtime_t *rt = NULL;
        os_calloc(1, sizeof(k8s_runtime_t), rt);
        lf->k8s_log->runtime = rt;
        mtinfo(K8S_LOG_TAG, "Kubernetes logreader initialised (location=%s%s).",
               lf->k8s_log->container_path ? "kubernetes:" : "kubernetes",
               lf->k8s_log->container_path ? lf->k8s_log->container_path : "");
        if (g_atexit_runtime) {
            mtwarn(K8S_LOG_TAG, "Multiple kubernetes <localfile> blocks are not supported "
                   "by this prototype; checkpoint state is kept for the last block only.");
        } else if (atexit(k8s_atexit_save)) {
            mtwarn(K8S_LOG_TAG, "Could not register shutdown handler; the checkpoint "
                   "will only be persisted by the periodic flush.");
        }
        g_atexit_runtime = rt;
    }
    k8s_runtime_t *rt = (k8s_runtime_t *)lf->k8s_log->runtime;

    /* Load checkpoint state on first ever read. Subsequent calls see
     * state_loaded=1 and skip the disk read. */
    if (!rt->state_loaded) {
        k8s_load_state();
        rt->state_loaded = 1;
    }

    /* Rate-limit the filesystem scan; this read() may be invoked very often
     * by the logcollector main loop. */
    const time_t now = time(NULL);
    if (now - rt->last_scan >= K8S_RESCAN_INTERVAL) {
        rt->last_scan = now;
        const size_t tracked_before = rt->tracked_n;
        k8s_scan_once(lf, rt);
        rt->initial_scan_done = 1;
        if (rt->tracked_n != tracked_before) {
            /* The tracked set changed: persist immediately so recovery
             * decisions after a crash never run on a stale identity set. */
            k8s_save_state(rt);
            rt->last_flush = now;
        }
    }

    /* Tail every tracked container's log file. open_or_reopen handles
     * rotation by re-detecting inode changes between invocations. */
    k8s_tail_all(rt, lf);

    /* Periodically persist offsets so a restart resumes cleanly. */
    if (now - rt->last_flush >= K8S_FLUSH_INTERVAL) {
        rt->last_flush = now;
        k8s_save_state(rt);
    }

    return NULL;
}

void k8s_logreader_destroy_runtime(logreader *lf)
{
    if (!lf || !lf->k8s_log || !lf->k8s_log->runtime) return;
    k8s_runtime_t *rt = (k8s_runtime_t *)lf->k8s_log->runtime;
    k8s_save_state(rt);
    if (g_atexit_runtime == rt) {
        g_atexit_runtime = NULL;
    }
    for (size_t i = 0; i < rt->tracked_n; i++) {
        k8s_tracked_free(rt->tracked[i]);
    }
    os_free(rt->tracked);
    os_free(rt);
    lf->k8s_log->runtime = NULL;
}

#endif /* !WIN32 */
