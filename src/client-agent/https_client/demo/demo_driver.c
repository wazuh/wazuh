/*
 * Wazuh agent HTTPS client — demo driver.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * A standalone, plain-C program that drives the REAL https_client module (the
 * production libhttps_client, exactly as agentd would through the bridge) at a
 * local mock manager, printing every callback so the conversation is visible.
 *
 * It stands in for agentd: build a config, hc_create/hc_start, feed a few
 * events, a small sync session and a multi-MB FIM full sync (over the intake
 * socket), force a Notify, let the control loop run, then hc_destroy. Not
 * production code; a demo harness only.
 */

/* Expose POSIX clock_gettime/nanosleep under strict -std=c11 on glibc. */
#define _POSIX_C_SOURCE 200809L

#include "https_client.h"

#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static struct timespec g_start;

/* For hc_set_config_hash inside on_config_downloaded (the one hc_* call that
 * IS callback-safe). */
static hc_handle *g_handle;

/* The key the mock rotates to at ROTATE_KEY_AT; the re-enroll callback swaps
 * to it (matches mock_manager.py ROTATED_KEY). */
static const char *g_rotated_key = "0f0e0d0c0b0a090807060504030201001f1e1d1c1b1a19181716151413121110";

/* Set by SIGINT/SIGTERM: ends sustained mode early with the clean drain. */
static atomic_int g_stop;

static void on_signal(int sig)
{
    (void)sig;
    atomic_store(&g_stop, 1);
}

static long elapsed_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - g_start.tv_sec) * 1000 + (now.tv_nsec - g_start.tv_nsec) / 1000000;
}

static const char *state_name(int state)
{
    switch (state)
    {
        case HC_STATE_STARTING: return "STARTING";
        case HC_STATE_REGISTERED: return "REGISTERED";
        case HC_STATE_REJECTED: return "REJECTED";
        case HC_STATE_AUTH_ERROR: return "AUTH_ERROR";
        default: return "STOPPED";
    }
}

/* full_log_fnc_t: the module's internal LOGFN_* calls land here. */
static void on_log(int level, const char *tag, const char *file, int line, const char *func,
                   const char *msg, va_list args)
{
    (void)tag;
    (void)file;
    (void)line;
    (void)func;
    char buf[1024];
    vsnprintf(buf, sizeof buf, msg, args);
    printf("[+%7ld ms] [client:%d] %s\n", elapsed_ms(), level, buf);
    fflush(stdout);
}

static void on_startup_result(bool accepted, const char *handshake_json, void *user_data)
{
    (void)user_data;
    printf("[+%7ld ms] >> STARTUP %s; manager metadata: %s\n", elapsed_ms(),
           accepted ? "ACCEPTED" : "REJECTED", handshake_json ? handshake_json : "(none)");
    fflush(stdout);
}

/* The credential was rejected (401): the module paused all traffic. A real
 * agent re-enrolls via POST /enroll; here we just swap to the mock's rotated
 * key under the same identity ("001", this driver's own agent_id) via
 * hc_set_agent_identity (callback-safe), which clears the pause and
 * re-registers. */
static void on_reenroll_required(void *user_data)
{
    (void)user_data;
    printf("[+%7ld ms] >> RE-ENROLL REQUIRED (401): swapping to the new key via "
           "hc_set_agent_identity -> %s\n", elapsed_ms(),
           hc_set_agent_identity(g_handle, "001", g_rotated_key) ? "accepted" : "rejected");
    fflush(stdout);
}

static void on_task(const char *task_id, const char *task_type, const char *payload_json,
                    void *user_data)
{
    (void)user_data;
    printf("[+%7ld ms] >> TASK received: id=%s type=%s payload=%s\n", elapsed_ms(), task_id,
           task_type, payload_json);
    fflush(stdout);
    /* All four contract types are fire-and-forget (#37733): nothing is
     * reported back; a real agent routes them to their handlers here. */
}

/* The new-config delivery: the file lives only until this returns, so a real
 * consumer copies it here, applies it (write merged.mg, unmerge, reload) and
 * corrects the module's hash view if the apply fails. */
static void on_config_downloaded(const char *config_hash, const char *file_path, void *user_data)
{
    (void)user_data;
    FILE *file = fopen(file_path, "rb");
    long size = 0;
    char first_line[96] = "(empty)";
    if (file)
    {
        if (fgets(first_line, sizeof first_line, file))
        {
            first_line[strcspn(first_line, "\n")] = '\0';
        }
        fseek(file, 0, SEEK_END);
        size = ftell(file);
        fclose(file);
    }
    printf("[+%7ld ms] >> CONFIG DOWNLOADED: hash=%.12s.. %ld B, first line: %s\n",
           elapsed_ms(), config_hash, size, first_line);
    printf("[+%7ld ms]    (a real agent would write merged.mg, unmerge and reload here;\n"
           "                demonstrating the callback-safe hc_set_config_hash: %s)\n",
           elapsed_ms(),
           hc_set_config_hash(g_handle, config_hash) ? "accepted" : "rejected");
    fflush(stdout);
}

static void on_sync_response(const char *session_id, int result, const char *body, size_t body_len,
                             void *user_data)
{
    (void)user_data;
    (void)body; /* A binary FlatBuffer now, not printable text. */
    printf("[+%7ld ms] >> STATEFUL result: session=%s result=%d (%zu-byte answer)\n", elapsed_ms(),
           session_id, result, body_len);
    fflush(stdout);
}

static void on_state_change(int state, void *user_data)
{
    (void)user_data;
    printf("[+%7ld ms] ~~ connection state -> %s\n", elapsed_ms(), state_name(state));
    fflush(stdout);
}

static void on_buffer_level(int level, void *user_data)
{
    (void)user_data;
    printf("[+%7ld ms] ~~ buffer level -> %d\n", elapsed_ms(), level);
    fflush(stdout);
}

static void nap(int ms)
{
    struct timespec t = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&t, NULL);
}

/* Reporter collectors (#37843): run on the module's reporter thread, return a
 * malloc'd JSON object the module owns (frees) after stamping identity. A real
 * agent aggregates every module's stats/config here. */
static char *collect_stats(void *user_data)
{
    (void)user_data;
    printf("[+%7ld ms] >> COLLECT stats\n", elapsed_ms());
    fflush(stdout);
    return strdup("{\"uptime\":86400,\"events_received\":12543,\"queue_usage\":15.2}");
}

static char *collect_config(void *user_data)
{
    (void)user_data;
    printf("[+%7ld ms] >> COLLECT config\n", elapsed_ms());
    fflush(stdout);
    return strdup("{\"client\":{\"notify_time\":2,\"config-profile\":\"demo\"}}");
}

/* Deterministic hex filler (xorshift-style) for the fake file hashes. */
static void fake_hex(char *dst, size_t hex_chars, uint64_t seed)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < hex_chars; i++)
    {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        dst[i] = digits[(seed >> 60) & 0xF];
    }
    dst[hex_chars] = '\0';
}

/* Builds a FIM full-sync session: "FULLSESSION:fim:" followed by one JSON
 * entry per monitored file (path, attributes, md5/sha1/sha256), one per line.
 * The shape mirrors what syscheck reports; the content is generated. */
static unsigned char *build_fim_full_sync(size_t entries, size_t *out_len)
{
    const size_t cap = 32 + entries * 420;
    unsigned char *buf = malloc(cap);
    size_t len = (size_t)snprintf((char *)buf, cap, "FULLSESSION:fim:");
    char md5[33], sha1[41], sha256[65];
    for (size_t i = 0; i < entries; i++)
    {
        fake_hex(md5, 32, i * 3 + 1);
        fake_hex(sha1, 40, i * 3 + 2);
        fake_hex(sha256, 64, i * 3 + 3);
        len += (size_t)snprintf((char *)buf + len, cap - len,
                                "{\"path\":\"/usr/lib/pkg-%05zu/libcomponent-%zu.so\","
                                "\"attributes\":{\"type\":\"file\",\"size\":%zu,"
                                "\"perm\":\"rw-r--r--\",\"uid\":\"0\",\"gid\":\"0\","
                                "\"inode\":%zu,\"mtime\":%ld,\"hash_md5\":\"%s\","
                                "\"hash_sha1\":\"%s\",\"hash_sha256\":\"%s\"}}\n",
                                i / 20, i, 4096 + i % 65536, 100000 + i,
                                1784500000L + (long)(i % 86400), md5, sha1, sha256);
    }
    *out_len = len;
    return buf;
}

/* Cheap integrity witness both sides can compute: sum of all bytes mod 2^32.
 * The mock prints the same over what it received; equal values on screen mean
 * the multi-MB session survived socket -> spool -> HTTPS byte-exact. */
static uint32_t additive_checksum(const unsigned char *data, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++)
    {
        sum += data[i];
    }
    return sum;
}

/* Ad-hoc JSON string-field extraction: this driver is a demo harness (no
 * cJSON dependency), and hc_enroll_result_t::body is always the mock's own
 * flat, single-line {"id":..,"name":..,"ip":..,"key":..} -- not a document
 * that ever needs a real parser here. Tolerates an optional space after the
 * colon: Python's json.dumps default separators put one there
 * (`"key": "..."`), which a naive `"key":"` needle would silently miss. */
static bool extract_json_string_field(const char *json, const char *field, char *out, size_t out_cap)
{
    char needle[64];
    snprintf(needle, sizeof needle, "\"%s\":", field);
    const char *start = strstr(json, needle);
    if (!start)
    {
        return false;
    }
    start += strlen(needle);
    while (*start == ' ')
    {
        start++;
    }
    if (*start != '"')
    {
        return false;
    }
    start += 1;
    const char *end = strchr(start, '"');
    if (!end || (size_t)(end - start) >= out_cap)
    {
        return false;
    }
    memcpy(out, start, (size_t)(end - start));
    out[end - start] = '\0';
    return true;
}

/* First-boot enrollment (#38465): hc_enroll() is deliberately handle-less --
 * it must work before hc_create() ever runs, exactly like this. password may
 * be empty (open mode: no Authorization header, mock_manager.py must be
 * started without --enroll-password for this to succeed). On success, fills
 * key_out with the client.keys-shaped hex key the mock minted. */
static bool enroll_agent(const char *host, uint16_t port, const char *password,
                         char *key_out, size_t key_out_cap)
{
    hc_config_t enroll_config;
    memset(&enroll_config, 0, sizeof enroll_config);
    strncpy(enroll_config.server_host, host, sizeof enroll_config.server_host - 1);
    enroll_config.server_port = port;
    enroll_config.verify_mode = HC_VERIFY_NONE; /* demo mock uses a self-signed cert */
    enroll_config.request_timeout_ms = 10000;

    hc_enroll_request_t request;
    memset(&request, 0, sizeof request);
    snprintf(request.body_json, sizeof request.body_json,
             "{\"name\":\"demo-agent\",\"version\":\"5.1.0\"}");
    strncpy(request.password, password, sizeof request.password - 1);
    request.log = on_log;

    printf("== enrolling (POST /enroll, %s mode) ==\n",
           password[0] ? "password" : "open");
    fflush(stdout);

    hc_enroll_result_t result;
    if (!hc_enroll(&enroll_config, &request, &result))
    {
        fprintf(stderr, "enroll: transport failure (no response reached the manager)\n");
        return false;
    }

    printf("== enroll response: http_code=%ld body=%s ==\n", result.http_code, result.body);
    fflush(stdout);

    if (result.http_code != 200)
    {
        fprintf(stderr, "enroll: rejected by the manager (http_code=%ld)\n", result.http_code);
        return false;
    }

    if (!extract_json_string_field(result.body, "key", key_out, key_out_cap))
    {
        fprintf(stderr, "enroll: 200 response missing a \"key\" field\n");
        return false;
    }
    return true;
}

int main(int argc, char **argv)
{
    if (argc < 4)
    {
        fprintf(stderr,
                "usage: %s <host> <port> <key_hex>|enroll[:<password>] [sync_socket_path]\n",
                argv[0]);
        return 2;
    }
    const char *sync_socket = argc > 4 ? argv[4] : NULL;
    clock_gettime(CLOCK_MONOTONIC, &g_start);

    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_signal;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    const uint16_t server_port = (uint16_t)atoi(argv[2]);
    /* #38465: "enroll" or "enroll:<password>" in the key_hex slot drives a
     * real first-boot POST /enroll against mock_manager.py instead of using a
     * pre-provisioned key, exactly as agentd's try_enroll_to_server() does
     * before hc_create() ever runs. */
    char enrolled_key[HC_MAX_KEY];
    const char *agent_key = argv[3];
    if (strncmp(argv[3], "enroll", 6) == 0 && (argv[3][6] == '\0' || argv[3][6] == ':'))
    {
        const char *password = argv[3][6] == ':' ? argv[3] + 7 : "";
        if (!enroll_agent(argv[1], server_port, password, enrolled_key, sizeof enrolled_key))
        {
            return 1;
        }
        agent_key = enrolled_key;
    }

    hc_config_t config;
    memset(&config, 0, sizeof config);
    strncpy(config.server_host, argv[1], sizeof config.server_host - 1);
    config.server_port = server_port;
    strncpy(config.agent_id, "001", sizeof config.agent_id - 1);
    strncpy(config.agent_key, agent_key, sizeof config.agent_key - 1);
    config.verify_mode = HC_VERIFY_NONE; /* demo mock uses a self-signed cert */
    config.notify_interval_s = 2;        /* Notify every 2 s so we see a few   */
    config.batch_interval_ms = 1000;     /* flush events every 1 s             */
    config.request_timeout_ms = 10000;   /* a multi-MB /stateful takes a moment */
    config.backoff_base_ms = 200;
    config.backoff_cap_ms = 2000;
    config.stats_enabled = true;          /* push /stats every few seconds     */
    config.stats_interval_s = 3;
    config.config_report_enabled = true;  /* push /config on its own cadence    */
    config.config_report_interval_s = 5;
    strncpy(config.version, "5.1.0", sizeof config.version - 1);
    /* SHA-256 of the empty merged.mg the mock starts with: in sync at boot,
     * so the scripted config flip is a real transition. */
    strncpy(config.config_checksum,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            sizeof config.config_checksum - 1);
    if (sync_socket)
    {
        strncpy(config.sync_socket_path, sync_socket, sizeof config.sync_socket_path - 1);
    }

    hc_callbacks_t callbacks;
    memset(&callbacks, 0, sizeof callbacks);
    callbacks.log = on_log;
    callbacks.on_startup_result = on_startup_result;
    callbacks.on_reenroll_required = on_reenroll_required;
    callbacks.on_task = on_task;
    callbacks.on_config_downloaded = on_config_downloaded;
    callbacks.on_sync_response = on_sync_response;
    callbacks.on_state_change = on_state_change;
    callbacks.on_buffer_level = on_buffer_level;
    callbacks.collect_stats = collect_stats;
    callbacks.collect_config = collect_config;

    printf("== creating + starting the https_client (target %s:%s) ==\n", argv[1], argv[2]);
    hc_handle *handle = hc_create(&config, &callbacks);
    g_handle = handle;
    if (!handle || !hc_start(handle))
    {
        fprintf(stderr, "failed to create/start the client\n");
        return 1;
    }

    /* Give the control thread a moment to run Startup + register. */
    nap(800);

    printf("== feeding 5 events into the /stateless stream ==\n");
    for (int i = 0; i < 5; i++)
    {
        char frame[64];
        int n = snprintf(frame, sizeof frame, "1:/var/log/syslog:demo event %d", i);
        hc_submit_event(handle, (const uint8_t *)frame, (size_t)n);
    }

    printf("== submitting a small /stateful sync session (in-memory) ==\n");
    unsigned char session[4096];
    memcpy(session, "FULLSESSION:syscollector:", 25);
    memset(session + 25, 'D', sizeof session - 25);
    hc_submit_sync_session(handle, "demo-sess-1", session, sizeof session);

    unsigned char *fim_session = NULL;
    size_t fim_len = 0;
    if (sync_socket)
    {
        /* The producer path, playing the FIM module: a full sync sends every
         * monitored file's entry as ONE FullSession over the local intake
         * socket. It bypasses the legacy 64 KB DGRAM cap entirely, is spooled
         * to disk by the module, and streamed to /stateful. */
        const size_t entries = 100000; /* a mid-size server's file inventory */
        printf("== FIM full sync: building %zu file entries ==\n", entries);
        fflush(stdout);
        fim_session = build_fim_full_sync(entries, &fim_len);
        printf("== streaming the FIM full sync over the intake socket: %zu entries, "
               "%.2f MB, checksum 0x%08x ==\n", entries, fim_len / (1024.0 * 1024.0),
               additive_checksum(fim_session, fim_len));
        fflush(stdout);
        if (!hc_send_sync_session(sync_socket, "fim-full-sync-1", fim_session, fim_len))
        {
            printf("   (!) failed to stream the session to %s\n", sync_socket);
        }
    }

    printf("== forcing an out-of-cycle Notify ==\n");
    hc_notify_now(handle);

    /* Let the control loop deliver the fire-and-forget task batch (notify
     * #2); nothing is reported back (#37733: no response message). Then the
     * mock flips its config at #3 (-> /download), its settings at #5 (-> an
     * in-place startup refresh) and rotates its key at #7 (-> 401, one
     * re-enroll callback, hc_set_agent_identity recovery). */
    nap(3000);
    hc_notify_now(handle);
    nap(7000);

    /* Optional sustained mode: DEMO_SECONDS=<n> keeps the client alive after
     * the scripted walkthrough, submitting an event every 2 s so the periodic
     * Notify + /stateless traffic stays visible, and re-running the FIM full
     * sync every 60 s. SIGINT/SIGTERM (Ctrl-C, docker stop) ends it early
     * through the same clean drain. */
    const char *extra = getenv("DEMO_SECONDS");
    const long extra_s = extra ? strtol(extra, NULL, 10) : 0;
    if (extra_s > 0)
    {
        printf("== sustained mode: ~%ld s of keepalive traffic, FIM full re-sync "
               "every 60 s (Ctrl-C stops cleanly) ==\n", extra_s);
        fflush(stdout);
        int fim_round = 1;
        for (long tick = 0; tick * 2 < extra_s && !atomic_load(&g_stop); tick++)
        {
            char frame[80];
            int n = snprintf(frame, sizeof frame, "1:/var/log/syslog:sustained event %ld", tick);
            hc_submit_event(handle, (const uint8_t *)frame, (size_t)n);

            /* Every 10 s, burst enough events to exceed the mock's /stateless
             * payload cap, so the 413 -> split -> resend path is visible. */
            if (tick > 0 && tick % 5 == 0)
            {
                printf("== bursting 120 events (exceeds the /stateless cap -> 413 "
                       "split/resend) ==\n");
                fflush(stdout);
                for (int burst = 0; burst < 120; burst++)
                {
                    char big[96];
                    int m = snprintf(big, sizeof big,
                                     "1:/var/log/burst:event %ld-%d payload-padding", tick, burst);
                    hc_submit_event(handle, (const uint8_t *)big, (size_t)m);
                }
            }
            if (fim_session && tick > 0 && tick % 30 == 0)
            {
                char sid[48];
                snprintf(sid, sizeof sid, "fim-full-sync-%d", ++fim_round);
                printf("== periodic FIM full re-sync (%s, %.2f MB) ==\n", sid,
                       fim_len / (1024.0 * 1024.0));
                fflush(stdout);
                hc_send_sync_session(sync_socket, sid, fim_session, fim_len);
            }
            nap(2000);
        }
    }

    free(fim_session);
    printf("== stopping (drain + join) ==\n");
    hc_destroy(handle);
    printf("== done ==\n");
    return 0;
}
