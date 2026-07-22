/*
 * Wazuh agent HTTPS client — demo driver.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * A standalone, plain-C program that drives the REAL https_client module (the
 * production libhttps_client, exactly as agentd would through the bridge) at a
 * local mock manager, printing every callback so the conversation is visible.
 *
 * It stands in for agentd: build a config, hc_create/hc_start, watch the
 * /control lifecycle run (startup, notifies, a settings flip, a key rotation
 * with re-enrollment), then hc_destroy. Not production code; a demo harness
 * only.
 */

/* Expose POSIX clock_gettime/nanosleep under strict -std=c11 on glibc. */
#define _POSIX_C_SOURCE 200809L

#include "https_client.h"

#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static struct timespec g_start;

static hc_handle *g_handle;

/* The key the mock rotates to at ROTATE_KEY_AT; the re-enroll callback swaps
 * to it (matches mock_manager.py ROTATED_KEY). */
static const char *g_rotated_key = "0f0e0d0c0b0a09080706050403020100";

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
 * agent re-enrolls via authd; here we just swap to the mock's rotated key
 * (hc_set_agent_key is callback-safe), which clears the pause and re-registers. */
static void on_reenroll_required(void *user_data)
{
    (void)user_data;
    printf("[+%7ld ms] >> RE-ENROLL REQUIRED (401): swapping to the new key via "
           "hc_set_agent_key -> %s\n", elapsed_ms(),
           hc_set_agent_key(g_handle, g_rotated_key) ? "accepted" : "rejected");
    fflush(stdout);
}

static void on_state_change(int state, void *user_data)
{
    (void)user_data;
    printf("[+%7ld ms] ~~ connection state -> %s\n", elapsed_ms(), state_name(state));
    fflush(stdout);
}

static void nap(int ms)
{
    struct timespec t = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&t, NULL);
}

int main(int argc, char **argv)
{
    if (argc < 4)
    {
        fprintf(stderr, "usage: %s <host> <port> <key_hex>\n", argv[0]);
        return 2;
    }
    clock_gettime(CLOCK_MONOTONIC, &g_start);

    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_signal;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    hc_config_t config;
    memset(&config, 0, sizeof config);
    strncpy(config.server_host, argv[1], sizeof config.server_host - 1);
    config.server_port = (uint16_t)atoi(argv[2]);
    strncpy(config.agent_id, "001", sizeof config.agent_id - 1);
    strncpy(config.agent_key, argv[3], sizeof config.agent_key - 1);
    config.verify_mode = HC_VERIFY_NONE; /* demo mock uses a self-signed cert */
    config.notify_interval_s = 2;        /* Notify every 2 s so we see a few   */
    config.request_timeout_ms = 10000;
    config.backoff_base_ms = 200;
    config.backoff_cap_ms = 2000;
    strncpy(config.version, "5.1.0", sizeof config.version - 1);

    hc_callbacks_t callbacks;
    memset(&callbacks, 0, sizeof callbacks);
    callbacks.log = on_log;
    callbacks.on_startup_result = on_startup_result;
    callbacks.on_reenroll_required = on_reenroll_required;
    callbacks.on_state_change = on_state_change;

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

    printf("== forcing an out-of-cycle Notify ==\n");
    hc_notify_now(handle);

    /* Let the control loop run: the mock flips its settings at notify #5
     * (-> the client refreshes startup in place) and rotates its key at #7
     * (-> 401, one re-enroll callback, hc_set_agent_key recovery). */
    nap(3000);
    hc_notify_now(handle);
    nap(7000);

    /* Optional sustained mode: DEMO_SECONDS=<n> keeps the client alive after
     * the scripted walkthrough so the periodic Notify traffic (and the key
     * rotation at notify #7) stays visible. SIGINT/SIGTERM (Ctrl-C, docker
     * stop) ends it early through the same clean drain. */
    const char *extra = getenv("DEMO_SECONDS");
    const long extra_s = extra ? strtol(extra, NULL, 10) : 0;
    if (extra_s > 0)
    {
        printf("== sustained mode: ~%ld s of keepalive traffic (Ctrl-C stops cleanly) ==\n",
               extra_s);
        fflush(stdout);
        for (long tick = 0; tick * 2 < extra_s && !atomic_load(&g_stop); tick++)
        {
            nap(2000);
        }
    }

    printf("== stopping (drain + join) ==\n");
    hc_destroy(handle);
    printf("== done ==\n");
    return 0;
}
