/*
 * Wazuh agent HTTPS client — demo driver.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * A standalone, plain-C program that drives the REAL https_client module (the
 * production libhttps_client, exactly as agentd would through the bridge) at a
 * local mock manager, printing every callback so the conversation is visible.
 *
 * It stands in for agentd: build a config, hc_create/hc_start, feed a few
 * events and one sync session, force a Notify, let the control loop run, then
 * hc_destroy. Not production code; a demo harness only.
 */

#include "https_client.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static struct timespec g_start;

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

static void on_task(const char *task_id, const char *task_type, const char *payload_json,
                    void *user_data)
{
    (void)user_data;
    printf("[+%7ld ms] >> TASK received: id=%s type=%s payload=%s\n", elapsed_ms(), task_id,
           task_type, payload_json);
    fflush(stdout);
}

static void on_sync_response(const char *session_id, int result, const char *body, void *user_data)
{
    (void)user_data;
    printf("[+%7ld ms] >> STATEFUL result: session=%s result=%d body=%s\n", elapsed_ms(),
           session_id, result, body ? body : "(none)");
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

int main(int argc, char **argv)
{
    if (argc < 4)
    {
        fprintf(stderr, "usage: %s <host> <port> <key_hex>\n", argv[0]);
        return 2;
    }
    clock_gettime(CLOCK_MONOTONIC, &g_start);

    hc_config_t config;
    memset(&config, 0, sizeof config);
    strncpy(config.server_host, argv[1], sizeof config.server_host - 1);
    config.server_port = (uint16_t)atoi(argv[2]);
    strncpy(config.agent_id, "001", sizeof config.agent_id - 1);
    strncpy(config.agent_key, argv[3], sizeof config.agent_key - 1);
    config.verify_mode = HC_VERIFY_NONE; /* demo mock uses a self-signed cert */
    config.notify_interval_s = 2;        /* Notify every 2 s so we see a few   */
    config.batch_interval_ms = 1000;     /* flush events every 1 s             */
    config.request_timeout_ms = 3000;
    config.backoff_base_ms = 200;
    config.backoff_cap_ms = 2000;
    strncpy(config.version, "5.1.0", sizeof config.version - 1);
    strncpy(config.config_checksum, "d41d8cd98f00b204e9800998ecf8427e",
            sizeof config.config_checksum - 1);

    hc_callbacks_t callbacks;
    memset(&callbacks, 0, sizeof callbacks);
    callbacks.log = on_log;
    callbacks.on_startup_result = on_startup_result;
    callbacks.on_task = on_task;
    callbacks.on_sync_response = on_sync_response;
    callbacks.on_state_change = on_state_change;
    callbacks.on_buffer_level = on_buffer_level;

    printf("== creating + starting the https_client (target %s:%s) ==\n", argv[1], argv[2]);
    hc_handle *handle = hc_create(&config, &callbacks);
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

    printf("== submitting a /stateful sync session (streamed) ==\n");
    unsigned char session[4096];
    memcpy(session, "FULLSESSION:syscollector:", 25);
    memset(session + 25, 'D', sizeof session - 25);
    hc_submit_sync_session(handle, "demo-sess-1", session, sizeof session);

    printf("== forcing an out-of-cycle Notify ==\n");
    hc_notify_now(handle);

    /* Let the control loop run a few Notify cycles (tasks, responses). */
    nap(6000);

    printf("== stopping (drain + join) ==\n");
    hc_destroy(handle);
    printf("== done ==\n");
    return 0;
}
