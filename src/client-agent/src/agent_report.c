/* Agent-wide config and stats reports
 * Copyright (C) 2015, Wazuh Inc.
 * July 29, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include "agentd.h"
#include "os_net.h"

#ifdef WIN32
#include "execd.h"
#include "logcollector.h"
#include "syscheck.h"
#include "wmodules.h"
#endif

/* The agent's modules live in separate daemons, so a full picture costs one
 * query per daemon. Each answers with the report for the modules it hosts, and
 * the arrays below are concatenated into the document pushed to /config and
 * /stats. A daemon that is disabled or not answering is left out rather than
 * reported empty, so the manager can tell "not running" from "nothing set". */

typedef struct report_source_t {
    const char *target;     ///< Component socket name under queue/sockets.
    const char *command;    ///< Command that yields that component's report.
} report_source_t;

static const report_source_t CONFIG_SOURCES[] = {
    {"agent", "getallconfig"},
    {"syscheck", "getallconfig"},
    {"logcollector", "getallconfig"},
    {"wmodules", "getallconfig"},
    {"com", "getallconfig"},
};

/* Only these two produce statistics today; the rest have no getstate handler. */
static const report_source_t STATS_SOURCES[] = {
    {"agent", "getallstats"},
    {"logcollector", "getallstats"},
};

/* REPORT_STARTUP_SETTLE_SECONDS (agentd.h): the other daemons each poll the
 * same startup gate on their own 1 s interval (STARTUP_GATE_POLL_INTERVAL)
 * and then still need a moment to open their own command socket, so the gate
 * opening is not the same instant as every daemon answering. See
 * startup_gate_is_settled(). */

#ifdef WIN32

/**
 * @brief Dispatch a command in-process, the way request.c does on Windows.
 * @param target Component name.
 * @param command Command to run. Modified in place by the dispatchers.
 * @param output Receives the allocated reply.
 * @return Length of *output, or 0 when the target is unknown.
 */
static size_t report_dispatch(const char *target, char *command, char **output) {
    const size_t length = strlen(command);

    if (strcmp(target, "agent") == 0) {
        return agcom_dispatch(command, output);
    } else if (strcmp(target, "syscheck") == 0) {
        return syscom_dispatch(command, length, output);
    } else if (strcmp(target, "logcollector") == 0) {
        return lccom_dispatch(command, output);
    } else if (strcmp(target, "wmodules") == 0) {
        return wmcom_dispatch(command, length, output);
    } else if (strcmp(target, "com") == 0) {
        return wcom_dispatch(command, output);
    }

    return 0;
}

/**
 * @brief Ask one component for its report. Windows runs every daemon inside a
 *        single process, so this is a direct call instead of a socket round trip.
 */
static char *report_query(const char *target, const char *command) {
    char request[OS_SIZE_128] = {0};
    char *response = NULL;

    /* In-process there is no socket to refuse the call the way the POSIX
     * report_query() below gets refused: dispatching straight into e.g.
     * syscheckd before its own thread has run past the startup gate touches
     * state it has not initialized yet (its directories_lock is a prime
     * example) instead of getting turned away. The startup gate is the only
     * cross-module readiness signal this process has, so until it (plus the
     * settle margin) has elapsed, every target is treated the same way a
     * component that is not answering yet would be -- see the POSIX
     * report_query() below for the other half of why this also guards
     * against a pre-reload config. */
    if (!startup_gate_is_settled(REPORT_STARTUP_SETTLE_SECONDS))
    {
        mdebug1("Component '%s' is not answering, leaving it out of the report.", target);
        return NULL;
    }

    snprintf(request, sizeof(request), "%s", command);

    if (report_dispatch(target, request, &response) == 0) {
        /* Same line, and the same reason, as the POSIX connect failure below:
         * the component produced nothing, so it is left out of the report.
         * Worth saying on both platforms -- a module missing from /config is
         * otherwise silent here, with no socket error to point at. */
        mdebug1("Component '%s' is not answering, leaving it out of the report.", target);
        os_free(response);
        return NULL;
    }

    return response;
}

#else

/**
 * @brief Send a command to a component socket and read the whole reply back.
 * @param sock Connected socket. Closed by this call.
 * @param command Command to send.
 * @return Allocated reply, or NULL when the exchange failed.
 */
static char *report_exchange(int sock, const char *command) {
    char *response = NULL;
    ssize_t length;

    if (OS_SendSecureTCP(sock, strlen(command), command) != 0) {
        mdebug1("Could not send '%s' to a component socket: %s", command, strerror(errno));
        close(sock);
        return NULL;
    }

    /* One byte short of the buffer, so the terminator below always has room. */
    os_calloc(OS_MAXSTR, sizeof(char), response);
    length = OS_RecvSecureTCP(sock, response, OS_MAXSTR - 1);
    close(sock);

    if (length <= 0) {
        /* OS_SOCKTERR here means the component's report did not fit in the
         * socket's buffer, which is the one failure worth naming. */
        mdebug1("No usable answer to '%s': %s", command,
                length == OS_SOCKTERR ? "the report is larger than the socket allows"
                                      : strerror(errno));
        os_free(response);
        return NULL;
    }

    response[length] = '\0';
    return response;
}

/**
 * @brief Ask one component for its report over its local socket.
 */
static char *report_query(const char *target, const char *command) {
    char sockname[PATH_MAX + 1] = {0};
    int sock;

    /* Same reasoning as the Windows report_query() above: until the startup
     * gate opens (plus REPORT_STARTUP_SETTLE_SECONDS, for the other daemons
     * to have very likely opened their own sockets too), a component that
     * has not started yet is indistinguishable from one that is disabled,
     * and a component that HAS opened its socket may still be running on the
     * pre-reload configuration if a fresher one is about to be downloaded
     * from the manager. Skipping every source until then keeps the first
     * /config (and /stats) push from racing that decision -- report_collect()
     * then sees nothing answered and the caller retries on its short backoff
     * instead of settling for whatever happened to be up first. */
    if (!startup_gate_is_settled(REPORT_STARTUP_SETTLE_SECONDS))
    {
        mdebug1("Component '%s' is not answering, leaving it out of the report.", target);
        return NULL;
    }

    snprintf(sockname, sizeof(sockname), "queue/sockets/%s", target);

    if (sock = OS_ConnectUnixDomain(sockname, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        mdebug1("Component '%s' is not answering, leaving it out of the report.", target);
        return NULL;
    }

    return report_exchange(sock, command);
}

#endif /* WIN32 */

/**
 * @brief Parse one component's reply into the array of entries it carries.
 * @param target Component name, for logging.
 * @param reply Component reply, "ok <json>" on success. Freed by this call.
 * @return Parsed array, or NULL when the component reported an error.
 */
static cJSON *report_entries(const char *target, char *reply) {
    cJSON *entries = NULL;

    if (!reply) {
        return NULL;
    }

    if (strncmp(reply, "ok ", 3) != 0) {
        mdebug1("Component '%s' refused to report: %s", target, reply);
        os_free(reply);
        return NULL;
    }

    if (entries = cJSON_Parse(reply + 3), !entries || !cJSON_IsObject(entries)) {
        mdebug1("Component '%s' answered with something other than a report.", target);
        cJSON_Delete(entries);
        entries = NULL;
    }

    os_free(reply);
    return entries;
}

/**
 * @brief Move every module of a component's report into the combined one.
 * @param report Destination object, keyed by module name.
 * @param entries Source object. Consumed by this call.
 */
static void report_absorb(cJSON *report, cJSON *entries) {
    cJSON *entry = NULL;

    while (entries && (entry = entries->child)) {
        cJSON_DetachItemViaPointer(entries, entry);
        /* Same key-lifetime rule as module_report_merge(): cJSON copies the key
         * before releasing the item's own, so passing entry->string is safe. */
        cJSON_AddItemToObject(report, entry->string, entry);
    }

    cJSON_Delete(entries);
}

/**
 * @brief Query every source and serialize the modules they reported.
 * @param sources Component/command pairs to query.
 * @param count Number of sources.
 * @return Allocated JSON document, or NULL when no component answered.
 */
static char *report_collect(const report_source_t *sources, size_t count) {
    cJSON *root = cJSON_CreateObject();
    cJSON *report = cJSON_CreateObject();
    char *document = NULL;
    size_t i;

    if (!root || !report) {
        cJSON_Delete(root);
        cJSON_Delete(report);
        return NULL; /* Out of memory: skip the cycle, same as nothing answering. */
    }

    for (i = 0; i < count; i++) {
        report_absorb(report, report_entries(sources[i].target,
                                             report_query(sources[i].target,
                                                          sources[i].command)));
    }

    if (!report->child) {
        /* Nothing answered. Skip the cycle instead of pushing an empty
         * document that would overwrite a good one in the manager's index. */
        cJSON_Delete(report);
        cJSON_Delete(root);
        return NULL;
    }

    cJSON_AddItemToObject(root, "modules", report);
    document = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return document;
}

char *w_agent_collect_config(void) {
    return report_collect(CONFIG_SOURCES, sizeof(CONFIG_SOURCES) / sizeof(CONFIG_SOURCES[0]));
}

char *w_agent_collect_stats(void) {
    return report_collect(STATS_SOURCES, sizeof(STATS_SOURCES) / sizeof(STATS_SOURCES[0]));
}
