/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "task_manager.h"

// pause(). Not pulled in by <csignal>: some libstdc++ headers happen to include it transitively on
// newer toolchains, which is why this built locally and not on the package builder.
#include <unistd.h>

#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>

/*
 * Runs the real module outside modulesd, so the qa suite can drive its socket for real.
 *
 * The point is that this is NOT a simulation: it loads the same shared object, hands it the same
 * C-ABI config, and implements the host-operations table the same way modulesd does -- only with
 * scripted answers instead of libwazuh, since libwazuh is exactly what a .so may not link.
 */

namespace
{
    volatile std::sig_atomic_t gStop = 0;

    void onSignal(int) { gStop = 1; }

    void logCallback(const int level,
                     const char* tag,
                     const char* file,
                     const int line,
                     const char* func,
                     const char* msg,
                     va_list args)
    {
        static const char* const LEVELS[] = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "DEBUG2"};
        const auto* name {(level >= 0 && level <= 5) ? LEVELS[level] : "INFO"};

        std::fprintf(stderr, "[%s] %s %s:%d:%s: ", name, tag ? tag : "-", file ? file : "-", line,
                     func ? func : "-");
        std::vfprintf(stderr, msg, args);
        std::fprintf(stderr, "\n");
        std::fflush(stderr);
    }

    /*
     * The host operations, scripted.
     *
     * Every one of these is a stub that answers plausibly rather than doing the real thing: the qa
     * suite exercises the QUEUE -- creation, claiming, retry, dead-lettering, recovery -- and the
     * recurring handlers are covered by unit tests with a fake IHostOps. Answering "no agents" and
     * "rotation done" keeps the scheduler's periodic work from failing in a way that would clutter
     * the log the suite reads.
     */
    int isWorker(void)
    {
        // 0 = master, so master-scoped schedules are allowed to spawn.
        return 0;
    }

    int emptyIdArray(long, const char*, char** out)
    {
        *out = strdup("[]");
        return *out != nullptr ? 0 : -1;
    }

    int emptyIdArrayFrom(int, const char*, char** out)
    {
        *out = strdup("[]");
        return *out != nullptr ? 0 : -1;
    }

    int agentInfo(int, char** out)
    {
        *out = strdup(R"({"name":"stub","last_keepalive":0})");
        return *out != nullptr ? 0 : -1;
    }

    void freeJson(char* json) { std::free(json); }

    int removeAgent(int, int, int* authdError)
    {
        *authdError = 0;
        return 0;
    }

    int rotateDaily(int, int, int) { return 0; }

    int rotateBySize(int, int, int, long)
    {
        // 0 = "the log was under the threshold", the common answer at a one-minute cadence.
        return 0;
    }

    void usage(const char* argv0)
    {
        std::fprintf(stderr,
                     "usage: %s --socket <path> --db <path> [--consumer <path>] [--executor-threads N]\n"
                     "\n"
                     "Runs the task manager module against the given socket and database. Both are\n"
                     "created if absent. Send SIGINT or SIGTERM to stop.\n",
                     argv0);
    }
} // namespace

int main(int argc, char** argv)
{
    task_manager_config_t config {};
    std::string socketPath;
    std::string dbPath;
    std::string consumerPath {"queue/sockets/inventory-sync-http.sock"};

    // argv[0] is not guaranteed to be present, let alone non-null.
    const char* const program {(argc > 0 && argv[0] != nullptr) ? argv[0] : "task_manager_testtool"};

    for (int i = 1; i < argc; ++i)
    {
        const std::string flag {argv[i]};

        // Every flag this tool accepts takes a value, so the value can be read once here rather
        // than through a lambda that may hand back nothing. A missing one is an ERROR: silently
        // ignoring it would start the module with a default the caller never asked for, and a qa
        // run that mistyped a path should fail loudly rather than test the wrong thing.
        if (i + 1 >= argc)
        {
            std::fprintf(stderr, "%s needs a value.\n\n", flag.c_str());
            usage(program);
            return 1;
        }

        const char* const value {argv[++i]};

        if (flag == "--socket")
        {
            socketPath = value;
        }
        else if (flag == "--db")
        {
            dbPath = value;
        }
        else if (flag == "--consumer")
        {
            consumerPath = value;
        }
        else if (flag == "--executor-threads")
        {
            config.executor_threads = std::atoi(value);
        }
        else
        {
            usage(program);
            return 1;
        }
    }

    if (socketPath.empty() || dbPath.empty())
    {
        usage(program);
        return 1;
    }

    std::snprintf(config.socket_path, sizeof(config.socket_path), "%s", socketPath.c_str());
    std::snprintf(config.db_path, sizeof(config.db_path), "%s", dbPath.c_str());
    std::snprintf(config.inventory_sync_socket, sizeof(config.inventory_sync_socket), "%s",
                  consumerPath.c_str());

    /*
     * Short intervals, so the suite does not have to wait out production cadences. Everything else
     * is left at zero, which the module reads as "use my default" -- keeping this tool honest about
     * what a real deployment does.
     */
    config.wake_backstop = 1;
    config.sweep_interval = 1;
    config.cleanup_interval = 5;
    config.claim_grace = 1;

    task_manager_host_ops_t hostOps {};
    hostOps.is_worker = isWorker;
    hostOps.disconnect_agents = emptyIdArray;
    hostOps.get_agents_by_status_from = emptyIdArrayFrom;
    hostOps.get_agent_info = agentInfo;
    hostOps.free_json = freeJson;
    hostOps.remove_agent = removeAgent;
    hostOps.rotate_log_daily = rotateDaily;
    hostOps.rotate_log_size = rotateBySize;

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    if (task_manager_start(logCallback, &config, &hostOps) != 0)
    {
        std::fprintf(stderr, "task_manager_start failed\n");
        return 1;
    }

    // Printed on stdout and flushed, so the harness can wait for readiness rather than sleeping.
    std::printf("task_manager listening on %s\n", socketPath.c_str());
    std::fflush(stdout);

    while (gStop == 0)
    {
        ::pause();
    }

    task_manager_stop();
    return 0;
}
