/*
 * Wazuh Module Manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Required for pthread_timedjoin_np on Linux (GNU extension)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "wmodules.h"
#include <sys/types.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#include "startup_gate_op.h"
#include "wm_shutdown.h"
#ifdef CLIENT
#include "agent_sync_protocol_c_interface.h"
#include "client-config.h"
#else
#include "mconf-config.h"
#include "wm_indexer_runtime.h"
#endif

static void wm_help();                  // Print help.
static void wm_setup();                 // Setup function. Exits on error.
static void wm_cleanup();               // Cleanup function, called on exiting.
static void wm_handler(int signum);     // Action on signal.
static void wm_signals_configure();     // Configure signal handling.
#ifdef WAZUH_RUNTIME_USER
static void wm_drop_privileges(const char *user); // Drop manager privileges permanently.
#endif

static int flag_foreground = 0;         // Running in foreground.

/*
 * Self-pipe between wm_handler() and the main thread (plan 18, E7a, I129). The handler only writes one byte here; the
 * main thread, which owns the indexer client runtime, reads it in wm_wait_shutdown_signal() and runs the whole shutdown
 * in wm_shutdown_run(). Both ends are non-blocking: the handler never blocks on a full pipe, and the reader drains it.
 */
static int wm_shutdown_pipe[2] = {-1, -1};
static volatile sig_atomic_t wm_shutdown_signum = 0;  // First shutdown signal received.
static pthread_t wm_main_thread;                       // The runtime's owner thread.

// Main function

int main(int argc, char **argv)
{
    int c;
    int wm_debug = 0;
    int test_config = 0;
#ifdef CLIENT
#define WM_GETOPT_CONF ""
#else
#define WM_GETOPT_CONF "c:"   // -c <config>: manager configuration file (/etc/wazuh-manager/wazuh-manager.conf)
#endif
#ifdef WAZUH_RUNTIME_USER
    const char *runtime_user = WAZUH_RUNTIME_USER;
    const char *getopt_options = "dfhtu:" WM_GETOPT_CONF;
#else
    const char *getopt_options = "dfht" WM_GETOPT_CONF;
#endif

    wm_main_thread = pthread_self();

    /* Set the name */
    OS_SetName(ARGV0);

    // Define current working directory
    char * home_path = w_homedir(argv[0]);
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }

    wmodule *cur_module;
#ifdef CLIENT
    wm_debug_level = getDefine_Int("wazuh_modules", "debug", 0, 2);
#else
    wm_debug_level = getDefine_Int_default("wazuh_modules", "debug", 0, 2, 0);
#endif

    // Get command line options

    while ((c = getopt(argc, argv, getopt_options)) != -1) {
        switch (c) {
        case 'd':
            nowDebug();
            wm_debug = 1;
            break;
        case 'f':
            flag_foreground = 1;
            break;
        case 'h':
            wm_help();
            break;
        case 't':
            test_config = 1;
            flag_foreground = 1;
            break;
#ifndef CLIENT
        case 'c':
            if (!optarg) {
                merror_exit("-c needs an argument");
            }
            wm_config_path = optarg;
            break;
#endif
#ifdef WAZUH_RUNTIME_USER
        case 'u':
            runtime_user = optarg;
            break;
#endif
        default:
            print_out(" ");
            wm_help();
        }
    }

    // Get default debug level

    if (wm_debug == 0) {
        wm_debug = wm_debug_level;

        while (wm_debug != 0) {
            nowDebug();
            wm_debug--;
        }
    }

    mdebug1(WAZUH_HOMEDIR, home_path);
    os_free(home_path);

#ifdef CLIENT
    const int nofile = getDefine_Int("wazuh_modules", "rlimit_nofile", 8192, 1048576);
#else
    const int nofile = getDefine_Int_default("wazuh_modules", "rlimit_nofile", 8192, 1048576, 65536);
#endif
    w_raise_nofile_limit(nofile, "wazuh_modules.rlimit_nofile");

#ifdef WAZUH_RUNTIME_USER
    wm_drop_privileges(runtime_user);
#endif

    // Setup daemon

    wm_setup();

    if (test_config) {
#ifndef CLIENT
        // -t also checks the files the configuration points to (certificates...), like the other
        // manager daemons; the document itself was already loaded and read by wm_config().
        if (w_mconf_validate(wm_config_path) < 0) {
            exit(EXIT_FAILURE);
        }
#endif
        exit(EXIT_SUCCESS);
    }

    minfo(STARTUP_MSG, (int)getpid());
    mdebug1("Available processors: %d", get_nproc());

    // Configure signal handling before startup gate wait so SIGTERM
    // triggers graceful cleanup even when modules are blocked.
    wm_signals_configure();

    // wm_control provides the control socket used by agentd to trigger
    // reloads that resolve the startup gate — start it before blocking.
    for (cur_module = wmodules; cur_module; cur_module = cur_module->next) {
        if (cur_module->tag && strcmp(cur_module->tag, "control") == 0) {
            if (CreateThreadJoinable(&cur_module->thread, cur_module->context->start, cur_module->data) < 0) {
                merror_exit("CreateThreadJoinable() for '%s': %s", cur_module->tag, strerror(errno));
            }
            mdebug2("Created new thread for the '%s' module.", cur_module->tag);
            break;
        }
    }

    wm_after_startup_gate();

#ifndef CLIENT
    // The indexer client runtime starts on this thread, its owner, before any module thread exists (I128). A failure
    // is already logged and modulesd goes on without a runtime (I131).
    wm_indexer_runtime_start();
#endif

    // Run modules

    for (cur_module = wmodules; cur_module; cur_module = cur_module->next) {
        if (cur_module->tag && strcmp(cur_module->tag, "control") == 0) {
            continue;  // already started above
        }
        if (CreateThreadJoinable(&cur_module->thread, cur_module->context->start, cur_module->data) < 0) {
            merror_exit("CreateThreadJoinable() for '%s': %s", cur_module->tag, strerror(errno));
        }
        mdebug2("Created new thread for the '%s' module.", cur_module->tag);
    }

    // Start com request thread
    w_create_thread(wmcom_main, NULL);

    // Modules run until a shutdown signal arrives. The handler only wakes this thread, which then runs the orderly
    // stop + timed-join + exit itself (I129): the runtime's begin_shutdown/shutdown must run on its owner thread, and
    // no other thread joins the module threads (two concurrent joins of the same thread return EINVAL/ESRCH, which
    // were misreported as shutdown timeouts). wm_shutdown_run() returns only for an unknown signal.
    for (;;) {
        wm_shutdown_run(wm_wait_shutdown_signal());
    }

    return EXIT_SUCCESS;
}

// Print help

void wm_help()
{
    print_out("Wazuh Module Manager - %s\nWazuh Inc.", __wazuh_version);
    print_out(" ");
#ifdef CLIENT
#define WM_HELP_CONF ""
#else
#define WM_HELP_CONF " [-c <config>]"
#endif
#ifdef WAZUH_RUNTIME_USER
    print_out("Usage: %s -[d|f|h|t] [-u <user>]" WM_HELP_CONF, ARGV0);
#else
    print_out("Usage: %s -[d|f|h|t]" WM_HELP_CONF, ARGV0);
#endif
    print_out(" ");
    print_out("    -d    Increase debug mode.");
    print_out("    -f    Run in foreground.");
    print_out("    -h    Print this help.");
    print_out("    -t    Test configuration.");
#ifndef CLIENT
    print_out("    -c <config> Configuration file to use (default: %s).", WAZUHCONF);
#endif
#ifdef WAZUH_RUNTIME_USER
    print_out("    -u <user> Run as user (default: %s).", WAZUH_RUNTIME_USER);
#endif

    exit(EXIT_FAILURE);
}

// Setup function. Exits on error.

void wm_setup()
{
    // Read the configuration (/etc/wazuh-manager/wazuh-manager.conf on the manager, ossec.conf on the
    // agent) and internal options

    if (wm_config() < 0) {
        exit(EXIT_FAILURE);
    }

#ifdef CLIENT
    // The sync protocol bounds one session by <agent><batch><size>, the same limit
    // that bounds a /stateless request. The block belongs to the agent rather than
    // to any module here, and the modules that build the protocol instances can
    // read no configuration at all, so it is read once and handed down before
    // wm_check() starts any of them.
    agent_batch batch = { .size = 0, .interval = 0 };
    w_read_agent_batch(WAZUHCONF, AGENTCONFIG, &batch);
    asp_set_session_max_bytes((uint64_t)batch.size);

    if (batch.size > 0) {
        mdebug1("Sync sessions bounded to %lld bytes by <agent><batch><size>.", batch.size);
    }

    // agent.sync_max_blocks_per_cycle is handed down the same way: how many of those
    // sessions one sync cycle may send before the rest waits for the next cycle.
    const int sync_max_blocks = getDefine_Int_default("agent", "sync_max_blocks_per_cycle", 1, 1000, 0);
    asp_set_max_blocks_per_sync((uint32_t)sync_max_blocks);

    if (sync_max_blocks > 0) {
        mdebug1("Sync cycles bounded to %d blocks by agent.sync_max_blocks_per_cycle.", sync_max_blocks);
    }
#endif

    // Go daemon

    if (!flag_foreground) {
        goDaemon();
        nowDaemon();
    }

#ifndef WAZUH_RUNTIME_USER
    const gid_t gid = Privsep_GetGroup(GROUPGLOBAL);
    if (gid == (gid_t) OS_INVALID) {
        merror_exit(USER_ERROR, "", GROUPGLOBAL, strerror(errno), errno);
    }

    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, GROUPGLOBAL, errno, strerror(errno));
    }

    wm_setGroupID(gid);
#endif

    if (wm_check() < 0) {
        mdebug1("No configuration defined. Exiting...");
        exit(EXIT_SUCCESS);
    }

    // Register cleanup function before CreatePID to avoid dangling PID files
    atexit(wm_cleanup);

    // Create PID file

    if (CreatePID(ARGV0, getpid()) < 0)
        merror_exit("Couldn't create PID file: (%s)", strerror(errno));

    // Initialize children pool
    wm_children_pool_init();
}

#ifdef WAZUH_RUNTIME_USER
static void wm_drop_privileges(const char *user)
{
    const uid_t uid = Privsep_GetUser(user);
    const gid_t gid = Privsep_GetGroup(GROUPGLOBAL);

    if (uid == (uid_t) OS_INVALID || gid == (gid_t) OS_INVALID) {
        merror_exit(USER_ERROR, user, GROUPGLOBAL, strerror(errno), errno);
    }

    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, GROUPGLOBAL, errno, strerror(errno));
    }

    if (Privsep_SetUser(uid) < 0) {
        merror_exit(SETUID_ERROR, user, errno, strerror(errno));
    }

    if (getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid) {
        merror_exit("Privilege drop to '%s:%s' could not be verified.", user, GROUPGLOBAL);
    }

    wm_setGroupID(gid);
    umask(0007);
}
#endif

// Cleanup function, called on exiting.

void wm_cleanup()
{
#ifndef CLIENT
    // Only the owner thread may shut the runtime down; an exit() from any other thread leaves it to the process
    // teardown (D71). Before the children are killed, so no request is still in flight towards them.
    if (pthread_equal(pthread_self(), wm_main_thread)) {
        wm_indexer_runtime_shutdown();
    }
#endif

    // Kill active child processes
    wm_kill_children();

    // Delete PID file

    if (DeletePID(ARGV0) < 0) {
        mdebug1("Couldn't delete PID file.");
    }
}

// Action on signal

void wm_signals_configure()
{
    // The self-pipe exists before any handler is installed, so wm_handler() always has a valid write end. pipe() and
    // fcntl() rather than pipe2(), which not every supported platform has.
    if (pipe(wm_shutdown_pipe) < 0) {
        merror_exit("Couldn't create the shutdown pipe: %s (%d)", strerror(errno), errno);
    }

    for (int i = 0; i < 2; i++) {
        const int fl = fcntl(wm_shutdown_pipe[i], F_GETFL);
        const int fd = fcntl(wm_shutdown_pipe[i], F_GETFD);

        if (fl < 0 || fcntl(wm_shutdown_pipe[i], F_SETFL, fl | O_NONBLOCK) < 0
            || fd < 0 || fcntl(wm_shutdown_pipe[i], F_SETFD, fd | FD_CLOEXEC) < 0) {
            merror_exit("Couldn't configure the shutdown pipe: %s (%d)", strerror(errno), errno);
        }
    }

    struct sigaction action = { .sa_handler = wm_handler };

    sigaction(SIGTERM, &action, NULL);

    if (flag_foreground) {
        sigaction(SIGHUP, &action, NULL);
        sigaction(SIGINT, &action, NULL);
    }

    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);
}

/*
 * Async-signal-safe: it only stores into sig_atomic_t variables and write()s one byte to the non-blocking self-pipe. No
 * mutex, logging, sleep, stop() or exit here: the shutdown runs on the main thread (wm_shutdown_run(), I129).
 */
void wm_handler(int signum)
{
    int saved_errno = errno;

    // Raised first: wazuh-control signals every daemon in the same pass, so syscheckd can already be gone during the
    // grace wait. wm_fim_query_json() and modulesSync() read this flag to log that as part of the shutdown instead of
    // an ERROR, and agent-info aborts its coordination on it. Module loops blocked in the interruptible waits of
    // wmodules.c leave on it, and the modules that check it while still starting up abort their start. A later signal
    // sets it again.
    wm_shutdown_requested = 1;

    if (!wm_shutdown_signum) {
        wm_shutdown_signum = signum;
    }

    // A full pipe (EAGAIN) already holds a wake-up for the main thread.
    ssize_t r = write(wm_shutdown_pipe[1], "s", 1);
    (void)r;

    errno = saved_errno;
}

int wm_wait_shutdown_signal(void)
{
    static bool returned = false;   // The signal is handed out once; later calls keep waiting.
    bool pipe_ok = wm_shutdown_pipe[0] >= 0;

    while (pipe_ok) {
        struct pollfd pfd = { .fd = wm_shutdown_pipe[0], .events = POLLIN };
        const int rc = poll(&pfd, 1, -1);

        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            merror("Couldn't wait on the shutdown pipe: %s (%d)", strerror(errno), errno);
            pipe_ok = false;
            break;
        }

        if (rc == 0) {
            continue;
        }

        if (!(pfd.revents & POLLIN)) {
            merror("Couldn't wait on the shutdown pipe: unexpected poll events (0x%x)", (unsigned int)pfd.revents);
            pipe_ok = false;
            break;
        }

        // Drain every pending wake-up, so later signals only find an empty pipe.
        for (;;) {
            char buf[64];
            const ssize_t n = read(wm_shutdown_pipe[0], buf, sizeof(buf));

            if (n > 0) {
                continue;
            }
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                merror("Couldn't read the shutdown pipe: %s (%d)", strerror(errno), errno);
                pipe_ok = false;
            }
            break;
        }

        if (!pipe_ok) {
            break;
        }

        if (!returned) {
            returned = true;
            return wm_shutdown_signum;
        }
    }

    // Fallback without the pipe: poll the flag once per second.
    for (;;) {
        if (wm_shutdown_requested && !returned) {
            returned = true;
            return wm_shutdown_signum;
        }
        sleep(1);
    }
}

void wm_after_startup_gate(void)
{
    if (startup_gate_wait_for_ready(ARGV0) != STARTUP_GATE_READY) {
        mdebug1("'%s' shutdown requested while waiting for the startup gate; exiting without starting.", ARGV0);
        // The shutdown that interrupted the gate runs the same sequence as any other: no plain exit(0) (I129).
        wm_shutdown_run(wm_wait_shutdown_signal());
    }
}

// Milliseconds from *from to *to (CLOCK_MONOTONIC).
static long wm_elapsed_ms(const struct timespec *from, const struct timespec *to)
{
    return (long)(to->tv_sec - from->tv_sec) * 1000L + (long)(to->tv_nsec - from->tv_nsec) / 1000000L;
}

void wm_shutdown_run(int signum)
{
    wmodule * cur_module;
    struct timespec t0;
    struct timespec now;

    switch (signum) {
    case SIGHUP:
    case SIGINT:
    case SIGTERM:
        break;
    default:
        merror("unknown signal (%d)", signum);
        return;
    }

    // Every budget below is measured from T0, on the monotonic clock.
    clock_gettime(CLOCK_MONOTONIC, &t0);

    mdebug1("Shutting down Wazuh modules.");
#ifdef __linux__
    mdebug1("Shutdown sequence running on thread %ld.", (long)syscall(SYS_gettid));
#endif

    // Grace time before the stop() callbacks, so the modules that don't read the flag can finish starting. A signal
    // that interrupts nanosleep() does not shorten it: the remainder is recomputed from T0.
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        const long rem = 1000L - wm_elapsed_ms(&t0, &now);

        if (rem <= 0) {
            break;
        }

        struct timespec req = { .tv_sec = rem / 1000L, .tv_nsec = (rem % 1000L) * 1000000L };
        nanosleep(&req, NULL);
    }

#ifndef CLIENT
    // The runtime's in-flight requests get until T0+25 s, before the module threads are asked to stop.
    clock_gettime(CLOCK_MONOTONIC, &now);
    wm_indexer_runtime_begin_shutdown(25000L - wm_elapsed_ms(&t0, &now));
#endif

    for (cur_module = wmodules; cur_module && cur_module->context && cur_module->context->name; cur_module = cur_module->next) {
        if (cur_module->context->stop) {
            cur_module->context->stop(cur_module->data);
        }
    }

    // Wait for all module threads to finish cleanly, until T0+28 s in total. This prevents RocksDB lock leaks and
    // other resource corruption caused by abrupt thread termination. pthread_timedjoin_np() takes a CLOCK_REALTIME
    // deadline, derived once from the monotonic budget.
    {
        struct timespec deadline;
        long remaining_ms;

        clock_gettime(CLOCK_MONOTONIC, &now);
        remaining_ms = 28000L - wm_elapsed_ms(&t0, &now);
        clock_gettime(CLOCK_REALTIME, &deadline);

        deadline.tv_sec += remaining_ms / 1000L;
        deadline.tv_nsec += (remaining_ms % 1000L) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000L;
        } else if (deadline.tv_nsec < 0) {
            deadline.tv_sec--;
            deadline.tv_nsec += 1000000000L;
        }

        for (cur_module = wmodules; cur_module && cur_module->context && cur_module->context->name; cur_module = cur_module->next) {
            if (cur_module->thread == (pthread_t)0) continue;
            if (cur_module->thread == pthread_self()) continue;
#ifdef __linux__
            int join_rc = pthread_timedjoin_np(cur_module->thread, NULL, &deadline);
            if (join_rc != 0) {
                mwarn("Module '%s' did not stop within the shutdown timeout. (rc=%d: %s)",
                      cur_module->context->name, join_rc, strerror(join_rc));
            }
#else
            pthread_join(cur_module->thread, NULL);
#endif
        }
    }

#ifndef CLIENT
    wm_indexer_runtime_shutdown();
#endif

    exit(EXIT_SUCCESS);
}
