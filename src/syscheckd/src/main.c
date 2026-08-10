/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Syscheck
 * Copyright (C) 2003 Daniel B. Cid <daniel@underlinux.com.br>
 */
#include "rootcheck.h"
#include "agent_sync_protocol_c_interface.h"
#ifdef CLIENT
#include "client-config.h"
#endif
#include "db.h"
#include "shared.h"
#include "syscheck.h"
#include "startup_gate_op.h"

#ifndef WIN32

#include <poll.h>

#define Q(x) #x
#define QUOTE(x) Q(x)

/* Milliseconds fim_shutdown_waiter() waits for the synchronization thread to report its
 * exit before giving up on the teardown; wazuh-control escalates to SIGKILL after ~30
 * seconds (MAX_KILL_TRIES in init/wazuh-client.sh), so stay well under that. */
#define FIM_SYNC_EXIT_TIMEOUT_MS 20000

// LCOV_EXCL_START

/* Print help statement */
__attribute__((noreturn)) static void help_syscheckd()
{
    print_header();
    print_out("  %s: -[Vhdtf] [-c config]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -c <config> Configuration file to use (default: %s)", WAZUHCONF);
    print_out(" ");
    exit(1);
}

extern bool is_fim_shutdown;
extern volatile int fim_sync_module_running;
extern pthread_t fim_sync_thread;
extern bool fim_sync_thread_initialized;
extern int fim_sync_exit_pipe[2];

/* Self-pipe written by fim_shutdown() to wake fim_shutdown_waiter() */
static int fim_shutdown_pipe[2] = {-1, -1};
/* Signal that triggered the shutdown, consumed by fim_shutdown_waiter() */
static volatile sig_atomic_t fim_shutdown_sig = SIGTERM;

/* Shut down syscheckd properly. This thread performs the teardown that fim_shutdown()
 * cannot do in signal context. Joining the synchronization thread from the handler
 * could deadlock: if the signal lands on a thread that holds syscheck.directories_lock
 * or syscheck.fim_scan_mutex (e.g. the main thread inside fim_scan()), that thread
 * parks in the handler without releasing them, while fim_run_integrity blocks on those
 * very locks and never re-checks fim_sync_module_running, so the join never returns.
 * Destroying the sync protocol handle from the handler is not safe either: it is still
 * used by threads that are never joined (event persistence, syscom), and a second
 * termination signal (signal() leaves the other signals unblocked while the handler
 * runs) could re-enter the handler, skip the join and free the handle under the live
 * synchronization thread. */
static void *fim_shutdown_waiter(__attribute__((unused)) void *arg)
{
    char buf;

    /* Wait for fim_shutdown() to report a termination signal */
    while (!fim_shutdown_process_on())
    {
        if (read(fim_shutdown_pipe[0], &buf, 1) < 0 && errno != EINTR)
        {
            sleep(1); // Defensive: reading the shutdown pipe cannot fail in practice
        }
    }

    minfo(SK_SHUTDOWN);

    /* Abort any in-flight synchronization so the join below is short */
    if (syscheck.sync_handle)
    {
        asp_stop(syscheck.sync_handle);
    }

    /* Wait for the inventory synchronization thread to exit: its loop reacts to
     * fim_sync_module_running (cleared by fim_shutdown()) within a second, and asp_stop()
     * above aborts an in-flight synchronization. The initialized flag is read under the
     * same write lock start_daemon() publishes it under, so the startup window cannot be
     * missed: either the thread is already visible here and gets joined before the handle
     * is destroyed, or start_daemon() observes the shutdown (is_fim_shutdown is
     * republished under the lock so the rwlock orders it) and never creates the thread. */
    w_rwlock_wrlock(&fim_sync_handle_rwlock);
    is_fim_shutdown = true;
    /* Republished under the lock: the signal can land between start_daemon()'s shutdown
     * check and its `fim_sync_module_running = 1`, which would overwrite the handler's
     * clear inside the creation critical section. Re-clearing here (ordered after that
     * section by the lock) makes the freshly created loop observe the stop within a
     * second, so the join below still completes. */
    fim_sync_module_running = 0;
    bool join_sync_thread = fim_sync_thread_initialized;
    /* Read the thread handle under the same lock its writer (start_daemon) holds, so the
     * join below never races the creation store. */
    pthread_t sync_thread = fim_sync_thread;
    fim_sync_thread_initialized = false;
    w_rwlock_unlock(&fim_sync_handle_rwlock);

    bool sync_thread_exited = true;

    if (join_sync_thread)
    {
        /* Everything the synchronization thread can block on after asp_stop() is bounded
         * (stop-aware waits, predicated sends, 1-second sleeps), so it reports its exit
         * through fim_sync_exit_pipe well within this timeout. If it does not, skip the
         * join and the teardown below — destroying the handle under a live thread is the
         * use-after-free this waiter exists to prevent — and proceed to _exit(). */
        struct pollfd sync_exit_poll = { .fd = fim_sync_exit_pipe[0], .events = POLLIN, .revents = 0 };
        int poll_ret;

        while ((poll_ret = poll(&sync_exit_poll, 1, FIM_SYNC_EXIT_TIMEOUT_MS)) < 0 && errno == EINTR) {}

        if (poll_ret > 0)
        {
            pthread_join(sync_thread, NULL);
        }
        else
        {
            sync_thread_exited = false;
            mwarn("The FIM inventory synchronization thread did not exit in time: skipping the synchronization database teardown.");
        }
    }

    if (sync_thread_exited)
    {
        /* Destroy the sync protocol handle so its SQLite connection to fim_sync.db is
         * closed cleanly (checkpointing and removing the -wal/-shm files) instead of
         * being leaked (issue #37334). The write lock excludes the handle users that
         * are not joined above (event persistence, syscom's fim_sync responses, the
         * DataClean paths and the scheduled-scan asp_reset), which take it for reading
         * around each call. */
        w_rwlock_wrlock(&fim_sync_handle_rwlock);
        if (syscheck.sync_handle)
        {
            asp_destroy(syscheck.sync_handle);
            syscheck.sync_handle = NULL;
        }
        w_rwlock_unlock(&fim_sync_handle_rwlock);

        /* fim.db itself runs journal_mode=truncate (no -wal/-shm files): this teardown
         * releases the DBSync context in a controlled order before exit(), it is not WAL
         * cleanup. FIMDB's internal guards turn the event/query paths into graceful
         * no-ops after it, but the scan transaction path (fim_db_transaction_*) is not
         * covered by them. The scan transaction lives entirely inside fim_scan_mutex, so
         * tear down only when no scan is in flight and keep the mutex so a new scan
         * cannot start a transaction against the released context; otherwise skip it —
         * exiting with fim.db open is safe (the truncate journal recovers on the next
         * start), closing it under a live transaction is not. */
        if (pthread_mutex_trylock(&syscheck.fim_scan_mutex) == 0)
        {
            fim_db_teardown();
        }
        else
        {
            mdebug1("Skipping the FIM database teardown: a scan is in progress.");
        }
    }

    /* Not HandleSIG(): its exit() would run the static destructors and the atexit handlers
     * while the threads this waiter could not join are still using them (issue #37993). */
    minfo(SIGNAL_RECV, (int)fim_shutdown_sig, strsignal((int)fim_shutdown_sig));
#ifdef ENABLE_AUDIT
    clean_rules();
#endif
    DeletePID(ARGV0);
    _exit(1);

    return NULL;
}

/* Termination signal handler: only async-signal-safe work happens here; the actual
 * teardown runs in fim_shutdown_waiter() (see above) */
static void fim_shutdown(int sig)
{
    int saved_errno = errno;

    fim_shutdown_sig = sig;
    is_fim_shutdown = true;
    fim_sync_module_running = 0;

    if (fim_shutdown_pipe[1] >= 0)
    {
        /* Wake the shutdown waiter; write() is async-signal-safe */
        while (write(fim_shutdown_pipe[1], "", 1) < 0 && errno == EINTR) {}
    }

    errno = saved_errno;
}

/* Syscheck unix main */
int main(int argc, char **argv)
{
    int c, r;
    int debug_level = 0;
    int test_config = 0, run_foreground = 0;
    const char *cfg = WAZUHCONF;
    gid_t gid;
    const char *group = QUOTE(GROUPGLOBAL);
    directory_t *dir_it = NULL;
    int start_realtime = 0;

    /* Set the name */
    OS_SetName(ARGV0);

    char * home_path = w_homedir(argv[0]);

    while ((c = getopt(argc, argv, "Vtdhfc:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_syscheckd();
                break;
            case 'd':
                nowDebug();
                debug_level ++;
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'c':
                if (!optarg) {
                    merror_exit("-c needs an argument");
                }
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_syscheckd();
                break;
        }
    }

    /* Change current working directory */
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }

    mdebug1(WAZUH_HOMEDIR, home_path);
    os_free(home_path);

    /* Check if the group given is valid */
    gid = Privsep_GetGroup(group);
    if (gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, "", group, strerror(errno), errno);
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* Initialize error logging for shared modulesd */
    dbsync_initialize(loggingErrorFunction);

    /* Read internal options */
    read_internal(debug_level);

    /* Check if the configuration is present */
    if (File_DateofChange(cfg) < 0) {
        merror_exit(NO_CONFIG, cfg);
    }

#ifdef CLIENT
    /* The sync protocol bounds one session by <agent><batch><size>, the same limit
     * that bounds a /stateless request. The block belongs to the agent rather than
     * to this daemon, and the protocol reads no configuration of its own, so it is
     * read here and handed down before fim_initialize() builds the instance. */
    agent_batch batch = { .size = 0, .interval = 0 };
    w_read_agent_batch(WAZUHCONF, AGENTCONFIG, &batch);
    asp_set_session_max_bytes((uint64_t)batch.size);

    if (batch.size > 0) {
        mdebug1("Sync sessions bounded to %lld bytes by <agent><batch><size>.", batch.size);
    }
#endif

    /* Read syscheck config */
    if ((r = Read_Syscheck_Config(cfg)) < 0) {
        mwarn(RCONFIG_ERROR, SYSCHECK, cfg);
        syscheck.disabled = 1;
    } else if ((r == 1) || (syscheck.disabled == 1)) {
        if (syscheck.directories == NULL || OSList_GetFirstNode(syscheck.directories) == NULL) {
            if (!test_config) {
                minfo(FIM_DIRECTORY_NOPROVIDED);
            }
        }

        if (!syscheck.ignore) {
            os_calloc(1, sizeof(char *), syscheck.ignore);
        } else {
            os_free(syscheck.ignore[0]);
        }

        if (!test_config) {
            minfo(FIM_DISABLED);
        }
    }

    /* Exit if testing config */
    if (test_config) {
        // Validate rootcheck config too; rootcheck_init() with test_config=1
        // only parses and exits without emitting STARTUP_MSG.
        rootcheck_init(test_config);
        exit(0);
    }

    /* Setup libmagic */
#ifdef USE_MAGIC
    init_magic(&magic_cookie);
#endif

    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

    /* Spawn the shutdown waiter before registering the termination signal handler
     * that wakes it through the pipe (issue #37334) */
    if (pipe(fim_shutdown_pipe) < 0 || pipe(fim_sync_exit_pipe) < 0) {
        merror_exit("Could not create the shutdown pipes: %s (%d)", strerror(errno), errno);
    }

    /* Keep the pipes out of child processes (e.g. prefilter_cmd). A failure here is not fatal
     * (it would only mean the pipe fds could leak into a child), so log and continue. */
    int cloexec_ret = 0;
    cloexec_ret |= fcntl(fim_shutdown_pipe[0], F_SETFD, FD_CLOEXEC);
    cloexec_ret |= fcntl(fim_shutdown_pipe[1], F_SETFD, FD_CLOEXEC);
    cloexec_ret |= fcntl(fim_sync_exit_pipe[0], F_SETFD, FD_CLOEXEC);
    cloexec_ret |= fcntl(fim_sync_exit_pipe[1], F_SETFD, FD_CLOEXEC);
    if (cloexec_ret < 0) {
        mwarn("Could not set FD_CLOEXEC on the shutdown pipes: %s (%d)", strerror(errno), errno);
    }

    w_create_thread(fim_shutdown_waiter, NULL);

    /* Start signal handling */
    StartSIG2(ARGV0, fim_shutdown);

    // Start com request thread
    w_create_thread(syscom_main, NULL);

    /* Create pid */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    startup_gate_wait_for_ready(ARGV0);

    // Rootcheck initialization is deferred until after the startup hash
    // gate releases. rootcheck_init() emits STARTUP_MSG ("wazuh-rootcheck:
    // INFO: Started"); running it before the gate would make rootcheck
    // appear as "Started" while every module is in fact still blocked
    // waiting for the manager's merged.mg hash to validate (issue 36239).
    if (rootcheck_init(0) == 0) {
        syscheck.rootcheck = 1;
    } else {
        syscheck.rootcheck = 0;
    }

    if (syscheck.rootcheck) {
        rootcheck_connect();
    }

    /* Connect to the queue */

    if ((syscheck.queue = StartMQPredicated(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS, fim_shutdown_process_on)) < 0) {
        merror_exit(QUEUE_FATAL, DEFAULTQUEUE);
    }

    if (!syscheck.disabled) {
        OSListNode *node_it;

        /* Start up message */
        minfo(STARTUP_MSG, (int)getpid());

        /* Print directories to be monitored */
        OSList_foreach(node_it, syscheck.directories) {
            dir_it = node_it->data;
            char optstr[ 1024 ];

            if (dir_it->symbolic_links == NULL) {
                mdebug1(FIM_MONITORING_DIRECTORY, dir_it->path,
                      syscheck_opts2str(optstr, sizeof(optstr), dir_it->options));
            } else {
                mdebug1(FIM_MONITORING_LDIRECTORY, dir_it->path, dir_it->symbolic_links,
                      syscheck_opts2str(optstr, sizeof(optstr), dir_it->options));
            }

            if (dir_it->tag != NULL)
                mdebug2(FIM_TAG_ADDED, dir_it->tag, dir_it->path);

            // Print diff file size limit
            if ((dir_it->options & CHECK_SEECHANGES) && syscheck.file_size_enabled) {
                mdebug2(FIM_DIFF_FILE_SIZE_LIMIT, dir_it->diff_size_limit, dir_it->path);
            }
        }

        if (!syscheck.file_size_enabled) {
            minfo(FIM_FILE_SIZE_LIMIT_DISABLED);
        }

        // Print maximum disk quota to be used by the queue/diff/local folder
        if (syscheck.disk_quota_enabled) {
            mdebug2(FIM_DISK_QUOTA_LIMIT, syscheck.disk_quota_limit);
        }
        else {
            minfo(FIM_DISK_QUOTA_LIMIT_DISABLED);
        }

        /* Print ignores. */
        if(syscheck.ignore)
            for (r = 0; syscheck.ignore[r] != NULL; r++)
                mdebug1(FIM_PRINT_IGNORE_ENTRY, "file", syscheck.ignore[r]);

        /* Print sregex ignores. */
        if(syscheck.ignore_regex)
            for (r = 0; syscheck.ignore_regex[r] != NULL; r++)
                mdebug1(FIM_PRINT_IGNORE_SREGEX, "file", syscheck.ignore_regex[r]->raw);

        /* Print files with no diff. */
        if (syscheck.nodiff){
            r = 0;
            while (syscheck.nodiff[r] != NULL) {
                mdebug1(FIM_NO_DIFF, syscheck.nodiff[r]);
                r++;
            }
        }

        /* Check directories set for real time */
        OSList_foreach(node_it, syscheck.directories) {
            dir_it = node_it->data;
            if (dir_it->options & REALTIME_ACTIVE) {
#if defined (INOTIFY_ENABLED) || defined (WIN32)
                minfo(FIM_REALTIME_MONITORING_DIRECTORY, dir_it->path);
                start_realtime = 1;
#else
                mwarn(FIM_WARN_REALTIME_DISABLED, dir_it->path);
                dir_it->options &= ~REALTIME_ACTIVE;
                dir_it->options |= SCHEDULED_ACTIVE;
#endif
            }
        }

        OSList_foreach(node_it, syscheck.wildcards) {
            dir_it = node_it->data;
            if (dir_it->options & REALTIME_ACTIVE) {
#if defined (INOTIFY_ENABLED) || defined (WIN32)
                start_realtime = 1;
                break;
#else
                mwarn(FIM_WARN_REALTIME_DISABLED, dir_it->path);
                dir_it->options &= ~REALTIME_ACTIVE;
                dir_it->options |= SCHEDULED_ACTIVE;
#endif
            }
        }
    }

    fim_initialize();

    if (!syscheck.disabled && start_realtime == 1) {
        realtime_start();
    }

    // Launch Whodata ebpf real-time thread
    if (!syscheck.disabled && syscheck.enable_whodata && syscheck.whodata_provider == EBPF_PROVIDER) {
#ifdef __linux__
#ifdef ENABLE_AUDIT
        check_ebpf_availability();
#else
        merror(FIM_ERROR_EBPF_NOT_SUPPORTED);
#endif
#endif
    }

    // Audit events thread
    if (!syscheck.disabled && syscheck.enable_whodata && syscheck.whodata_provider == AUDIT_PROVIDER) {
#ifdef ENABLE_AUDIT
        if (audit_init() < 0) {
            directory_t *dir_it;
            OSListNode *node_it;

            mwarn(FIM_WARN_AUDIT_THREAD_NOSTARTED);

            // Switch who-data to real-time mode

            OSList_foreach(node_it, syscheck.directories) {
                dir_it = node_it->data;
                if ((dir_it->options & WHODATA_ACTIVE)) {
                    dir_it->options &= ~WHODATA_ACTIVE;
                    dir_it->options |= REALTIME_ACTIVE;
                }
            }

            OSList_foreach(node_it, syscheck.wildcards) {
                dir_it = node_it->data;
                if ((dir_it->options & WHODATA_ACTIVE)) {
                    dir_it->options &= ~WHODATA_ACTIVE;
                    dir_it->options |= REALTIME_ACTIVE;
                }
            }

            w_mutex_lock(&syscheck.fim_realtime_mutex);
            if (syscheck.realtime == NULL) {
                if (realtime_start() < 0) {
                    OSList_foreach(node_it, syscheck.directories) {
                        dir_it = node_it->data;
                        if (dir_it->options & REALTIME_ACTIVE) {
                            dir_it->options &= ~REALTIME_ACTIVE;
                            dir_it->options |= SCHEDULED_ACTIVE;
                        }
                    }
                }
            }
            w_mutex_unlock(&syscheck.fim_realtime_mutex);

        }
#else
        merror(FIM_ERROR_WHODATA_AUDIT_SUPPORT);
#endif
    }

    /* Start the daemon */
    start_daemon();

    // We shouldn't reach this point unless syscheck is disabled
    while(1) {
        pause();
    }

    return (0);
}

#endif /* !WIN32 */

// LCOV_EXCL_STOP
