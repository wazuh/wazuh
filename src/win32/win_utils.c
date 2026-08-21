/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32
#include "shared.h"
#include "agentd.h"
#include "https_client_bridge.h"
#include "logcollector.h"
#include "execd.h"
#include "wmodules.h"
#include "sysInfo.h"
#include "sym_load.h"
#include "os_net.h"
#include "dll_load_notify.h"
#include "startup_gate_op.h"
#include "agent_sync_protocol_c_interface.h"
#include "os_win.h"

#ifdef WAZUH_UNIT_TESTING
#include "unit_tests/wrappers/windows/libc/kernel32_wrappers.h"
#include "unit_tests/wrappers/windows/processthreadsapi_wrappers.h"
#include "unit_tests/wrappers/windows/handleapi_wrappers.h"
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

HANDLE hMutex;
int win_debug_level;

/* Guards the "is a shutdown already in progress" decision against the actual
 * mutation it gates: wm_config() building the wmodules list and each module
 * thread being spawned (local_start(), below) versus stop_wmodules() setting
 * wm_shutdown_requested and walking that same list. Without this, a stop
 * landing mid-startup could run stop_wmodules() against an empty/half-built
 * list, or local_start() could keep spawning module threads after a shutdown
 * was already requested (issue 38428). Initialized once, from
 * wm_lifecycle_lock_init(), before OssecServiceStart() registers the ctrl
 * handler that can call stop_wmodules() -- see win_service.c. */
static CRITICAL_SECTION wm_lifecycle_lock;
static volatile LONG wm_lifecycle_lock_initialized = 0;

/* Idempotent: local_start() (and therefore wm_start_modules_unless_shutting_down(),
 * which takes wm_lifecycle_lock) is reachable both from OssecServiceStart() -- which
 * calls this first -- and directly from "wazuh-agent.exe start" (win_agent.c), which
 * never goes through OssecServiceStart() at all. Without the guard below, the "start"
 * CLI path would enter wm_start_modules_unless_shutting_down()'s EnterCriticalSection()
 * on a never-initialized CRITICAL_SECTION (issue 38428). Safe to call from both paths:
 * InterlockedCompareExchange ensures InitializeCriticalSection() only actually runs once. */
void wm_lifecycle_lock_init(void)
{
    if (InterlockedCompareExchange(&wm_lifecycle_lock_initialized, 1, 0) == 0) {
        InitializeCriticalSection(&wm_lifecycle_lock);
    }
}

/* Defined in win_service.c: pumps dwCheckPoint/dwWaitHint back to the SCM
 * while stop_wmodules() is still joining module threads, so a slow shutdown
 * doesn't look hung to the SCM (issue 38428, defect #7). */
extern void report_stop_progress(DWORD checkpoint, DWORD wait_hint_ms);

void *sysinfo_module = NULL;
sysinfo_networks_func sysinfo_network_ptr = NULL;
sysinfo_free_result_func sysinfo_free_result_ptr = NULL;

/** Prototypes **/
int Start_win32_Syscheck();

/* syscheck main thread */
#ifdef WIN32
DWORD WINAPI skthread(__attribute__((unused)) LPVOID arg)
#else
void *skthread()
#endif
{
    if (startup_gate_wait_for_ready("wazuh-syscheckd") == STARTUP_GATE_READY) {
        Start_win32_Syscheck();
    }
#ifdef WIN32
    return 0;
#else
    return (NULL);
#endif
}

/* logcollector main thread */
#ifdef WIN32
DWORD WINAPI logcollector_thread(__attribute__((unused)) LPVOID arg)
#else
void *logcollector_thread()
#endif
{
    if (startup_gate_wait_for_ready("wazuh-logcollector") == STARTUP_GATE_READY) {
        LogCollectorStart();
    }
#ifdef WIN32
    return 0;
#else
    return (NULL);
#endif
}

#ifdef WIN32
DWORD WINAPI win_module_thread(__attribute__((unused)) void *arg)
#else
void *win_module_thread(void *arg)
#endif
{
    win_module_start_ctx_t *ctx = (win_module_start_ctx_t *)arg;

    if (!ctx || !ctx->routine) {
        os_free(ctx);
#ifdef WIN32
        return 0;
#else
        return NULL;
#endif
    }

    startup_gate_wait_result_t gate_result = startup_gate_wait_for_ready(ctx->name[0] ? ctx->name : "wazuh-modulesd");

    // The gate also releases when shutdown is requested, so getting here does not mean
    // the agent is starting -- it may already be stopping. Starting a module then is
    // never useful: it opens databases and runs a scan that the join below is about to
    // interrupt anyway. Each module also refuses to start under a stop it already
    // received (wm_sys_stop() records it before returning, SCA sets g_shutting_down,
    // agent-info consults the injected predicate), but checking gate_result here keeps
    // the whole routine from running in the first place -- and unlike a bare
    // wm_shutdown_requested re-check, the same STARTUP_GATE_SHUTDOWN_REQUESTED result
    // also covers every other gated entry point (wazuh-syscheckd, wazuh-logcollector,
    // execd), not just this one (issue 38428).
    //
    // gate_result is a snapshot from the moment startup_gate_wait_for_ready() last
    // queried the gate -- a real IPC round trip, not an instantaneous check -- so a
    // stop can still land between that query returning "ready" and ctx->routine()
    // actually running below. Re-reading wm_shutdown_requested here is a cheap,
    // near-zero-latency second look that closes almost all of that window.
    const bool shutdown_before_start = (gate_result != STARTUP_GATE_READY) || wm_shutdown_requested;
#ifdef WIN32
    DWORD result = 0;
    if (!shutdown_before_start) {
        result = ctx->routine(ctx->data);
    }
    os_free(ctx);
    return result;
#else
    void *result = NULL;
    if (!shutdown_before_start) {
        result = ctx->routine(ctx->data);
    }
    os_free(ctx);
    return result;
#endif
}

void stop_wmodules()
{
    // Signal the agent-wide shutdown so dispatchers (e.g. modulesSync) skip work
    // that targets modules already being torn down. On POSIX the modulesd SIGTERM
    // handler sets this; on Windows shutdown flows through here instead.
    //
    // Set under wm_lifecycle_lock, atomically with the check local_start() makes
    // before building the wmodules list / spawning module threads (issue 38428):
    // whichever of the two gets there first, the other sees a consistent state --
    // either the list is untouched and local_start() is about to skip it entirely,
    // or local_start() already finished spawning everything and this walk below
    // sees the complete, stable list. The lock is released immediately after,
    // deliberately NOT held through the (potentially many-second) join loop below,
    // so it never makes a pending stop wait any longer than it has to.
    EnterCriticalSection(&wm_lifecycle_lock);
    wm_shutdown_requested = 1;
    LeaveCriticalSection(&wm_lifecycle_lock);

    // Two passes, mirroring the POSIX SIGTERM handler (wazuh_modules/src/main.c):
    // signal every module first, then join every module against one shared budget.
    //
    // The passes must not be interleaved. A module's stop() only tells that module
    // to wind down; some modules cannot finish winding down until a *sibling* has
    // been told too -- agent-info's run loop, for instance, can sit in
    // Syscollector::pause() until syscollector's stop() clears its scan/sync state.
    // Stopping and joining one module at a time therefore deadlocked agent-info
    // against syscollector for the length of its own timeout.
    wmodule * cur_module;

    // Shared across every module and started before the signal pass, so the budget
    // covers everything done here and not just the joins -- otherwise N modules could
    // each burn a fresh timeout, or a slow stop() callback could spend minutes off the
    // clock, and either way the total could outlast the SCM's own patience
    // (WaitToKillServiceTimeout). The stops are signalling only, but not instantaneous:
    // syscollector's and SCA's quiesce() both wait for an in-flight flush to finish,
    // with no timeout of their own. Each module runs its own teardown before its thread
    // returns, so the join is what guarantees that teardown completed.
    const DWORD MODULE_JOIN_BUDGET_MS = 20000;
    // Upper bound on how long any single wait slice blocks, so report_stop_progress()
    // gets called often enough that the SCM never sees a stale checkpoint for more
    // than this long, even while waiting on one slow module (issue 38428, defect #7).
    const DWORD CHECKPOINT_SLICE_MS = 2000;
    const ULONGLONG budget_start = GetTickCount64();
    DWORD checkpoint = 1;

    for (cur_module = wmodules; cur_module; cur_module = cur_module->next) {
        if (cur_module->context->stop) {
            cur_module->context->stop(cur_module->data);
        }
    }

    for (cur_module = wmodules; cur_module; cur_module = cur_module->next) {
        if (cur_module->win_thread) {
            // Never wait on our own thread. merror_exit() from a module thread routes
            // through WinSetError() -> OssecServiceCtrlHandler() -> here, so without this
            // the pass would wait on its own handle for the whole budget, log a timeout
            // that never happened and leave nothing left for the modules after it. The
            // POSIX handler skips the same way (wazuh_modules/src/main.c: thread ==
            // pthread_self()).
            if (GetThreadId(cur_module->win_thread) == GetCurrentThreadId()) {
                mdebug1("Module '%s' is the thread requesting the shutdown; not joining it.",
                        cur_module->context->name);
                CloseHandle(cur_module->win_thread);
                cur_module->win_thread = NULL;
                continue;
            }

            DWORD wait_result;

            while (1) {
                const ULONGLONG elapsed = GetTickCount64() - budget_start;
                const DWORD remaining = (elapsed < MODULE_JOIN_BUDGET_MS) ? (DWORD)(MODULE_JOIN_BUDGET_MS - elapsed) : 0;
                const DWORD slice = remaining < CHECKPOINT_SLICE_MS ? remaining : CHECKPOINT_SLICE_MS;

                // Always ask, even with the budget spent: a zero-length wait still
                // reports WAIT_OBJECT_0 for a thread that already finished. Asserting
                // a timeout without looking at the handle logged the error below for
                // modules that had shut down cleanly and were merely charged for a
                // budget an earlier module had spent.
                wait_result = WaitForSingleObject(cur_module->win_thread, slice);
                report_stop_progress(checkpoint++, CHECKPOINT_SLICE_MS * 2);

                if (wait_result != WAIT_TIMEOUT || remaining == 0) {
                    break;
                }
            }

            if (wait_result == WAIT_TIMEOUT) {
                merror("Module '%s' worker thread did not exit within the %lu ms shutdown budget; "
                       "shutdown will proceed while it may still be running.",
                       cur_module->context->name, MODULE_JOIN_BUDGET_MS);
            } else if (wait_result == WAIT_FAILED) {
                merror("Module '%s' worker thread wait failed (error %lu); closing handle and proceeding.",
                       cur_module->context->name, GetLastError());
            }

            CloseHandle(cur_module->win_thread);
            cur_module->win_thread = NULL;
        }
    }
}

/* Loads the wodle configuration and spawns a module thread per configured
 * wodle -- unless a shutdown is already in progress, in which case it skips
 * both entirely. Extracted out of local_start() so this specific check can be
 * unit-tested without dragging in local_start()'s enrollment/HTTPS-client/
 * syscheck/logcollector setup.
 *
 * Shares wm_lifecycle_lock with stop_wmodules(): holding it across
 * "check the flag, then build the list, then spawn every thread" makes that
 * whole sequence atomic with respect to a concurrent stop_wmodules() call, so
 * a stop landing mid-startup either sees the pre-startup empty list (and
 * local_start() then sees the flag and skips out) or the fully-spawned list
 * (issue 38428, defects #2/#3/#5). The lock is only held across
 * w_create_thread() itself (fast, non-blocking) -- never across a module's
 * own subsequent Run(), which happens on that module's own thread. */
STATIC void wm_start_modules_unless_shutting_down(void)
{
    DWORD threadID2;

    EnterCriticalSection(&wm_lifecycle_lock);

    if (wm_shutdown_requested) {
        LeaveCriticalSection(&wm_lifecycle_lock);
        mdebug1("Shutdown already in progress; skipping wodle startup.");
        return;
    }

    /* Read wodle configuration */
    if (wm_config() < 0) {
        LeaveCriticalSection(&wm_lifecycle_lock);
        mlerror_exit(LOGLEVEL_ERROR, CONFIG_ERROR, WAZUHCONF);
    }

    /* Start modules */
    if (!wm_check()) {
        wmodule * cur_module;

        for (cur_module = wmodules; cur_module; cur_module = cur_module->next) {
            win_module_start_ctx_t *start_ctx = NULL;
            const char *module_name = NULL;

            os_calloc(1, sizeof(win_module_start_ctx_t), start_ctx);
            start_ctx->routine = cur_module->context->start;
            start_ctx->data = cur_module->data;
            module_name = (cur_module->context && cur_module->context->name) ? cur_module->context->name : "module";
            snprintf(start_ctx->name, sizeof(start_ctx->name), "wazuh-modulesd/%s", module_name);

            cur_module->win_thread = w_create_thread(NULL,
                                                      0,
                                                      win_module_thread,
                                                      start_ctx,
                                                      0,
                                                      (LPDWORD)&threadID2);
        }
    }

    LeaveCriticalSection(&wm_lifecycle_lock);
}

/* Locally start (after service/win init) */
int local_start()
{
    // This must be always the first instruction
    enable_dll_verification();

    char *cfg = WAZUHCONF;
    WSADATA wsaData;
    DWORD  threadID;

    win_debug_level = getDefine_Int("windows", "debug", 0, 2);

    /* Get debug level */
    int debug_level = win_debug_level;
    while (debug_level != 0) {
        nowDebug();
        debug_level--;
    }

    if (sysinfo_module = so_get_module_handle("sysinfo"), sysinfo_module)
    {
        sysinfo_free_result_ptr = so_get_function_sym(sysinfo_module, "sysinfo_free_result");
        sysinfo_network_ptr = so_get_function_sym(sysinfo_module, "sysinfo_networks");
    }

    /* Initialize logging module*/
    w_logging_init();

    /* Start Winsock */
    if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
        merror_exit("WSAStartup() failed");
    }

    /* Start agent */
    os_calloc(1, sizeof(agent), agt);

    /* Configuration file not present */
    if (File_DateofChange(cfg) < 0) {
        merror_exit("Configuration file '%s' not found", cfg);
    }

    /* Read agent config */
    mdebug1("Reading agent configuration.");
    if (ClientConf(cfg) < 0) {
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    if (!(agt->server && agt->server[0].rip)) {
        merror(AG_INV_IP);
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    if (!Validate_Address(agt->server)){
        merror(AG_INV_MNGIP, agt->server[0].rip);
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    if (!Validate_IPv6_Link_Local_Interface(agt->server)){
        merror(AG_INV_INT);
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    /* Checked here, before any module thread is created, instead of failing much later
     * inside w_https_client_start(). */
    if (!w_agent_validate_ssl_ca(agt)) {
        mlerror_exit(LOGLEVEL_ERROR, CLIENT_ERROR);
    }

    if (agt->notify_time == 0) {
        agt->notify_time = NOTIFY_TIME;
    }
    if (agt->max_time_reconnect_try == 0 ) {
        agt->max_time_reconnect_try = RECONNECT_TIME;
    }
    if (agt->max_time_reconnect_try <= agt->notify_time) {
        agt->max_time_reconnect_try = (agt->notify_time * 3);
        minfo("Max time to reconnect can't be less than notify_time(%d), using notify_time*3 (%d)", agt->notify_time, agt->max_time_reconnect_try);
    }

    /* Same session ceiling modulesd applies on the other platforms, taken straight from
     * the configuration this process already read (local and centralized merged) rather
     * than re-reading the files. It has to be set here, while the configuration is being
     * finalized and before any thread exists: syscheck is started below and builds its
     * protocol instance on that thread, and an instance copies the limit once, when it
     * is constructed. Setting it any later is a race the module usually wins. */
    asp_set_session_max_bytes((uint64_t)agt->batch.size);

    if (agt->batch.size > 0) {
        mdebug1("Sync sessions bounded to %lld bytes by <agent><batch><size>.", agt->batch.size);
    }

    if(agt->enrollment.enabled) {
        // If autoenrollment is enabled, we will avoid exit if there is no valid key
        OS_PassEmptyKeyfile();
    } else {
        /* Check auth keys */
        if (!OS_CheckKeys()) {
            merror_exit(AG_NOKEYS_EXIT);
        }
    }

    /* Read private keys */
    minfo(ENC_READ);
    OS_ReadKeys(&keys, W_DUAL_KEY, 0);

    minfo("Using notify time: %d and max time to reconnect: %d", agt->notify_time, agt->max_time_reconnect_try);

    /* Start execd thread */
    if (!WinExecdStart()) {
        agt->execdq = -1;
    }

    /* Start mutex */
    mdebug1("Creating thread mutex.");
    hMutex = CreateMutex(NULL, FALSE, NULL);
    if (hMutex == NULL) {
        merror_exit("Error creating mutex.");
    }

    /* Set wait lock before starting threads */
    os_setwait();

    /* Enrollment (blocking until a valid key exists) and the startup gate
     * must both be ready before the HTTPS client is ever started: it reads
     * client.keys exactly once, at creation, with no retry on failure. */
    start_agent_prepare();

    /* HTTPS client: the agent's only transport (mirrors AgentdStart on POSIX;
     * the Windows startup path is separate). Started before any producer
     * thread: on Windows the modules call SendMSG in-process, so an event
     * emitted before the accumulator exists is dropped outright rather than
     * waiting in a queue as it would on POSIX. */
    w_https_client_start();
    atexit(w_https_client_stop);

    /* Start syscheck thread */
    w_create_thread(NULL,
                     0,
                     skthread,
                     NULL,
                     0,
                     (LPDWORD)&threadID);

    /* Read logcollector config file */
    mdebug1("Reading logcollector configuration.");

    /* Init message queue */
    w_msg_hash_queues_init();

    /* Read config file */
    if (LogCollectorConfig(cfg) < 0) {
        mlerror_exit(LOGLEVEL_ERROR, CONFIG_ERROR, cfg);
    }

    /* No file available to monitor -- continue */
    if (logff == NULL) {
        os_calloc(2, sizeof(logreader), logff);
        logff[0].file = NULL;
        logff[0].ffile = NULL;
        logff[0].logformat = NULL;
        logff[0].fp = NULL;
        logff[1].file = NULL;
        logff[1].logformat = NULL;

        minfo(NO_FILE);
    }

    /* No sockets defined */
    if (logsk == NULL) {
        os_calloc(2, sizeof(socket_forwarder), logsk);
        logsk[0].name = NULL;
        logsk[0].location = NULL;
        logsk[0].mode = 0;
        logsk[0].prefix = NULL;
        logsk[1].name = NULL;
        logsk[1].location = NULL;
        logsk[1].mode = 0;
        logsk[1].prefix = NULL;
    }

    /* Start logcollector thread */
    w_create_thread(NULL,
                     0,
                     logcollector_thread,
                     NULL,
                     0,
                     (LPDWORD)&threadID);

    /* Initialize children pool */
    wm_children_pool_init();

    /* Read wodle configuration and spawn a thread per configured module --
     * unless a shutdown has already been requested (issue 38428). */
    wm_start_modules_unless_shutting_down();

    /* Initialize random numbers */
    srandom(time(0));
    os_random();

    /* Launch rotation thread */
    int rotate_log = getDefine_Int("monitord", "rotate_log", 0, 1);
    if (rotate_log) {
        w_create_thread(NULL,
                        0,
                        w_rotate_log_thread,
                        NULL,
                        0,
                        (LPDWORD)&threadID);
    }

    /* Configure and start statistics */
    w_agentd_state_init();
    w_create_thread(NULL,
                     0,
                     state_main,
                     NULL,
                     0,
                     (LPDWORD)&threadID);

    start_agent(1);

    /* Delete agent state file at exit */
    atexit(DeleteState);

    /* Main thread from here on. With no manager socket left to read, all that
     * remains of the old receiver loop is expiring the active-response
     * timeouts, which only this thread runs. */
    while (1) {
        if (agt->execdq >= 0) {
            ExecdTimeoutRun();
        }

        sleep(1);
    }

    if (sysinfo_module){
        so_free_library(sysinfo_module);
    }

    WSACleanup();
    return (0);
}

/* SendMSGAction for Windows */
int SendMSGAction(__attribute__((unused)) int queue, const char *message, const char *locmsg, char loc)
{
    char loc_buff[OS_SIZE_8192 + 1] = {0};
    char tmpstr[OS_MAXSTR + 2];
    DWORD dwWaitResult;
    int retval = -1;
    tmpstr[OS_MAXSTR + 1] = '\0';

    /* Using a mutex to synchronize the writes */
    while (1) {
        dwWaitResult = WaitForSingleObject(hMutex, 1000000L);

        if (dwWaitResult != WAIT_OBJECT_0) {
            switch (dwWaitResult) {
                case WAIT_TIMEOUT:
                    mdebug2("Sending mutex timeout.");
                    sleep(5);
                    continue;
                case WAIT_ABANDONED:
                    merror("Error waiting mutex (abandoned).");
                    return retval;
                default:
                    merror("Error waiting mutex.");
                    return retval;
            }
        } else {
            /* Lock acquired */
            break;
        }
    }   /* end - while for mutex... */

    if (OS_INVALID == wstr_escape(loc_buff, sizeof(loc_buff), (char *) locmsg, '|', ':')) {
        merror(FORMAT_ERROR);
        return retval;
    }

    snprintf(tmpstr, OS_MAXSTR, "%c:%s:%s", loc, loc_buff, message);

    /* Every event goes to the HTTPS /stateless accumulator; sync sessions are
     * handed to the module in-process (bridge_submit_sync_session).
     * (Windows has no DGRAM queue; SendMSGAction is the in-process EventForward.) */
    w_agentd_state_update(INCREMENT_MSG_COUNT, NULL);
    w_https_client_submit_event(tmpstr, strlen(tmpstr));
    retval = 0;

    if (!ReleaseMutex(hMutex)) {
        merror("Error releasing mutex.");
    }
    return retval;
}

/* SendMSG for Windows */
int SendMSG(__attribute__((unused)) int queue, const char *message, const char *locmsg, char loc) {
    os_wait();
    return SendMSGAction(queue, message, locmsg, loc);
}

int SendBinaryMSGAction(__attribute__((unused)) int queue, const void *message, size_t message_len, const char *locmsg, char loc)
{
    char loc_buff[OS_SIZE_8192 + 1] = {0};
    char tmpstr[OS_MAXSTR + 1] = {0};
    DWORD dwWaitResult;
    int retval = -1;

    // Using a mutex to synchronize the writes
    while (1) {
        dwWaitResult = WaitForSingleObject(hMutex, 1000000L);

        if (dwWaitResult != WAIT_OBJECT_0) {
            switch (dwWaitResult) {
                case WAIT_TIMEOUT:
                    mdebug2("Sending mutex timeout.");
                    sleep(5);
                    continue;
                case WAIT_ABANDONED:
                    merror("Error waiting mutex (abandoned).");
                    return retval;
                default:
                    merror("Error waiting mutex.");
                    return retval;
            }
        } else {
            // Lock acquired, proceed
            break;
        }
    }

    // Escape the location string.
    if (OS_INVALID == wstr_escape(loc_buff, sizeof(loc_buff), (char *) locmsg, '|', ':')) {
        merror(FORMAT_ERROR);
        ReleaseMutex(hMutex); // Release mutex on error
        return retval;
    }

    // Manually construct the binary message
    char *p = tmpstr;
    size_t loc_buff_len = strlen(loc_buff);
    size_t header_len = 3 + loc_buff_len; // Format "loc:loc_buff:"
    size_t total_len = header_len + message_len;

    // Safety check: Ensure the message fits in the fixed-size buffer.
    if (total_len > OS_MAXSTR) {
        mwarn("Binary message is too large to be sent (%zu bytes required, %d max). Payload of %zu bytes for module '%s' was dropped.",
                total_len, OS_MAXSTR, message_len, locmsg);
        ReleaseMutex(hMutex); // Release mutex on error
        return retval;
    }

    // Build the header
    *p++ = loc;
    *p++ = ':';
    memcpy(p, loc_buff, loc_buff_len);
    p += loc_buff_len;
    *p++ = ':';

    // Append the binary payload
    memcpy(p, message, message_len);

    // Dispatch the message with its *actual size* (binary payload: no strlen).
    w_agentd_state_update(INCREMENT_MSG_COUNT, NULL);
    w_https_client_submit_event(tmpstr, total_len);
    retval = 0;

    // Release the mutex
    if (!ReleaseMutex(hMutex)) {
        merror("Error releasing mutex.");
    }

    return retval;
}

/* SendBinaryMSG for Windows */
int SendBinaryMSG(__attribute__((unused)) int queue, const void *message, size_t message_len, const char *locmsg, char loc) {
    os_wait();
    return SendBinaryMSGAction(queue, message, message_len, locmsg, loc);
}

/* SendMSGPredicated for Windows */
int SendMSGPredicated(__attribute__((unused)) int queue, const char *message, const char *locmsg, char loc, bool (*fn_ptr)()) {
    os_wait_predicate(fn_ptr);
    return SendMSGAction(queue, message, locmsg, loc);
}

/* SendBinaryMSGPredicated for Windows */
int SendBinaryMSGPredicated(__attribute__((unused)) int queue, const void *message, size_t message_len, const char *locmsg, char loc, bool (*fn_ptr)()) {
    os_wait_predicate(fn_ptr);
    return SendBinaryMSGAction(queue, message, message_len, locmsg, loc);
}

/* StartMQ for Windows */
int StartMQWithSpecificOwnerAndPerms(__attribute__((unused)) const char *path
                                     ,__attribute__((unused)) short int type
                                     ,__attribute__((unused)) short int n_tries
                                     ,__attribute__((unused)) uid_t uid
                                     ,__attribute__((unused)) gid_t gid
                                     ,__attribute__((unused)) mode_t perm)
{
    return (0);
}

/* StartMQ for Windows */
int StartMQ(__attribute__((unused)) const char *path, __attribute__((unused)) short int type, __attribute__((unused)) short int n_tries)
{
    return (0);
}

/* StartMQPredicated for Windows */
int StartMQPredicated(__attribute__((unused)) const char *path, __attribute__((unused)) short int type, __attribute__((unused)) short int n_tries, __attribute__((unused)) bool (*fn_ptr)()) {
    return (0);
}

/* MQReconnectPredicated for Windows */
int MQReconnectPredicated(__attribute__((unused)) const char *path, __attribute__((unused)) bool (fn_ptr)())
{
    return (0);
}

char *get_agent_ip_legacy_win32()
{
    char agent_ip[IPSIZE + 1] = { '\0' };
    cJSON *object;

    if (sysinfo_network_ptr && sysinfo_free_result_ptr) {
        const int error_code = sysinfo_network_ptr(&object);
        if (error_code == 0) {
            if (object) {
                const cJSON *iface = cJSON_GetObjectItem(object, "iface");
                if (iface) {
                    const int size_ids = cJSON_GetArraySize(iface);
                    for (int i = 0; i < size_ids; ++i){
                        const cJSON *element = cJSON_GetArrayItem(iface, i);
                        if(!element) {
                            continue;
                        }
                        cJSON *gateway = cJSON_GetObjectItem(element, "gateway");
                        if(gateway && cJSON_GetStringValue(gateway) && 0 != strcmp(gateway->valuestring, " ")) {

                            const char * primaryIpType = NULL;
                            const char * secondaryIpType = NULL;

                            if (strchr(gateway->valuestring, ':') != NULL) {
                                // Assume gateway is IPv6. IPv6 IP will be prioritary
                                primaryIpType = "IPv6";
                                secondaryIpType = "IPv4";
                            } else {
                                // Assume gateway is IPv4. IPv4 IP will be prioritary
                                primaryIpType = "IPv4";
                                secondaryIpType = "IPv6";
                            }

                            const cJSON * ip = cJSON_GetObjectItem(element, primaryIpType);
                            if (!ip) {
                                ip = cJSON_GetObjectItem(element, secondaryIpType);
                                if (!ip) {
                                    continue;
                                }
                            }
                            const int size_proto_interfaces = cJSON_GetArraySize(ip);
                            for (int j = 0; j < size_proto_interfaces; ++j) {
                                const cJSON *element_ip = cJSON_GetArrayItem(ip, j);
                                if(!element_ip) {
                                    continue;
                                }
                                cJSON *address = cJSON_GetObjectItem(element_ip, "address");
                                if (address && cJSON_GetStringValue(address))
                                {
                                    strncpy(agent_ip, address->valuestring, IPSIZE);
                                    break;
                                }
                            }
                            if (*agent_ip != '\0') {
                                break;
                            }
                        }
                    }
                }
                sysinfo_free_result_ptr(&object);
            }
        }
        else {
            merror("Unable to get system network information. Error code: %d.", error_code);
        }
    }

    if (strchr(agent_ip, ':') != NULL) {
        OS_ExpandIPv6(agent_ip, IPSIZE);
    }

    return strdup(agent_ip);
}

#endif
