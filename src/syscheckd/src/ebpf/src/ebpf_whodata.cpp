/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * #37396 cutover: this file used to load libbpf and the FIM BPF object
 * itself (init_libbpf/init_bpfobj/select_programs/ring buffer management —
 * ~500 lines). All of that moved to the standalone eBPF Module engine
 * (src/shared_modules/ebpf_provider/), which is consumer-agnostic per
 * #37396's constraint: FIM only calls rt_open()/rt_poll()/rt_close() (see
 * rt_engine_api in ebpf_whodata.hpp) and interprets the versioned
 * rt_file_event contract — no eBPF-specific code path beyond that.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>
#include <string>
#include <memory>
#include <thread>
#include <bounded_queue.hpp>

#include "ebpf_whodata.hpp"
#include "bpf_helpers.h"
#include "container_baseline_fim_bridge.h"
#include "container_live_fim.h"

// Define global variables (declared extern in ebpf_whodata.hpp)
volatile bool event_received = false;
volatile bool ebpf_hc_created = false;

rt_engine_api_t rt_engine_api;

// Engine handle shared between ebpf_whodata_healthcheck() and ebpf_whodata():
// opened once (during healthcheck) and reused for the real polling loop, so
// the BPF programs are loaded/attached exactly once per agent run, not once
// per call — mirrors the previous design's persistent global_obj/bpf_helpers.
static rt_handle_t g_engine_handle = nullptr;

#define EBPF_HC_FILE "tmp/ebpf_hc"
#define BPF_OBJ_INSTALL_PATH "lib/rt_file.bpf.o"
#define WAIT_MS 500
#define HC_ACTION_TIMEOUT_S 10

time_t (*w_time)(time_t*) = time;

int ebpf_kernel_queue_full_reported = 0;
fim::BoundedQueue<std::unique_ptr<dynamic_file_event>> kernelEventQueue;

// Container-candidate events (#37533): populated by handle_event() when a raw
// event's path matches a configured `tags="container"` directory, drained by
// its own worker thread (ebpf_pop_container_events) so the — potentially
// IPC-blocking — cgroup->container resolution never runs on the thread that
// drains the kernel ring buffer.
int ebpf_container_queue_full_reported = 0;
fim::BoundedQueue<std::unique_ptr<container_file_event>> containerEventQueue;

/*
 * Cheap, local (no IPC) check of whether `path` falls under one of the
 * currently configured `<directories tags="container">` prefixes. Reuses
 * fim_collect_container_monitored_paths() — the same OSList walk the #37532
 * baseline already does at startup — so this always reflects the live
 * configuration (including after a reload) without needing its own cache.
 */
static bool matches_container_prefix(const char* path)
{
    if (!path)
    {
        return false;
    }

    cb_monitored_path_t* paths = nullptr;
    size_t count = 0;

    if (fim_collect_container_monitored_paths(&paths, &count) != 0 || !paths)
    {
        return false;
    }

    bool matched = false;
    const std::string path_str(path);

    for (size_t i = 0; i < count; ++i)
    {
        if (paths[i].internal_path && path_str.compare(0, strlen(paths[i].internal_path), paths[i].internal_path) == 0)
        {
            matched = true;
            break;
        }
    }

    fim_free_container_monitored_paths(paths);
    return matched;
}

static char* uint_to_str(unsigned int num)
{
    std::string s = std::to_string(num);
    return strdup(s.c_str());
}

static char* ulong_to_str(unsigned long long num)
{
    std::string s = std::to_string(num);
    return strdup(s.c_str());
}

/* Sink for normal whodata events — matches rt_sink_fn's signature exactly,
 * so it's passed straight to rt_poll() with no adapter needed. */
void handle_event(const struct rt_file_event* ev, void* /*user*/)
{
    auto logFn = fimebpf::instance().m_loggingFunction;

    if (!logFn || !ev)
    {
        return;
    }

    // Container files (#37533): classified by a cheap, local path-prefix
    // match against configured `tags="container"` directories — NOT by
    // fim_configuration_directory(), which matches against host directory
    // config and would be meaningless against a kernel-reported path that
    // may be in a container's own mount-namespace view. Routed to a
    // dedicated queue/thread so the (possibly IPC-blocking) container
    // resolution never runs here. Host events fall through unchanged below.
    if (matches_container_prefix(ev->filename))
    {
        auto cevent = std::make_unique<container_file_event>(container_file_event
        {
            .filename  = std::string(ev->filename),
            .cgroup_id = ev->cgroup_id,
            .mnt_ns    = ev->mnt_ns,
            .pid       = ev->pid,
            .inode     = ev->inode,
            .dev       = ev->dev
        });

        if (!containerEventQueue.push(std::move(cevent)))
        {
            if (!ebpf_container_queue_full_reported)
            {
                logFn(LOG_WARNING, FIM_FULL_EBPF_CONTAINER_QUEUE);
                ebpf_container_queue_full_reported = 1;
            }
        }

        return;
    }

    auto confFn = fimebpf::instance().m_fim_configuration_directory;

    if (!confFn)
    {
        return;
    }

    directory_t* config = confFn(ev->filename, false);

    if (config && (config->options & WHODATA_ACTIVE))
    {
        auto event = std::make_unique<dynamic_file_event>(dynamic_file_event
        {
            .filename    = std::string(ev->filename),
            .cwd         = std::string(ev->cwd),
            .parent_cwd  = std::string(ev->parent_cwd),
            .comm        = std::string(ev->comm),
            .parent_comm = std::string(ev->parent_comm),
            .pid         = ev->pid,
            .ppid        = ev->ppid,
            .uid         = ev->uid,
            .gid         = ev->gid,
            .inode       = ev->inode,
            .dev         = ev->dev
        });

        if (!kernelEventQueue.push(std::move(event)))
        {
            if (!ebpf_kernel_queue_full_reported)
            {
                logFn(LOG_WARNING, FIM_FULL_EBPF_KERNEL_QUEUE);
                ebpf_kernel_queue_full_reported = 1;
            }
        }
    }
}

/* Sink for healthcheck events — same rt_sink_fn signature. */
void healthcheck_event(const struct rt_file_event* ev, void* /*user*/)
{
    if (ev && strstr(ev->filename, EBPF_HC_FILE))
    {
        event_received = true;
    }
}

using healthcheck_operation_t = bool (*)(const char*, char*, size_t);

static void log_healthcheck_message(modules_log_level_t level,
                                    const char* format,
                                    const char* action,
                                    const char* detail = nullptr) {
    auto logFn = fimebpf::instance().m_loggingFunction;
    char log_message[4200] = {0};

    if (!logFn) {
        return;
    }

    if (detail) {
        snprintf(log_message,
                 sizeof(log_message),
                 format,
                 action,
                 detail);
    } else {
        snprintf(log_message,
                 sizeof(log_message),
                 format,
                 action);
    }

    logFn(level, log_message);
}

static bool wait_for_healthcheck_event(rt_handle_t handle, char* detail, size_t detail_size) {
    auto logFn = fimebpf::instance().m_loggingFunction;

    if (!logFn) {
        return false;
    }

    event_received = false;
    time_t start_time = w_time(nullptr);

    while (!event_received) {
        int ret = rt_engine_api.poll(handle, healthcheck_event, nullptr, WAIT_MS);
        if (ret < 0) {
            logFn(LOG_ERROR, FIM_ERROR_EBPF_RINGBUFF_CONSUME);
            snprintf(detail, detail_size, "%s", FIM_EBPF_HEALTHCHECK_EVENT_CONSUME_DETAIL);
            return false;
        }

        if (w_time(nullptr) - start_time >= HC_ACTION_TIMEOUT_S) {
            snprintf(detail, detail_size, "%s", FIM_EBPF_HEALTHCHECK_EVENT_TIMEOUT_DETAIL);
            return false;
        }
    }

    return true;
}

static bool create_healthcheck_file(const char* file_path, char* detail, size_t detail_size) {
    char error_message[4200] = {0};
    auto logFn = fimebpf::instance().m_loggingFunction;

    if (!logFn) {
        return false;
    }

    std::ofstream file(file_path);
    if (!file.is_open()) {
        snprintf(error_message, sizeof(error_message), FIM_ERROR_EBPF_HEALTHCHECK_FILE, file_path);
        logFn(LOG_ERROR, error_message);
        snprintf(detail, detail_size, "%s", FIM_EBPF_HEALTHCHECK_CREATE_DETAIL);
        return false;
    }

    file << "Testing eBPF healthcheck\n";
    file.close();

    return true;
}

static bool modify_healthcheck_file_content(const char* file_path, char* detail, size_t detail_size) {
    std::ofstream file(file_path, std::ios::app);

    if (!file.is_open()) {
        snprintf(detail, detail_size, "%s", FIM_EBPF_HEALTHCHECK_CONTENT_DETAIL);
        return false;
    }

    file << "Updating eBPF healthcheck\n";
    file.close();

    return true;
}

static bool modify_healthcheck_file_metadata(const char* file_path, char* detail, size_t detail_size) {
    struct stat file_stat = {};

    int fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        snprintf(detail,
                 detail_size,
                 FIM_EBPF_HEALTHCHECK_STAT_DETAIL,
                 file_path,
                 strerror(errno));
        return false;
    }

    if (fstat(fd, &file_stat) != 0) {
        int saved_errno = errno;
        close(fd);
        snprintf(detail,
                 detail_size,
                 FIM_EBPF_HEALTHCHECK_STAT_DETAIL,
                 file_path,
                 strerror(saved_errno));
        return false;
    }

    mode_t current_mode = file_stat.st_mode & 0777;
    mode_t new_mode = (current_mode ^ S_IXUSR) & 0777;

    if (fchmod(fd, new_mode) != 0) {
        int saved_errno = errno;
        close(fd);
        snprintf(detail,
                 detail_size,
                 FIM_EBPF_HEALTHCHECK_CHMOD_DETAIL,
                 file_path,
                 strerror(saved_errno));
        return false;
    }

    close(fd);
    return true;
}

static bool delete_healthcheck_file(const char* file_path, char* detail, size_t detail_size) {
    char error_message[4200] = {0};
    auto logFn = fimebpf::instance().m_loggingFunction;

    if (!logFn) {
        return false;
    }

    if (std::remove(file_path) != 0) {
        snprintf(error_message, sizeof(error_message), FIM_ERROR_EBPF_HEALTHCHECK_FILE_DEL, file_path);
        logFn(LOG_ERROR, error_message);
        snprintf(detail, detail_size, "%s", FIM_EBPF_HEALTHCHECK_DELETE_DETAIL);
        return false;
    }

    return true;
}

static bool run_healthcheck_action(rt_handle_t handle,
                                   const char* action,
                                   const char* file_path,
                                   healthcheck_operation_t operation,
                                   bool enabled) {
    char detail[4200] = {0};

    if (!enabled) {
        log_healthcheck_message(LOG_ERROR,
                                FIM_ERROR_EBPF_HEALTHCHECK_ACTION_SKIPPED,
                                action,
                                FIM_EBPF_HEALTHCHECK_SKIP_DETAIL);
        return false;
    }

    if (!operation(file_path, detail, sizeof(detail)) || !wait_for_healthcheck_event(handle, detail, sizeof(detail))) {
        log_healthcheck_message(LOG_ERROR,
                                FIM_ERROR_EBPF_HEALTHCHECK_ACTION_FAILED,
                                action,
                                detail);
        return false;
    }

    log_healthcheck_message(LOG_INFO, FIM_EBPF_HEALTHCHECK_ACTION_SUCCESS, action);
    return true;
}

/* Worker thread to pop events from kernelEventQueue (host files, unchanged) */
void ebpf_pop_events(fim::BoundedQueue<std::unique_ptr<dynamic_file_event>>& local_kernelEventQueue)
{
    auto logFn = fimebpf::instance().m_loggingFunction;

    if (!logFn)
    {
        return;
    }

    while (!fimebpf::instance().m_fim_shutdown_process_on())
    {
        std::unique_ptr<dynamic_file_event> event;

        if (!local_kernelEventQueue.pop(event, WAIT_MS))
        {
            if (fimebpf::instance().m_fim_shutdown_process_on())
            {
                return;
            }
        }

        if (event)
        {
            whodata_evt* w_evt = (whodata_evt*)calloc(1, sizeof(whodata_evt));

            if (!w_evt)
            {
                continue;
            }

            w_evt->path         = strdup(event->filename.c_str());
            w_evt->process_name = strdup(event->comm.c_str());
            w_evt->user_id      = uint_to_str(event->uid);
            w_evt->user_name    = fimebpf::instance().m_get_user(event->uid);
            w_evt->group_id     = uint_to_str(event->gid);
            w_evt->group_name   = fimebpf::instance().m_get_group(event->gid);
            w_evt->inode        = ulong_to_str(event->inode);
            w_evt->dev          = ulong_to_str(event->dev);
            w_evt->process_id   = event->pid;
            w_evt->ppid         = event->ppid;
            w_evt->cwd          = strdup(event->cwd.c_str());
            w_evt->parent_cwd   = strdup(event->parent_cwd.c_str());
            w_evt->parent_name  = strdup(event->parent_comm.c_str());

            fimebpf::instance().m_fim_whodata_event(w_evt);
            fimebpf::instance().m_free_whodata_event(w_evt);
        }
    }
}

/* Worker thread to pop events from containerEventQueue (#37533). Calls
 * fim_handle_container_whodata_event() directly instead of going through the
 * host whodata_evt/fim_whodata_event() pipeline: container files need
 * cgroup->container resolution and /proc/<pid>/root path translation first,
 * which that pipeline has no seam for. */
void ebpf_pop_container_events(fim::BoundedQueue<std::unique_ptr<container_file_event>>& local_containerEventQueue)
{
    auto logFn = fimebpf::instance().m_loggingFunction;

    if (!logFn)
    {
        return;
    }

    while (!fimebpf::instance().m_fim_shutdown_process_on())
    {
        std::unique_ptr<container_file_event> event;

        if (!local_containerEventQueue.pop(event, WAIT_MS))
        {
            if (fimebpf::instance().m_fim_shutdown_process_on())
            {
                return;
            }
        }

        if (event)
        {
            fim_handle_container_whodata_event(event->cgroup_id,
                                               event->mnt_ns,
                                               event->pid,
                                               event->filename.c_str(),
                                               event->inode,
                                               event->dev);
        }
    }
}

#ifdef __cplusplus
extern "C" {
#endif

void fimebpf_initialize(directory_t* (*fim_conf)(const char*, bool),
                        char* (*getUser)(int),
                        char* (*getGroup)(int),
                        void (*fimWhodataEvent)(whodata_evt*),
                        void (*freeWhodataEvent)(whodata_evt*),
                        void (*loggingFn)(modules_log_level_t, const char*),
                        char* (*abspathFn)(const char*, char*, size_t),
                        bool (*fimShutdownProcessOn)(),
                        unsigned int syscheckQueueSize)
{
    fimebpf::instance().initialize(fim_conf, getUser, getGroup, fimWhodataEvent, freeWhodataEvent,
                                   loggingFn, abspathFn, fimShutdownProcessOn, syscheckQueueSize);
}

int ebpf_whodata_healthcheck()
{
    auto logFn = fimebpf::instance().m_loggingFunction;
    auto abspathFn = fimebpf::instance().m_abspath;
    char ebpf_hc_abs_path[PATH_MAX] = {0};
    bool healthcheck_failed = false;

    if (!logFn || !abspathFn)
    {
        return 1;
    }

    kernelEventQueue.setMaxSize(fimebpf::instance().m_queue_size);

    if (!g_engine_handle)
    {
        // Request every FILE_* class: the healthcheck exercises create,
        // content-modify, attribute-modify, and delete in turn.
        char bpf_obj_abs_path[PATH_MAX] = {0};
        abspathFn(BPF_OBJ_INSTALL_PATH, bpf_obj_abs_path, sizeof(bpf_obj_abs_path));

        struct rt_filter filter = {RT_FILE_ALL_BITS, bpf_obj_abs_path};
        g_engine_handle = rt_engine_api.open(&filter);
    }

    if (!g_engine_handle)
    {
        logFn(LOG_ERROR, FIM_ERROR_EBPF_OBJ_LOAD);
        return 1;
    }

    event_received = false;
    abspathFn(EBPF_HC_FILE, ebpf_hc_abs_path, sizeof(ebpf_hc_abs_path));

    if (std::remove(ebpf_hc_abs_path) == 0) {
        logFn(LOG_DEBUG_VERBOSE, FIM_EBPF_HEALTHCHECK_CLEANUP);
    }

    bool file_created = run_healthcheck_action(g_engine_handle,
                                                  "create file",
                                                  ebpf_hc_abs_path,
                                                  create_healthcheck_file,
                                                  true);

    healthcheck_failed |= !file_created;

    healthcheck_failed |= !run_healthcheck_action(g_engine_handle,
                                                  "modify content",
                                                  ebpf_hc_abs_path,
                                                  modify_healthcheck_file_content,
                                                  file_created);

    healthcheck_failed |= !run_healthcheck_action(g_engine_handle,
                                                  "modify metadata",
                                                  ebpf_hc_abs_path,
                                                  modify_healthcheck_file_metadata,
                                                  file_created);

    healthcheck_failed |= !run_healthcheck_action(g_engine_handle,
                                                  "delete file",
                                                  ebpf_hc_abs_path,
                                                  delete_healthcheck_file,
                                                  file_created);

    // Note: the engine handle is deliberately NOT closed here — it's reused
    // by ebpf_whodata()'s main polling loop (see g_engine_handle's comment).

    if (std::remove(ebpf_hc_abs_path) != 0 && errno != ENOENT) {
        char error_message[4200] = {0};
        snprintf(error_message, sizeof(error_message), FIM_ERROR_EBPF_HEALTHCHECK_FILE_DEL, ebpf_hc_abs_path);
        logFn(LOG_ERROR, error_message);
    }

    if (healthcheck_failed) {
        return 1;
    }

    logFn(LOG_INFO, FIM_EBPF_HEALTHCHECK_SUCCESS);
    return 0;
}

int ebpf_whodata()
{
    auto logFn = fimebpf::instance().m_loggingFunction;
    int ret;

    // Assumes ebpf_whodata_healthcheck() already ran and populated
    // g_engine_handle — same assumption the pre-cutover code made about
    // bpf_helpers/global_obj (run_check.c always calls the healthcheck
    // before spawning this as its own thread).
    if (!logFn || !g_engine_handle)
    {
        return 1;
    }

    std::thread ebpf_pop_thread([&]()
    {
        ebpf_pop_events(kernelEventQueue);
    });
    ebpf_pop_thread.detach();

    // Only spin up the container worker thread (and pay its per-event prefix
    // check in handle_event()) when at least one `tags="container"` directory
    // is actually configured — mirrors fim_run_container_baseline()'s own
    // no-op-when-unconfigured behavior instead of always paying the cost.
    // Known limitation: this check runs once at thread startup, like the
    // baseline; container directories added via a config reload after
    // ebpf_whodata() is already running won't get a drain thread until the
    // next agent restart (matches_container_prefix() would still route their
    // events into containerEventQueue, which would then just fill up and log
    // "queue full" rather than being processed).
    {
        cb_monitored_path_t* paths = nullptr;
        size_t path_count = 0;
        if (fim_collect_container_monitored_paths(&paths, &path_count) == 0 && paths && path_count > 0U)
        {
            fim_free_container_monitored_paths(paths);
            containerEventQueue.setMaxSize(fimebpf::instance().m_queue_size);
            std::thread ebpf_pop_container_thread([&]()
            {
                ebpf_pop_container_events(containerEventQueue);
            });
            ebpf_pop_container_thread.detach();
        }
        else if (paths)
        {
            fim_free_container_monitored_paths(paths);
        }
    }

    while (!fimebpf::instance().m_fim_shutdown_process_on())
    {
        ret = rt_engine_api.poll(g_engine_handle, handle_event, nullptr, WAIT_MS);

        if (ret < 0)
        {
            logFn(LOG_ERROR, FIM_ERROR_EBPF_RINGBUFF_CONSUME);
            break;
        }
    }

    rt_engine_api.close(g_engine_handle);
    g_engine_handle = nullptr;

    return 0;
}

#ifdef __cplusplus
}
#endif
