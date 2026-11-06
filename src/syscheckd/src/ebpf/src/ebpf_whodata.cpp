/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <atomic>
#include <bounded_queue.hpp>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <pwd.h>

#include <mutex>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>

#include "ebpf_whodata.hpp"

#define EBPF_HC_FILE         "tmp/ebpf_hc"
#define BPF_OBJ_INSTALL_PATH "lib/rt_file.bpf.o"
#define WAIT_MS              500
#define HC_ACTION_TIMEOUT_S  10
// Healthcheck owns polling until it publishes a ready handle under this mutex.
// The production loop holds it through join-before-close, preventing a second owner.
static std::mutex engine_mutex;
static rt_handle_t g_engine_handle = nullptr;
static bool engine_ready = false;
static std::atomic<bool> worker_stop {false};
volatile bool event_received = false;
volatile bool ebpf_hc_created = false;
rt_engine_api_t rt_engine_api;
time_t (*w_time)(time_t*) = time;

int ebpf_kernel_queue_full_reported = 0;
fim::BoundedQueue<std::unique_ptr<dynamic_file_event>> kernelEventQueue;

static void engine_log(int level, const char* message, void*)
{
    const modules_log_level_t levels[] = {LOG_ERROR, LOG_WARNING, LOG_INFO, LOG_DEBUG_VERBOSE};

    if (auto log = fimebpf::instance().m_loggingFunction)
    {
        log(level >= RT_LOG_ERROR && level <= RT_LOG_DEBUG ? levels[level] : LOG_DEBUG_VERBOSE, message);
    }
}

template<typename T>
static char* num_to_str(T num)
{
    return strdup(std::to_string(num).c_str());
}

constexpr auto ID_CACHE_TTL = std::chrono::seconds(1);
constexpr size_t ID_CACHE_MAX_ENTRIES = 1024;

template<typename T>
using id_cache_t = std::unordered_map<uint32_t, std::pair<T, std::chrono::steady_clock::time_point>>;

template<typename T, typename Resolver>
static T resolve_cached(id_cache_t<T>& cache, uint32_t id, Resolver resolve)
{
    static std::mutex mutex;
    const std::lock_guard<std::mutex> lock(mutex);

    if (cache.size() > ID_CACHE_MAX_ENTRIES)
    {
        cache.clear();
    }

    const auto now = std::chrono::steady_clock::now();
    auto& [value, resolved_at] = cache[id];

    if (now - resolved_at >= ID_CACHE_TTL)
    {
        value = resolve(id);
        resolved_at = now;
    }

    return value;
}

static char* get_cached_name(id_cache_t<std::string>& cache, uint32_t id, char* (*resolve)(int))
{
    const auto name = resolve_cached(cache,
                                     id,
                                     [resolve](uint32_t value) -> std::string
    {
        const std::unique_ptr<char, decltype(&free)> resolved(
            resolve(static_cast<int>(value)), free);

        if (!resolved)
        {
            return {};
        }
        return resolved.get();
    });
    return name.empty() ? nullptr : strdup(name.c_str());
}

static char* get_user_cached(uint32_t uid)
{
    static id_cache_t<std::string> cache;
    return get_cached_name(cache, uid, fimebpf::instance().m_get_user);
}

static char* get_group_cached(uint32_t gid)
{
    static id_cache_t<std::string> cache;
    return get_cached_name(cache, gid, fimebpf::instance().m_get_group);
}

/* Resolves the primary GID for a given UID by looking up its passwd entry.
 * Used to derive "login_gid" (audit GID) from login_uid, since the kernel
 * audit subsystem only tracks loginuid (auid) and has no equivalent GID. */
static int get_login_gid(unsigned int uid)
{
    static id_cache_t<int> cache;
    return resolve_cached(cache,
                          uid,
                          [](uint32_t id)
    {
        struct passwd pwd {};
        struct passwd* result = nullptr;
        char buf[16384];

        if (getpwuid_r(id, &pwd, buf, sizeof(buf), &result) != 0 || result == nullptr)
        {
            return -1;
        }

        return static_cast<int>(pwd.pw_gid);
    });
}

/* Callback for normal whodata events */
void handle_event(const struct rt_file_event* e, void* ctx)
{
    (void)ctx;
    auto logFn = fimebpf::instance().m_loggingFunction;
    auto confFn = fimebpf::instance().m_fim_configuration_directory;

    if (!logFn || !confFn)
    {
        return;
    }

    if (confFn(e->filename))
    {
        auto event =
            std::make_unique<dynamic_file_event>(dynamic_file_event {.filename = std::string(e->filename),
                                                                     .cwd = std::string(e->cwd),
                                                                     .parent_cwd = std::string(e->parent_cwd),
                                                                     .comm = std::string(e->comm),
                                                                     .parent_comm = std::string(e->parent_comm),
                                                                     .pid = e->pid,
                                                                     .ppid = e->ppid,
                                                                     .uid = e->uid,
                                                                     .gid = e->gid,
                                                                     .euid = e->euid,
                                                                     .login_uid = e->login_uid,
                                                                     .inode = e->inode,
                                                                     .dev = e->dev});

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

/* Every non-probe event is copied while the engine's record is still valid. */
void healthcheck_event(const struct rt_file_event* e, void* ctx)
{
    const auto* expected = static_cast<const healthcheck_context*>(ctx);

    if (expected && strcmp(e->filename, expected->path) == 0)
    {
        if (e->event_type == expected->event_type)
        {
            event_received = true;
        }

        return;
    }

    handle_event(e, nullptr);
}

using healthcheck_operation_t = bool (*)(const char*, char*, size_t);

static void
log_healthcheck_message(modules_log_level_t level, const char* format, const char* action, const char* detail = nullptr)
{
    auto logFn = fimebpf::instance().m_loggingFunction;

    if (!logFn)
    {
        return;
    }

    char log_message[4200] = {0};
    snprintf(log_message, sizeof(log_message), format, action, detail ? detail : "");
    logFn(level, log_message);
}

static bool wait_for_healthcheck_event(rt_handle_t handle, healthcheck_context& expected, char* detail, size_t detail_size)
{
    auto logFn = fimebpf::instance().m_loggingFunction;

    if (!logFn)
    {
        return false;
    }

    event_received = false;
    time_t start_time = w_time(nullptr);

    while (!event_received)
    {
        int ret = rt_engine_api.poll(handle, healthcheck_event, &expected, WAIT_MS);

        if (ret < 0)
        {
            logFn(LOG_ERROR, FIM_ERROR_EBPF_RINGBUFF_CONSUME);
            snprintf(detail, detail_size, "%s", FIM_EBPF_HEALTHCHECK_EVENT_CONSUME_DETAIL);
            return false;
        }

        if (w_time(nullptr) - start_time >= HC_ACTION_TIMEOUT_S)
        {
            snprintf(detail, detail_size, "%s", FIM_EBPF_HEALTHCHECK_EVENT_TIMEOUT_DETAIL);
            return false;
        }
    }

    return true;
}

static bool create_healthcheck_file(const char* file_path, char* detail, size_t detail_size)
{
    char error_message[4200] = {0};
    auto logFn = fimebpf::instance().m_loggingFunction;

    if (!logFn)
    {
        return false;
    }

    std::ofstream file(file_path);

    if (!file.is_open())
    {
        snprintf(error_message, sizeof(error_message), FIM_ERROR_EBPF_HEALTHCHECK_FILE, file_path);
        logFn(LOG_ERROR, error_message);
        snprintf(detail, detail_size, "%s", FIM_EBPF_HEALTHCHECK_CREATE_DETAIL);
        return false;
    }

    file << "Testing eBPF healthcheck\n";
    file.close();

    return true;
}

static bool modify_healthcheck_file_content(const char* file_path, char* detail, size_t detail_size)
{
    std::ofstream file(file_path, std::ios::app);

    if (!file.is_open())
    {
        snprintf(detail, detail_size, "%s", FIM_EBPF_HEALTHCHECK_CONTENT_DETAIL);
        return false;
    }

    file << "Updating eBPF healthcheck\n";
    file.close();

    return true;
}

static bool modify_healthcheck_file_metadata(const char* file_path, char* detail, size_t detail_size)
{
    struct stat file_stat = {};

    int fd = open(file_path, O_RDONLY);

    if (fd < 0)
    {
        snprintf(detail, detail_size, FIM_EBPF_HEALTHCHECK_STAT_DETAIL, file_path, strerror(errno));
        return false;
    }

    if (fstat(fd, &file_stat) != 0)
    {
        int saved_errno = errno;
        close(fd);
        snprintf(detail, detail_size, FIM_EBPF_HEALTHCHECK_STAT_DETAIL, file_path, strerror(saved_errno));
        return false;
    }

    mode_t current_mode = file_stat.st_mode & 0777;
    mode_t new_mode = (current_mode ^ S_IXUSR) & 0777;

    if (fchmod(fd, new_mode) != 0)
    {
        int saved_errno = errno;
        close(fd);
        snprintf(detail, detail_size, FIM_EBPF_HEALTHCHECK_CHMOD_DETAIL, file_path, strerror(saved_errno));
        return false;
    }

    close(fd);
    return true;
}

static bool delete_healthcheck_file(const char* file_path, char* detail, size_t detail_size)
{
    char error_message[4200] = {0};
    auto logFn = fimebpf::instance().m_loggingFunction;

    if (!logFn)
    {
        return false;
    }

    if (std::remove(file_path) != 0)
    {
        snprintf(error_message, sizeof(error_message), FIM_ERROR_EBPF_HEALTHCHECK_FILE_DEL, file_path);
        logFn(LOG_ERROR, error_message);
        snprintf(detail, detail_size, "%s", FIM_EBPF_HEALTHCHECK_DELETE_DETAIL);
        return false;
    }

    return true;
}

static bool run_healthcheck_action(
    rt_handle_t handle, const char* action, const char* file_path, healthcheck_operation_t operation, unsigned int event_type)
{
    char detail[4200] = {0};

    // Drain already queued probe events before triggering the next action. Create
    // and content modification both use OPEN, so type matching alone cannot
    // distinguish an old create record from the new write-intent open.
    healthcheck_context pending {file_path, 0};

    if (rt_engine_api.poll(handle, healthcheck_event, &pending, 0) < 0)
    {
        log_healthcheck_message(LOG_ERROR, FIM_ERROR_EBPF_HEALTHCHECK_ACTION_FAILED,
                                action, FIM_EBPF_HEALTHCHECK_EVENT_CONSUME_DETAIL);
        std::remove(file_path);
        return false;
    }

    healthcheck_context expected {file_path, event_type};
    event_received = false;

    if (!operation(file_path, detail, sizeof(detail)) ||
            !wait_for_healthcheck_event(handle, expected, detail, sizeof(detail)))
    {
        log_healthcheck_message(LOG_ERROR, FIM_ERROR_EBPF_HEALTHCHECK_ACTION_FAILED, action, detail);
        std::remove(file_path);
        return false;
    }

    log_healthcheck_message(LOG_INFO, FIM_EBPF_HEALTHCHECK_ACTION_SUCCESS, action);
    return true;
}

/* Worker thread to pop events from kernelEventQueue */
void ebpf_pop_events(fim::BoundedQueue<std::unique_ptr<dynamic_file_event>>& local_kernelEventQueue)
{
    auto logFn = fimebpf::instance().m_loggingFunction;

    if (!logFn)
    {
        return;
    }

    while (!worker_stop.load() && !fimebpf::instance().m_fim_shutdown_process_on())
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

            w_evt->path = strdup(event->filename.c_str());
            w_evt->process_name = strdup(event->comm.c_str());
            w_evt->user_id = num_to_str(event->uid);
            w_evt->user_name = get_user_cached(event->uid);
            w_evt->group_id = num_to_str(event->gid);
            w_evt->group_name = get_group_cached(event->gid);
            w_evt->effective_uid = num_to_str(event->euid);
            w_evt->effective_name = get_user_cached(event->euid);

            if (event->login_uid != (uint32_t) -1)
            {
                w_evt->audit_uid = num_to_str(event->login_uid);
                w_evt->audit_name = get_user_cached(event->login_uid);
                int audit_gid_val = get_login_gid(event->login_uid);

                if (audit_gid_val >= 0)
                {
                    w_evt->audit_gid = num_to_str((unsigned int)audit_gid_val);
                    w_evt->audit_group_name = get_group_cached(static_cast<uint32_t>(audit_gid_val));
                }
            }

            w_evt->inode = num_to_str(event->inode);
            w_evt->dev = num_to_str(event->dev);
            w_evt->process_id = event->pid;
            w_evt->ppid = event->ppid;
            w_evt->cwd = strdup(event->cwd.c_str());
            w_evt->parent_cwd = strdup(event->parent_cwd.c_str());
            w_evt->parent_name = strdup(event->parent_comm.c_str());

            fimebpf::instance().m_fim_whodata_event(w_evt);
            fimebpf::instance().m_free_whodata_event(w_evt);
        }
    }
}

#ifdef __cplusplus
extern "C"
{
#endif

void fimebpf_initialize(bool (*fim_conf)(const char*),
                        char* (*getUser)(int),
                        char* (*getGroup)(int),
                        void (*fimWhodataEvent)(whodata_evt*),
                        void (*freeWhodataEvent)(whodata_evt*),
                        void (*loggingFn)(modules_log_level_t, const char*),
                        char* (*abspathFn)(const char*, char*, size_t),
                        bool (*fimShutdownProcessOn)(),
                        unsigned int syscheckQueueSize)
{
    fimebpf::instance().initialize(fim_conf,
                                   getUser,
                                   getGroup,
                                   fimWhodataEvent,
                                   freeWhodataEvent,
                                   loggingFn,
                                   abspathFn,
                                   fimShutdownProcessOn,
                                   syscheckQueueSize);
}

int ebpf_whodata_healthcheck()
{
    std::lock_guard<std::mutex> owner(engine_mutex);
    auto logFn = fimebpf::instance().m_loggingFunction;
    auto abspathFn = fimebpf::instance().m_abspath;

    if (!logFn || !abspathFn || g_engine_handle)
    {
        return 1;
    }

    if (rt_abi_major() != RT_ABI_MAJOR)
    {
        logFn(LOG_ERROR, "eBPF engine ABI major mismatch; refusing host whodata.");
        return 1;
    }

    kernelEventQueue.setMaxSize(fimebpf::instance().m_queue_size);
    char object_path[PATH_MAX] = {0};
    char library_path[PATH_MAX] = {0};
    char probe_path[PATH_MAX] = {0};
    abspathFn(BPF_OBJ_INSTALL_PATH, object_path, sizeof(object_path));
    abspathFn("lib/libbpf.so", library_path, sizeof(library_path));
    abspathFn(EBPF_HC_FILE, probe_path, sizeof(probe_path));
    rt_filter filter {};
    filter.type_mask = RT_FILE_ALL_BITS;
    filter.bpf_obj_path = object_path;
    filter.libbpf_path = library_path;
    filter.log = engine_log;
    filter.cgroup_mode = RT_CGROUP_MODE_ALL;
    filter.skip_mask = 0;
    g_engine_handle = rt_engine_api.open(&filter);

    if (!g_engine_handle)
    {
        logFn(LOG_ERROR, FIM_ERROR_EBPF_OBJ_LOAD);
        return 1;
    }

    std::remove(probe_path);
    const bool success =
        run_healthcheck_action(g_engine_handle, "create file", probe_path, create_healthcheck_file, RT_EV_FILE_OPEN) &&
        run_healthcheck_action(g_engine_handle, "modify content", probe_path, modify_healthcheck_file_content, RT_EV_FILE_OPEN) &&
        run_healthcheck_action(g_engine_handle, "modify metadata", probe_path, modify_healthcheck_file_metadata, RT_EV_FILE_ATTR) &&
        run_healthcheck_action(g_engine_handle, "delete file", probe_path, delete_healthcheck_file, RT_EV_FILE_UNLINK);
    std::remove(probe_path);

    if (!success)
    {
        rt_engine_api.close(g_engine_handle);
        g_engine_handle = nullptr;
        return 1;
    }

    // No poll is in flight. Publish ownership to ebpf_whodata without reopening.
    engine_ready = true;
    logFn(LOG_INFO, FIM_EBPF_HEALTHCHECK_SUCCESS);
    return 0;
}

int ebpf_whodata()
{
    std::lock_guard<std::mutex> owner(engine_mutex);
    auto logFn = fimebpf::instance().m_loggingFunction;

    if (!logFn || !g_engine_handle || !engine_ready)
    {
        return 1;
    }

    engine_ready = false;
    worker_stop.store(false);
    std::thread consumer([]()
    {
        ebpf_pop_events(kernelEventQueue);
    });
    std::thread polling([logFn]()
    {
        while (!fimebpf::instance().m_fim_shutdown_process_on())
        {
            if (rt_engine_api.poll(g_engine_handle, handle_event, nullptr, WAIT_MS) < 0)
            {
                logFn(LOG_ERROR, FIM_ERROR_EBPF_RINGBUFF_CONSUME);
                break;
            }
        }
    });
    // As in ContainerEventDrain::stop(): stop and join users before freeing the handle.
    polling.join();
    worker_stop.store(true);
    consumer.join();
    rt_engine_api.close(g_engine_handle);
    g_engine_handle = nullptr;
    return 0;
}

#ifdef __cplusplus
}
#endif
