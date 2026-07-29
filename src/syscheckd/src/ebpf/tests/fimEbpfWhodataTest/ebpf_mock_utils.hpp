#ifndef BPF_HELPERS_TEST_H
#define BPF_HELPERS_TEST_H
#include <cstring>
#include <future>
#include "ebpf_whodata.hpp"
#include "bpf_helpers.h"

inline std::shared_ptr<std::promise<void>> g_pop_started_promise;
inline std::shared_future<void> g_pop_started_future;

class MockFimebpf : public fimebpf
{
    public:
        static fimebpf::fim_configuration_directory_t mock_fim_conf;
        static fimebpf::get_user_t mock_get_user;
        static fimebpf::get_group_t mock_get_group;
        static fimebpf::fim_whodata_event_t mock_fim_whodata_event;
        static fimebpf::loggingFunction_t mock_loggingFunction;
        static fimebpf::abspath_t mock_abspath;
        MOCK_METHOD(bool, mock_fim_shutdown_process_on, ());
        MOCK_METHOD(void, m_fim_whodata_event, (whodata_evt*), ());
        MOCK_METHOD(void, m_free_whodata_event, (whodata_evt*), ());

        static MockFimebpf& GetInstance()
        {
            static MockFimebpf instance;
            return instance;
        }

        static void SetMockFunctions()
        {
            fimebpf::instance().m_fim_configuration_directory = mock_fim_conf;
            fimebpf::instance().m_get_user = mock_get_user;
            fimebpf::instance().m_get_group = mock_get_group;
            fimebpf::instance().m_loggingFunction = mock_loggingFunction;
            fimebpf::instance().m_abspath = mock_abspath;
            fimebpf::instance().m_fim_shutdown_process_on = []()
            {
                return MockFimebpf::GetInstance().mock_fim_shutdown_process_on();
            };
            fimebpf::instance().m_fim_whodata_event = [](whodata_evt * event)
            {
                MockFimebpf::GetInstance().m_fim_whodata_event(event);
            };
            fimebpf::instance().m_free_whodata_event = [](whodata_evt * event)
            {
                if (event == NULL) return;

                if (event->user_name) free(event->user_name);

                if (event->cwd) free(event->cwd);

                if (event->audit_name) free(event->audit_name);

                if (event->audit_uid) free(event->audit_uid);

                if (event->effective_name) free(event->effective_name);

                if (event->effective_uid) free(event->effective_uid);

                if (event->group_id) free(event->group_id);

                if (event->group_name) free(event->group_name);

                if (event->parent_name) free(event->parent_name);

                if (event->parent_cwd) free(event->parent_cwd);

                if (event->inode) free(event->inode);

                if (event->dev) free(event->dev);

                if (event->user_id) free(event->user_id);

                if (event->path) free(event->path);

                if (event->process_name) free(event->process_name);

                free(event);
            };
        }
};

fimebpf::fim_configuration_directory_t MockFimebpf::mock_fim_conf = nullptr;
fimebpf::get_user_t MockFimebpf::mock_get_user = nullptr;
fimebpf::get_group_t MockFimebpf::mock_get_group = nullptr;
fimebpf::fim_whodata_event_t MockFimebpf::mock_fim_whodata_event = nullptr;
fimebpf::loggingFunction_t MockFimebpf::mock_loggingFunction = nullptr;
fimebpf::abspath_t MockFimebpf::mock_abspath = nullptr;

directory_t* mock_fim_conf_failure([[maybe_unused]] const char* config_path, [[maybe_unused]] bool notify_not_found)
{
    return nullptr;
}
directory_t* mock_fim_conf_success([[maybe_unused]] const char* config_path, [[maybe_unused]] bool notify_not_found)
{
    static directory_t mockDirectory;
    mockDirectory.options = WHODATA_ACTIVE;
    return &mockDirectory;
}

char* mock_get_user([[maybe_unused]] int uid)
{
    return strdup("mock_user");
}
char* mock_get_group([[maybe_unused]] int gid)
{
    return strdup("mock_group");
}
void mock_fim_whodata_event([[maybe_unused]] whodata_evt* event)
{
    return;
}
void mock_loggingFunction([[maybe_unused]] modules_log_level_t level, [[maybe_unused]] const char* msg)
{
    return;
}
char* mock_abspath([[maybe_unused]] const char* path, char* buffer, [[maybe_unused]] size_t size)
{
    std::strcpy(buffer, "/tmp/ebpf_hc");
    return buffer;
}

void mock_ebpf_pop_events([[maybe_unused]] fim::BoundedQueue<std::unique_ptr<dynamic_file_event>>& kernel_queue)
{
    return;
}

void reset_pop_barrier()
{
    g_pop_started_promise = std::make_shared<std::promise<void>>();
    g_pop_started_future  = g_pop_started_promise->get_future().share();
}

void mock_ebpf_pop_events_barrier([[maybe_unused]] fim::BoundedQueue<std::unique_ptr<dynamic_file_event>>& kernel_queue)
{
    if (g_pop_started_promise)
    {
        try
        {
            g_pop_started_promise->set_value();
        }
        catch (...) {}
    }

    return;
}

/*
 * #37396/#37533 cutover: mocks for the rt_engine_api seam (rt_open/rt_poll/
 * rt_close via ebpf_whodata.hpp's `rt_engine_api` global), replacing the
 * old per-libbpf-call mocks (mock_bpf_object_*, mock_ring_buffer_*, ...)
 * that used to live here. Tests now only need to fake three functions
 * instead of a dozen, matching the engine's actual consumer-facing surface.
 */

rt_handle_t mock_rt_open_success([[maybe_unused]] const struct rt_filter* filter)
{
    // Any non-null value works: rt_poll/rt_close mocks below never
    // dereference it, they just check it's non-null where relevant.
    return reinterpret_cast<rt_handle_t>(0x1);
}

rt_handle_t mock_rt_open_failure([[maybe_unused]] const struct rt_filter* filter)
{
    return nullptr;
}

int mock_rt_poll_success([[maybe_unused]] rt_handle_t handle, [[maybe_unused]] rt_sink_fn sink,
                        [[maybe_unused]] void* user, [[maybe_unused]] int timeout_ms)
{
    return 1;
}

int mock_rt_poll_failure([[maybe_unused]] rt_handle_t handle, [[maybe_unused]] rt_sink_fn sink,
                         [[maybe_unused]] void* user, [[maybe_unused]] int timeout_ms)
{
    return -1;
}

// Fires the healthcheck sink with a synthetic matching event, then reports
// success — used to drive ebpf_whodata_healthcheck()'s wait-for-event loop
// without a real kernel.
int mock_rt_poll_healthcheck_success([[maybe_unused]] rt_handle_t handle, rt_sink_fn sink, void* user,
                                     [[maybe_unused]] int timeout_ms)
{
    struct rt_file_event ev {};
    ev.event_type = RT_EV_FILE_OPEN;
    std::strncpy(ev.filename, "tmp/ebpf_hc", sizeof(ev.filename) - 1);
    if (sink)
    {
        sink(&ev, user);
    }
    return 1;
}

int mock_rt_poll_success_barrier([[maybe_unused]] rt_handle_t handle, [[maybe_unused]] rt_sink_fn sink,
                                 [[maybe_unused]] void* user, [[maybe_unused]] int timeout_ms)
{
    if (g_pop_started_future.valid())
    {
        g_pop_started_future.wait();
    }
    return 1;
}

int mock_rt_poll_failure_barrier([[maybe_unused]] rt_handle_t handle, [[maybe_unused]] rt_sink_fn sink,
                                 [[maybe_unused]] void* user, [[maybe_unused]] int timeout_ms)
{
    if (g_pop_started_future.valid())
    {
        g_pop_started_future.wait();
    }
    return -1;
}

void mock_rt_close([[maybe_unused]] rt_handle_t handle) {}

#endif // BPF_HELPERS_TEST_H
