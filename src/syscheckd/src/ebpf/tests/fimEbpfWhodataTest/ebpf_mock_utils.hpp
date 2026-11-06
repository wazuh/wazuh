#ifndef BPF_HELPERS_TEST_H
#define BPF_HELPERS_TEST_H
#include <cstring>
#include "ebpf_whodata.hpp"
#include <bounded_queue.hpp>


extern fim::BoundedQueue<std::unique_ptr<dynamic_file_event>> kernelEventQueue;


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

                if (event->audit_gid) free(event->audit_gid);

                if (event->audit_group_name) free(event->audit_group_name);

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

bool mock_fim_conf_failure([[maybe_unused]] const char* config_path)
{
    return false;
}
bool mock_fim_conf_success([[maybe_unused]] const char* config_path)
{
    return true;
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
// Tests replace the engine's three consumer operations, never libbpf internals.
#endif
