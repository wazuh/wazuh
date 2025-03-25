#ifndef BPF_HELPERS_TEST_H
#define BPF_HELPERS_TEST_H
#include <cstring>
#include "ebpf_whodata.hpp"
#include "bpf_helpers.h"
#include "dynamic_library_wrapper.h"

extern std::unique_ptr<w_bpf_helpers_t> bpf_helpers;


class MockFimebpf : public fimebpf {
public:
    static fimebpf::fim_configuration_directory_t mock_fim_conf;
    static fimebpf::get_user_t mock_get_user;
    static fimebpf::get_group_t mock_get_group;
    static fimebpf::fim_whodata_event_t mock_fim_whodata_event;
    static fimebpf::free_whodata_event_t mock_free_whodata_event;
    static fimebpf::loggingFunction_t mock_loggingFunction;
    static fimebpf::abspath_t mock_abspath;
    MOCK_METHOD(bool, mock_fim_shutdown_process_on, ());

    static MockFimebpf& GetInstance() {
        static MockFimebpf instance;
        return instance;
    }

    static void SetMockFunctions() {
        fimebpf::instance().m_fim_configuration_directory = mock_fim_conf;
        fimebpf::instance().m_get_user = mock_get_user;
        fimebpf::instance().m_get_group = mock_get_group;
        fimebpf::instance().m_fim_whodata_event = mock_fim_whodata_event;
        fimebpf::instance().m_free_whodata_event = mock_free_whodata_event;
        fimebpf::instance().m_loggingFunction = mock_loggingFunction;
        fimebpf::instance().m_abspath = mock_abspath;
        fimebpf::instance().m_fim_shutdown_process_on = []() {
            return MockFimebpf::GetInstance().mock_fim_shutdown_process_on();
        };
    }
};

fimebpf::fim_configuration_directory_t MockFimebpf::mock_fim_conf = nullptr;
fimebpf::get_user_t MockFimebpf::mock_get_user = nullptr;
fimebpf::get_group_t MockFimebpf::mock_get_group = nullptr;
fimebpf::fim_whodata_event_t MockFimebpf::mock_fim_whodata_event = nullptr;
fimebpf::free_whodata_event_t MockFimebpf::mock_free_whodata_event = nullptr;
fimebpf::loggingFunction_t MockFimebpf::mock_loggingFunction = nullptr;
fimebpf::abspath_t MockFimebpf::mock_abspath = nullptr;

directory_t* mock_fim_conf([[maybe_unused]] const char* config_path) { return nullptr; }

char* mock_get_user([[maybe_unused]] int uid) { return strdup("mock_user"); }
char* mock_get_group([[maybe_unused]] int gid) { return strdup("mock_group"); }
void mock_fim_whodata_event([[maybe_unused]] whodata_evt* event) { return; }
void mock_free_whodata_event([[maybe_unused]] whodata_evt* event) { return; }
void mock_loggingFunction([[maybe_unused]] modules_log_level_t level, [[maybe_unused]] const char* msg) { return; }

char* mock_abspath([[maybe_unused]] const char* path, char* buffer, [[maybe_unused]] size_t size) {
    std::strcpy(buffer, "/mock/path");
    return buffer;
}

void* mock_bpf_object_open_file_success([[maybe_unused]] const char* filename, [[maybe_unused]] void* opts) { return (void*)1; }
void* mock_bpf_object_open_file_failure([[maybe_unused]] const char* filename, [[maybe_unused]] void* opts) { return nullptr; }
int mock_bpf_object_load_success([[maybe_unused]] void* obj) { return 0; }
int mock_bpf_object_load_failure([[maybe_unused]] void* obj) { return 1; }
void mock_bpf_object_close_called([[maybe_unused]] void* obj) { return; }
bpf_program* mock_bpf_object_next_program([[maybe_unused]] void* obj, [[maybe_unused]] bpf_program* pos) { return nullptr; }
bpf_program* mock_bpf_object_next_program_in([[maybe_unused]] void* obj, [[maybe_unused]] bpf_program* pos) { return (bpf_program *)1; }
int mock_bpf_program_attach_success([[maybe_unused]] void* prog) { return 1; }
int mock_bpf_program_attach_failure([[maybe_unused]] void* prog) { return 0; }
int mock_bpf_object_find_map_fd_by_name_success([[maybe_unused]] void* obj, [[maybe_unused]] const char* name) { return 1; }
int mock_bpf_object_find_map_fd_by_name_failure([[maybe_unused]] void* obj, [[maybe_unused]] const char* name) { return -1; }

ring_buffer* mock_ring_buffer_new_success([[maybe_unused]] int fd, [[maybe_unused]] ring_buffer_sample_fn sample_cb, [[maybe_unused]] void* ctx, [[maybe_unused]] void* consumer_ctx) {
    return (ring_buffer*)1;
}

ring_buffer* mock_ring_buffer_new_failure([[maybe_unused]] int fd, [[maybe_unused]] ring_buffer_sample_fn sample_cb, [[maybe_unused]] void* ctx, [[maybe_unused]] void* consumer_ctx) {
    return nullptr;
}

int mock_ring_buffer_poll_success(ring_buffer* rb, int timeout_ms) [[maybe_unused]] { return 1; }
int mock_ring_buffer_poll_failure(ring_buffer* rb, int timeout_ms) [[maybe_unused]] { return -1; }
void mock_ring_buffer_free(ring_buffer* rb) [[maybe_unused]] {}
void mock_bpf_object_close(void* obj) [[maybe_unused]] {}
void mock_w_bpf_deinit(void* helpers) [[maybe_unused]] {}
int mock_init_ring_buffer_success(ring_buffer** rb, ring_buffer_sample_fn sample_cb) [[maybe_unused]] { return 0; }
int mock_init_ring_buffer_failure(ring_buffer** rb, ring_buffer_sample_fn sample_cb) [[maybe_unused]] { return 1; }
void mock_ebpf_pop_events() [[maybe_unused]] { return; }
void mock_whodata_pop_events() [[maybe_unused]] { return; }


#endif // BPF_HELPERS_TEST_H
