#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstring>
#include "dynamic_library_wrapper.h"
#include "ebpf_mock_utils.hpp"

void* global_obj = nullptr;

void resetGlobalState() {
    global_obj = nullptr;
    if (bpf_helpers) {
	w_bpf_deinit(bpf_helpers);
    }
}


class InitBpfobjTest : public ::testing::Test {
protected:
    void SetUp() override {
        MockFimebpf::mock_loggingFunction = mock_loggingFunction;
        MockFimebpf::SetMockFunctions();
        bpf_helpers = std::make_unique<w_bpf_helpers_t>();
        bpf_helpers->bpf_link_destroy = (bpf_link__destroy_t)mock_bpf_link_destroy;
    }
    void TearDown() override {
        resetGlobalState();
    }
};

static bool mock_bpf_lsm_active_true() {
    return true;
}

static int s_load_calls = 0;
static int mock_bpf_object_load_fail_first([[maybe_unused]] void* obj) {
    s_load_calls++;
    // Fail both LSM variants (dpath, then walk) so init_bpfobj must reach the
    // kprobe retry instead of the in-function dpath->walk fallback.
    return s_load_calls <= 2 ? 1 : 0;
}

static int s_attach_calls = 0;
static int mock_bpf_program_attach_fail_first([[maybe_unused]] void* prog) {
    s_attach_calls++;
    // Fail once during the LSM attempt so init_bpfobj falls back to kprobe,
    // which then attaches cleanly.
    return s_attach_calls == 2 ? 1 : 0;
}

TEST_F(InitBpfobjTest, Success) {

    MockFimebpf::mock_abspath = mock_abspath;
    MockFimebpf::SetMockFunctions();

    bpf_helpers->bpf_object_open_file = (bpf_object__open_file_t)mock_bpf_object_open_file_success;
    bpf_helpers->bpf_object_load = (bpf_object__load_t)mock_bpf_object_load_success;
    bpf_helpers->bpf_object_close = (bpf_object__close_t)mock_bpf_object_close_called;
    bpf_helpers->bpf_program_attach = (bpf_program__attach_t)mock_bpf_program_attach_success;
    bpf_helpers->bpf_object_next_program = (bpf_object__next_program_t)mock_bpf_object_next_program;
    bpf_helpers->bpf_program_set_autoload = (bpf_program__set_autoload_t)mock_bpf_program_set_autoload;
    bpf_helpers->bpf_program_autoload = (bpf_program__autoload_t)mock_bpf_program_autoload_true;
    bpf_helpers->bpf_program_section_name = (bpf_program__section_name_t)mock_bpf_program_section_name_kprobe;
    bpf_helpers->bpf_program_name = (bpf_program__name_t)mock_bpf_program_name_default;

    MockFimebpf::SetMockFunctions();
    int result = init_bpfobj();
    ASSERT_EQ(result, 0);
}

TEST_F(InitBpfobjTest, LoggingPointerFailed) {
    MockFimebpf::mock_loggingFunction = nullptr;
    MockFimebpf::SetMockFunctions();

    int result = init_bpfobj();
    ASSERT_EQ(result, 1);
}

TEST_F(InitBpfobjTest, FailureDueToFileOpen) {

    MockFimebpf::mock_abspath = mock_abspath;
    MockFimebpf::SetMockFunctions();

    bpf_helpers->bpf_object_open_file = (bpf_object__open_file_t)mock_bpf_object_open_file_failure;

    int result = init_bpfobj();

    ASSERT_EQ(result, 1);
}

TEST_F(InitBpfobjTest, FailureDueLoadeBPFobject) {
    bpf_helpers->bpf_object_open_file = (bpf_object__open_file_t)mock_bpf_object_open_file_success;
    bpf_helpers->bpf_object_load = (bpf_object__load_t)mock_bpf_object_load_failure;
    bpf_helpers->bpf_program_attach = (bpf_program__attach_t)mock_bpf_program_attach_failure;
    bpf_helpers->bpf_object_next_program = (bpf_object__next_program_t)mock_bpf_object_next_program;
    bpf_helpers->bpf_object_close = (bpf_object__close_t)mock_bpf_object_close_called;
    bpf_helpers->bpf_program_set_autoload = (bpf_program__set_autoload_t)mock_bpf_program_set_autoload;
    bpf_helpers->bpf_program_autoload = (bpf_program__autoload_t)mock_bpf_program_autoload_true;
    bpf_helpers->bpf_program_section_name = (bpf_program__section_name_t)mock_bpf_program_section_name_kprobe;
    bpf_helpers->bpf_program_name = (bpf_program__name_t)mock_bpf_program_name_default;

    int result = init_bpfobj();
    ASSERT_EQ(result, 1);
}

TEST_F(InitBpfobjTest, FailureDueAttachBPFobject) {
    bpf_helpers->bpf_object_open_file = (bpf_object__open_file_t)mock_bpf_object_open_file_success;
    bpf_helpers->bpf_object_load = (bpf_object__load_t)mock_bpf_object_load_success;
    bpf_helpers->bpf_object_next_program = (bpf_object__next_program_t)mock_bpf_object_next_program_in;
    bpf_helpers->bpf_object_close = (bpf_object__close_t)mock_bpf_object_close_called;
    bpf_helpers->bpf_program_attach = (bpf_program__attach_t)mock_bpf_program_attach_failure;
    bpf_helpers->bpf_program_set_autoload = (bpf_program__set_autoload_t)mock_bpf_program_set_autoload;
    bpf_helpers->bpf_program_autoload = (bpf_program__autoload_t)mock_bpf_program_autoload_true;
    bpf_helpers->bpf_program_section_name = (bpf_program__section_name_t)mock_bpf_program_section_name_kprobe;
    bpf_helpers->bpf_program_name = (bpf_program__name_t)mock_bpf_program_name_default;

    int result = init_bpfobj();
    ASSERT_EQ(result, 1);
}

TEST_F(InitBpfobjTest, FallbackToKprobeOnLoadFailure) {
    MockFimebpf::mock_abspath = mock_abspath;
    MockFimebpf::SetMockFunctions();

    s_load_calls = 0;
    bpf_helpers->is_bpf_lsm_active = (is_bpf_lsm_active_t)mock_bpf_lsm_active_true;
    bpf_helpers->bpf_object_open_file = (bpf_object__open_file_t)mock_bpf_object_open_file_success;
    bpf_helpers->bpf_object_load = (bpf_object__load_t)mock_bpf_object_load_fail_first;
    bpf_helpers->bpf_object_close = (bpf_object__close_t)mock_bpf_object_close_called;
    bpf_helpers->bpf_program_attach = (bpf_program__attach_t)mock_bpf_program_attach_success;
    bpf_helpers->bpf_object_next_program = (bpf_object__next_program_t)mock_bpf_object_next_program;
    bpf_helpers->bpf_program_set_autoload = (bpf_program__set_autoload_t)mock_bpf_program_set_autoload;
    bpf_helpers->bpf_program_autoload = (bpf_program__autoload_t)mock_bpf_program_autoload_true;
    bpf_helpers->bpf_program_section_name = (bpf_program__section_name_t)mock_bpf_program_section_name_kprobe;
    bpf_helpers->bpf_program_name = (bpf_program__name_t)mock_bpf_program_name_default;

    int result = init_bpfobj();
    ASSERT_EQ(result, 0);
}

TEST_F(InitBpfobjTest, FallbackToKprobeOnAttachFailure) {
    MockFimebpf::mock_abspath = mock_abspath;
    MockFimebpf::SetMockFunctions();

    s_attach_calls = 0;
    bpf_helpers->is_bpf_lsm_active = (is_bpf_lsm_active_t)mock_bpf_lsm_active_true;
    bpf_helpers->bpf_object_open_file = (bpf_object__open_file_t)mock_bpf_object_open_file_success;
    bpf_helpers->bpf_object_load = (bpf_object__load_t)mock_bpf_object_load_success;
    bpf_helpers->bpf_object_next_program = (bpf_object__next_program_t)mock_bpf_object_next_program_in;
    bpf_helpers->bpf_object_close = (bpf_object__close_t)mock_bpf_object_close_called;
    bpf_helpers->bpf_program_attach = (bpf_program__attach_t)mock_bpf_program_attach_fail_first;
    bpf_helpers->bpf_program_set_autoload = (bpf_program__set_autoload_t)mock_bpf_program_set_autoload;
    bpf_helpers->bpf_program_autoload = (bpf_program__autoload_t)mock_bpf_program_autoload_true;
    bpf_helpers->bpf_program_section_name = (bpf_program__section_name_t)mock_bpf_program_section_name_kprobe;
    bpf_helpers->bpf_program_name = (bpf_program__name_t)mock_bpf_program_name_default;

    int result = init_bpfobj();
    ASSERT_EQ(result, 0);
}
