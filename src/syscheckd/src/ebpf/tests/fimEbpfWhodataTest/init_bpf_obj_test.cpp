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
    }
    void TearDown() override {
        resetGlobalState();
    }
};

TEST_F(InitBpfobjTest, Success) {

    MockFimebpf::mock_abspath = mock_abspath;
    MockFimebpf::SetMockFunctions();

    bpf_helpers->bpf_object_open_file = (bpf_object__open_file_t)mock_bpf_object_open_file_success;
    bpf_helpers->bpf_object_load = (bpf_object__load_t)mock_bpf_object_load_success;
    bpf_helpers->bpf_object_close = (bpf_object__close_t)mock_bpf_object_close_called;
    bpf_helpers->bpf_program_attach = (bpf_program__attach_t)mock_bpf_program_attach_success;
    bpf_helpers->bpf_object_next_program = (bpf_object__next_program_t)mock_bpf_object_next_program;

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

    int result = init_bpfobj();
    ASSERT_EQ(result, 1);
}

TEST_F(InitBpfobjTest, FailureDueAttachBPFobject) {
    bpf_helpers->bpf_object_open_file = (bpf_object__open_file_t)mock_bpf_object_open_file_success;
    bpf_helpers->bpf_object_load = (bpf_object__load_t)mock_bpf_object_load_success;
    bpf_helpers->bpf_object_next_program = (bpf_object__next_program_t)mock_bpf_object_next_program_in;
    bpf_helpers->bpf_object_close = (bpf_object__close_t)mock_bpf_object_close_called;
    bpf_helpers->bpf_program_attach = (bpf_program__attach_t)mock_bpf_program_attach_failure;

    int result = init_bpfobj();
    ASSERT_EQ(result, 1);
}
