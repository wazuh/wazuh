#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstring>
#include "dynamic_library_wrapper.h"
#include "ebpf_mock_utils.hpp"

void resetGlobalState() {
    if (bpf_helpers) {
	w_bpf_deinit(bpf_helpers);
    }
}


class RingBufferTest : public ::testing::Test {
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


TEST_F(RingBufferTest, LoggingFailure) {
    ring_buffer* rb = nullptr;
    ring_buffer_sample_fn sample_cb = nullptr;

    MockFimebpf::mock_loggingFunction = nullptr;
    MockFimebpf::SetMockFunctions();
    ASSERT_EQ(1, init_ring_buffer(&rb, sample_cb));
}

TEST_F(RingBufferTest, InitSuccess) {
    ring_buffer* rb = nullptr;
    ring_buffer_sample_fn sample_cb = nullptr;

    bpf_helpers->bpf_object_find_map_fd_by_name = (bpf_object__find_map_fd_by_name_t)mock_bpf_object_find_map_fd_by_name_success;
    bpf_helpers->bpf_object_close = (bpf_object__close_t)mock_bpf_object_close_called;
    bpf_helpers->ring_buffer_new = (ring_buffer__new_t)mock_ring_buffer_new_success;

    ASSERT_EQ(0, init_ring_buffer(&rb, sample_cb));
}

TEST_F(RingBufferTest, InitMapFdFailure) {
    ring_buffer* rb = nullptr;
    ring_buffer_sample_fn sample_cb = nullptr;

    bpf_helpers->bpf_object_find_map_fd_by_name = (bpf_object__find_map_fd_by_name_t)mock_bpf_object_find_map_fd_by_name_failure;
    bpf_helpers->bpf_object_close = (bpf_object__close_t)mock_bpf_object_close_called;

    ASSERT_EQ(1, init_ring_buffer(&rb, sample_cb));
}

TEST_F(RingBufferTest, InitRbNewFailure) {
    ring_buffer* rb = nullptr;
    ring_buffer_sample_fn sample_cb = nullptr;

    bpf_helpers->bpf_object_find_map_fd_by_name = (bpf_object__find_map_fd_by_name_t)mock_bpf_object_find_map_fd_by_name_success;
    bpf_helpers->bpf_object_close = (bpf_object__close_t)mock_bpf_object_close_called;
    bpf_helpers->ring_buffer_new = (ring_buffer__new_t)mock_ring_buffer_new_failure;

    ASSERT_EQ(1, init_ring_buffer(&rb, sample_cb));
}

void SetUpModule() {}
void TearDownModule() {}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    SetUpModule();
    int result = RUN_ALL_TESTS();
    TearDownModule();
    return result;
}
