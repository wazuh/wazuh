#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "ebpf_mock_utils.hpp"
#include "ebpf_whodata.h"
#include "bpf_helpers.h"


class EbpfWhodataTest : public ::testing::Test {
protected:

    virtual void SetUp() {
        MockFimebpf::mock_loggingFunction = mock_loggingFunction;
        MockFimebpf::SetMockFunctions();
        bpf_helpers = std::make_unique<w_bpf_helpers_t>();
    }

    virtual void TearDown() {
        bpf_helpers.reset();
    }
};

int ebpf_whodata();

TEST_F(EbpfWhodataTest, SuccessfulRun) {

    bpf_helpers->ring_buffer_poll = (ring_buffer__poll_t)mock_ring_buffer_poll_failure;
    bpf_helpers->ring_buffer_free = (ring_buffer__free_t)mock_ring_buffer_free;
    bpf_helpers->bpf_object_close = (bpf_object__close_t)mock_bpf_object_close;
    bpf_helpers->init_ring_buffer = (init_ring_buffer_t)mock_init_ring_buffer_success;

    int result = ebpf_whodata();

    EXPECT_EQ(result, 0);
}

TEST_F(EbpfWhodataTest, RingBufferInitError) {

    fimebpf::instance().m_is_fim_shutdown = true;
    bpf_helpers->init_ring_buffer = (init_ring_buffer_t)mock_init_ring_buffer_failure;

    int result = ebpf_whodata();

    EXPECT_EQ(result, 1);
}

/*
TEST_F(EbpfWhodataTest, RingBufferPollError) {

    fimebpf::instance().m_is_fim_shutdown = false;
    MockInterface mock;

    bpf_helpers->init_ring_buffer = (init_ring_buffer_t)mock_init_ring_buffer_success;
    bpf_helpers->ring_buffer_poll = (ring_buffer__poll_t)mock_ring_buffer_poll_failure;
    bpf_helpers->ring_buffer_free = (ring_buffer__free_t)mock_ring_buffer_free;
    bpf_helpers->bpf_object_close = (bpf_object__close_t)mock_bpf_object_close;

    int result = ebpf_whodata();

    EXPECT_EQ(result, 0);
}
*/

void SetUpModule() {}
void TearDownModule() {}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    SetUpModule();
    int result = RUN_ALL_TESTS();
    TearDownModule();
    return result;
}
