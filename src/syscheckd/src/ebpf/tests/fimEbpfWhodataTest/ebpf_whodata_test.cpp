#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "ebpf_mock_utils.hpp"
#include "ebpf_whodata.h"
#include "bpf_helpers.h"

extern volatile bool event_received;
extern volatile bool ebpf_hc_created;
time_t fake_time_now = 0;
extern time_t (*w_time)(time_t*);

class EbpfWhodataTest : public ::testing::Test {
protected:

    virtual void SetUp() {
        MockFimebpf::mock_loggingFunction = mock_loggingFunction;
        MockFimebpf::mock_abspath = mock_abspath;
        MockFimebpf::SetMockFunctions();
        bpf_helpers = std::make_unique<w_bpf_helpers_t>();
        bpf_helpers->ebpf_pop_events = (ebpf_pop_events_t)mock_ebpf_pop_events;
        bpf_helpers->init_ring_buffer = (init_ring_buffer_t)mock_init_ring_buffer_success;
        bpf_helpers->ring_buffer_poll = (ring_buffer__poll_t)mock_ring_buffer_poll_success;
        bpf_helpers->ring_buffer_free = (ring_buffer__free_t)mock_ring_buffer_free;
        bpf_helpers->bpf_object_close = (bpf_object__close_t)mock_bpf_object_close;
        bpf_helpers->check_invalid_kernel_version = (check_invalid_kernel_version_t)mock_check_invalid_kernel_version;
        bpf_helpers->init_libbpf = (init_libbpf_t)mock_init_libbpf;
        bpf_helpers->init_bpfobj = (init_bpfobj_t)mock_init_bpfobj;
    }

    virtual void TearDown() {
        bpf_helpers.reset();
    }
};

time_t mock_time(time_t* t) {
    if (t) {
        *t = fake_time_now;
    }
    return fake_time_now;
}

int ebpf_whodata();

TEST_F(EbpfWhodataTest, SuccessfulRun) {

    bpf_helpers->init_ring_buffer = (init_ring_buffer_t)mock_init_ring_buffer_success;
    bpf_helpers->ring_buffer_poll = (ring_buffer__poll_t)mock_ring_buffer_poll_success;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
        .WillOnce(::testing::Return(false))
        .WillOnce(::testing::Return(true));

    int result = ebpf_whodata();

    EXPECT_EQ(result, 0);
}

TEST_F(EbpfWhodataTest, RingBufferInitError) {

    bpf_helpers->init_ring_buffer = (init_ring_buffer_t)mock_init_ring_buffer_failure;

    int result = ebpf_whodata();

    EXPECT_EQ(result, 1);
}

TEST_F(EbpfWhodataTest, RingBufferPollError) {

    bpf_helpers->ring_buffer_poll = (ring_buffer__poll_t)mock_ring_buffer_poll_failure;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
        .WillOnce(::testing::Return(false));

    int result = ebpf_whodata();

    EXPECT_EQ(result, 0);
}

TEST_F(EbpfWhodataTest, EbpfWhodataHealthcheckTestSuccess) {

    event_received = true;

    EXPECT_FALSE(ebpf_whodata_healthcheck());
}

TEST_F(EbpfWhodataTest, EbpfWhodataHealthcheckTestFailInitRingBuffer) {

    bpf_helpers->init_ring_buffer = (init_ring_buffer_t)mock_init_ring_buffer_failure;

    EXPECT_TRUE(ebpf_whodata_healthcheck());
}

TEST_F(EbpfWhodataTest, EbpfWhodataHealthcheckTestFailNoEventReceived) {

    event_received = false;
    w_time = mock_time;
    bpf_helpers->ring_buffer_poll = [](ring_buffer*, int) {
        fake_time_now += 5;
        return 0;
    };

    EXPECT_TRUE(ebpf_whodata_healthcheck());
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
