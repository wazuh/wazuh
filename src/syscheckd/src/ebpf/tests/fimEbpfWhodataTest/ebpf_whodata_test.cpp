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
    static void SetUpTestSuite() {
        MockFimebpf::mock_loggingFunction = mock_loggingFunction;
        MockFimebpf::mock_abspath = mock_abspath;
        MockFimebpf::mock_get_user = mock_get_user;
        MockFimebpf::mock_get_group = mock_get_group;
        MockFimebpf::mock_fim_conf = mock_fim_conf_success;
        MockFimebpf::SetMockFunctions();
    }

    static void TearDownTestSuite() {
        bpf_helpers.reset();
    }

    void SetUp() override {
        event_received  = false;
        ebpf_hc_created = false;

        bpf_helpers = std::make_unique<w_bpf_helpers_t>();
        bpf_helpers->init_ring_buffer            = (init_ring_buffer_t)mock_init_ring_buffer_success;
        bpf_helpers->ring_buffer_free            = (ring_buffer__free_t)mock_ring_buffer_free;
        bpf_helpers->bpf_object_close            = (bpf_object__close_t)mock_bpf_object_close;
        bpf_helpers->bpf_object_open_file        = mock_bpf_object_open_file_success;
        bpf_helpers->bpf_object_load             = mock_bpf_object_load_success;
        bpf_helpers->bpf_object_next_program     = mock_bpf_object_next_program;
        bpf_helpers->bpf_program_attach          = mock_bpf_program_attach_success;
        bpf_helpers->bpf_object_find_map_fd_by_name = mock_bpf_object_find_map_fd_by_name_success;
        bpf_helpers->ring_buffer_new             = mock_ring_buffer_new_success;
        bpf_helpers->check_invalid_kernel_version= (check_invalid_kernel_version_t)mock_check_invalid_kernel_version;
        bpf_helpers->init_libbpf                 = (init_libbpf_t)mock_init_libbpf;
        bpf_helpers->init_bpfobj                 = (init_bpfobj_t)mock_init_bpfobj;
        bpf_helpers->ebpf_pop_events             = mock_ebpf_pop_events;
        bpf_helpers->ring_buffer_poll            = (ring_buffer__poll_t)mock_ring_buffer_poll_success_barrier;
    }

    void TearDown() override {}
};

time_t mock_time(time_t* t) {
    if (t) {
        *t = fake_time_now;
    }
    return fake_time_now;
}

int ebpf_whodata();

TEST_F(EbpfWhodataTest, SuccessfulRun) {
    reset_pop_barrier();
    bpf_helpers->ebpf_pop_events  = mock_ebpf_pop_events_barrier;
    bpf_helpers->ring_buffer_poll = (ring_buffer__poll_t)mock_ring_buffer_poll_success_barrier;

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
    reset_pop_barrier();
    bpf_helpers->ebpf_pop_events  = mock_ebpf_pop_events_barrier;
    bpf_helpers->ring_buffer_poll = (ring_buffer__poll_t)mock_ring_buffer_poll_failure_barrier;

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
