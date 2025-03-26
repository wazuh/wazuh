#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "ebpf_mock_utils.hpp"
#include "ebpf_whodata.h"
#include "bpf_helpers.h"
#include <bounded_queue.hpp>
#include <iostream>



class PopEventsTest : public ::testing::Test {
protected:

    virtual void SetUp() {
        MockFimebpf::mock_loggingFunction = mock_loggingFunction;
    	MockFimebpf::mock_fim_conf = mock_fim_conf_success;
        MockFimebpf::mock_get_user = mock_get_user;
        MockFimebpf::mock_get_group = mock_get_group;
        MockFimebpf::SetMockFunctions();
        bpf_helpers = std::make_unique<w_bpf_helpers_t>();
    }

    virtual void TearDown() {
        bpf_helpers.reset();
    }
};

void whodata_pop_events(fim::BoundedQueue<std::unique_ptr<whodata_evt, whodata_deleter>>& queue);

template <typename T>
class MockBoundedQueue : public fim::BoundedQueue<T> {
public:
    MockBoundedQueue() = default;
    MockBoundedQueue(size_t max_size) : fim::BoundedQueue<T>(max_size) {}
    MOCK_METHOD(bool, pop, (T& out_value, int timeout_ms), (override));
    MOCK_METHOD(bool, push, (T&& in_value), (override));
};


TEST_F(PopEventsTest, ShutdownImmediately) {

    MockBoundedQueue<std::unique_ptr<whodata_evt, whodata_deleter>> mock_queue;
    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
        .WillOnce(::testing::Return(true));

    whodata_pop_events(mock_queue);
}

TEST_F(PopEventsTest, PopFailsAndShutdown) {

    MockBoundedQueue<std::unique_ptr<whodata_evt, whodata_deleter>> mock_queue;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
        .WillOnce(::testing::Return(false))
        .WillOnce(::testing::Return(true));

    EXPECT_CALL(mock_queue, pop(::testing::_, ::testing::_))
        .WillOnce(::testing::Return(false));


    whodata_pop_events(mock_queue);
}

TEST_F(PopEventsTest, PopSucceedsWithEvent) {

    MockBoundedQueue<std::unique_ptr<whodata_evt, whodata_deleter>> mock_queue;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
        .WillOnce(::testing::Return(false))
        .WillOnce(::testing::Return(true));

    EXPECT_CALL(mock_queue, pop(::testing::_, ::testing::_))
       .WillOnce(::testing::DoAll(
        ::testing::Invoke(
            [&](std::unique_ptr<whodata_evt, whodata_deleter>& event_arg, int timeout_arg) {
		std::unique_ptr<whodata_evt, whodata_deleter> new_event = std::make_unique<whodata_evt>();
                event_arg = std::make_unique<whodata_evt>();
            }
        ),
        ::testing::Return(true)
    ));

    EXPECT_CALL(MockFimebpf::GetInstance(), m_fim_whodata_event(::testing::NotNull()));

    whodata_pop_events(mock_queue);
}

/* TEST: ebpf_pop_events */

TEST_F(PopEventsTest, LoggingPointerFailed) {
    MockFimebpf::mock_loggingFunction = nullptr;
    MockFimebpf::SetMockFunctions();
    MockBoundedQueue<std::unique_ptr<file_event>> mock_kernel_queue;
    MockBoundedQueue<std::unique_ptr<whodata_evt, whodata_deleter>> mock_whodata_queue;

    ebpf_pop_events(mock_kernel_queue, mock_whodata_queue);
}

TEST_F(PopEventsTest, ShutdownProcessTrue) {
    MockBoundedQueue<std::unique_ptr<file_event>> mock_kernel_queue;
    MockBoundedQueue<std::unique_ptr<whodata_evt, whodata_deleter>> mock_whodata_queue;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
        .WillOnce(::testing::Return(true));

    ebpf_pop_events(mock_kernel_queue, mock_whodata_queue);
}

TEST_F(PopEventsTest, EbpPopFailsAndShutdown) {
    MockBoundedQueue<std::unique_ptr<file_event>> mock_kernel_queue;
    MockBoundedQueue<std::unique_ptr<whodata_evt, whodata_deleter>> mock_whodata_queue;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
        .WillOnce(::testing::Return(false))
        .WillOnce(::testing::Return(true));

    EXPECT_CALL(mock_kernel_queue, pop(::testing::_, ::testing::_))
       .WillOnce(::testing::DoAll(
        ::testing::Invoke(
            [&](std::unique_ptr<file_event>& event_arg, int timeout_arg) {
		std::cout << "Update data" << std::endl;
		std::unique_ptr<file_event> new_event = std::make_unique<file_event>();
                event_arg = std::make_unique<file_event>();
            }
        ),
        ::testing::Return(false)
    ));

    ebpf_pop_events(mock_kernel_queue, mock_whodata_queue);
}

TEST_F(PopEventsTest, EbpPopWithEvent) {
    MockBoundedQueue<std::unique_ptr<file_event>> mock_kernel_queue;
    MockBoundedQueue<std::unique_ptr<whodata_evt, whodata_deleter>> mock_whodata_queue;
    MockFimebpf::mock_fim_conf = mock_fim_conf_failure;
    MockFimebpf::SetMockFunctions();

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
        .WillOnce(::testing::Return(false))
        .WillOnce(::testing::Return(true));

    EXPECT_CALL(mock_kernel_queue, pop(::testing::_, ::testing::_))
       .WillOnce(::testing::DoAll(
        ::testing::Invoke(
            [&](std::unique_ptr<file_event>& event_arg, int timeout_arg) {
		        std::unique_ptr<file_event> new_event = std::make_unique<file_event>();
                event_arg = std::make_unique<file_event>();
            }
        ),
        ::testing::Return(true)
    ));

    ebpf_pop_events(mock_kernel_queue, mock_whodata_queue);
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
