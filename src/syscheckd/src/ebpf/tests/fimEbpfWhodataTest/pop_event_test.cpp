#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "ebpf_mock_utils.hpp"
#include "ebpf_whodata.h"
#include "bpf_helpers.h"
#include <bounded_queue.hpp>
#include <iostream>



class PopEventsTest : public ::testing::Test
{
    protected:

        virtual void SetUp()
        {
            MockFimebpf::mock_loggingFunction = mock_loggingFunction;
            MockFimebpf::mock_fim_conf = mock_fim_conf_success;
            MockFimebpf::mock_get_user = mock_get_user;
            MockFimebpf::mock_get_group = mock_get_group;
            MockFimebpf::SetMockFunctions();
        }

        virtual void TearDown() {}
};

template <typename T>
class MockBoundedQueue : public fim::BoundedQueue<T>
{
    public:
        MockBoundedQueue() = default;
        MockBoundedQueue(size_t max_size) : fim::BoundedQueue<T>(max_size) {}
        MOCK_METHOD(bool, pop, (T& out_value, int timeout_ms), (override));
        MOCK_METHOD(bool, push, (T&& in_value), (override));
};

/* TEST: ebpf_pop_events (host files) */

TEST_F(PopEventsTest, LoggingPointerFailed)
{
    MockFimebpf::mock_loggingFunction = nullptr;
    MockFimebpf::SetMockFunctions();
    MockBoundedQueue<std::unique_ptr<dynamic_file_event>> mock_kernel_queue;

    ebpf_pop_events(mock_kernel_queue);
}

TEST_F(PopEventsTest, ShutdownProcessTrue)
{
    MockBoundedQueue<std::unique_ptr<dynamic_file_event>> mock_kernel_queue;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
    .WillOnce(::testing::Return(true));

    ebpf_pop_events(mock_kernel_queue);
}

TEST_F(PopEventsTest, EbpfPopFailsAndShutdown)
{
    MockBoundedQueue<std::unique_ptr<dynamic_file_event>> mock_kernel_queue;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
    .WillOnce(::testing::Return(false))
    .WillOnce(::testing::Return(true));

    EXPECT_CALL(mock_kernel_queue, pop(::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::Invoke(
                      [&](std::unique_ptr<dynamic_file_event>& event_arg, [[maybe_unused]]int timeout_arg)
    {
        std::cout << "Update data" << std::endl;
        std::unique_ptr<dynamic_file_event> new_event = std::make_unique<dynamic_file_event>();
        event_arg = std::make_unique<dynamic_file_event>();
    }
                  ),
    ::testing::Return(false)
              ));

    ebpf_pop_events(mock_kernel_queue);
}

TEST_F(PopEventsTest, EbpfPopWithEvent)
{
    MockBoundedQueue<std::unique_ptr<dynamic_file_event>> mock_kernel_queue;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
    .WillOnce(::testing::Return(false))
    .WillOnce(::testing::Return(true));

    EXPECT_CALL(mock_kernel_queue, pop(::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::Invoke(
                      [&](std::unique_ptr<dynamic_file_event>& event_arg, [[maybe_unused]]int timeout_arg)
    {
        std::unique_ptr<dynamic_file_event> new_event = std::make_unique<dynamic_file_event>();
        event_arg = std::make_unique<dynamic_file_event>();
    }
                  ),
    ::testing::Return(true)
              ));

    EXPECT_CALL(MockFimebpf::GetInstance(), m_fim_whodata_event(::testing::_))
    .Times(::testing::AnyNumber());

    ebpf_pop_events(mock_kernel_queue);
}

/* TEST: ebpf_pop_container_events (#37533) — previously entirely untested.
 * fim_handle_container_whodata_event() isn't behind a mockable seam yet, so
 * these are smoke tests (drain logic doesn't crash / respects shutdown),
 * not assertions about container resolution behavior — that's
 * container_live_fim.cpp's own concern. */

TEST_F(PopEventsTest, ContainerPopLoggingPointerFailed)
{
    MockFimebpf::mock_loggingFunction = nullptr;
    MockFimebpf::SetMockFunctions();
    MockBoundedQueue<std::unique_ptr<container_file_event>> mock_container_queue;

    ebpf_pop_container_events(mock_container_queue);
}

TEST_F(PopEventsTest, ContainerPopShutdownProcessTrue)
{
    MockBoundedQueue<std::unique_ptr<container_file_event>> mock_container_queue;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
    .WillOnce(::testing::Return(true));

    ebpf_pop_container_events(mock_container_queue);
}

TEST_F(PopEventsTest, ContainerPopWithEventDoesNotCrash)
{
    MockBoundedQueue<std::unique_ptr<container_file_event>> mock_container_queue;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
    .WillOnce(::testing::Return(false))
    .WillOnce(::testing::Return(true));

    EXPECT_CALL(mock_container_queue, pop(::testing::_, ::testing::_))
    .WillOnce(::testing::DoAll(
                  ::testing::Invoke(
                      [&](std::unique_ptr<container_file_event>& event_arg, [[maybe_unused]]int timeout_arg)
    {
        event_arg = std::make_unique<container_file_event>(container_file_event
        {
            .filename = "/etc/passwd", .cgroup_id = 1, .mnt_ns = 1, .pid = 1, .inode = 1, .dev = 1
        });
    }
                  ),
    ::testing::Return(true)
              ));

    // fim_handle_container_whodata_event() will run for real here (not
    // mocked) — with no container_instances socket present it resolves to
    // unavailable and returns early, so this only asserts "doesn't crash",
    // not any container-resolution behavior.
    ebpf_pop_container_events(mock_container_queue);
}

void SetUpModule() {}
void TearDownModule() {}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    SetUpModule();
    int result = RUN_ALL_TESTS();
    TearDownModule();
    return result;
}
