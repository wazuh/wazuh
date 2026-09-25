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

template <typename T>
class MockBoundedQueue : public fim::BoundedQueue<T> {
public:
    MockBoundedQueue() = default;
    MockBoundedQueue(size_t max_size) : fim::BoundedQueue<T>(max_size) {}
    MOCK_METHOD(bool, pop, (T& out_value, int timeout_ms), (override));
    MOCK_METHOD(bool, push, (T&& in_value), (override));
};

/* TEST: ebpf_pop_events */

TEST_F(PopEventsTest, LoggingPointerFailed) {
    MockFimebpf::mock_loggingFunction = nullptr;
    MockFimebpf::SetMockFunctions();
    MockBoundedQueue<std::unique_ptr<dynamic_file_event>> mock_kernel_queue;

    ebpf_pop_events(mock_kernel_queue);
}

TEST_F(PopEventsTest, ShutdownProcessTrue) {
    MockBoundedQueue<std::unique_ptr<dynamic_file_event>> mock_kernel_queue;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
        .WillOnce(::testing::Return(true));

    ebpf_pop_events(mock_kernel_queue);
}

TEST_F(PopEventsTest, EbpfPopFailsAndShutdown) {
    MockBoundedQueue<std::unique_ptr<dynamic_file_event>> mock_kernel_queue;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
        .WillOnce(::testing::Return(false))
        .WillOnce(::testing::Return(true));

    EXPECT_CALL(mock_kernel_queue, pop(::testing::_, ::testing::_))
       .WillOnce(::testing::DoAll(
        ::testing::Invoke(
            [&](std::unique_ptr<dynamic_file_event>& event_arg, [[maybe_unused]]int timeout_arg) {
		std::cout << "Update data" << std::endl;
		std::unique_ptr<dynamic_file_event> new_event = std::make_unique<dynamic_file_event>();
                event_arg = std::make_unique<dynamic_file_event>();
            }
        ),
        ::testing::Return(false)
    ));

    ebpf_pop_events(mock_kernel_queue);
}

TEST_F(PopEventsTest, EbpfPopWithEvent) {
    MockBoundedQueue<std::unique_ptr<dynamic_file_event>> mock_kernel_queue;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
        .WillOnce(::testing::Return(false))
        .WillOnce(::testing::Return(true));

    EXPECT_CALL(mock_kernel_queue, pop(::testing::_, ::testing::_))
       .WillOnce(::testing::DoAll(
        ::testing::Invoke(
            [&](std::unique_ptr<dynamic_file_event>& event_arg, [[maybe_unused]]int timeout_arg) {
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

template <typename Check>
static void pop_one_event(uint32_t login_uid, Check check) {
    MockBoundedQueue<std::unique_ptr<dynamic_file_event>> mock_kernel_queue;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
        .WillOnce(::testing::Return(false))
        .WillOnce(::testing::Return(true));

    EXPECT_CALL(mock_kernel_queue, pop(::testing::_, ::testing::_))
       .WillOnce(::testing::DoAll(
        ::testing::Invoke(
            [login_uid](std::unique_ptr<dynamic_file_event>& event_arg, [[maybe_unused]]int timeout_arg) {
                event_arg = std::make_unique<dynamic_file_event>();
                event_arg->login_uid = login_uid;
            }
        ),
        ::testing::Return(true)
    ));

    EXPECT_CALL(MockFimebpf::GetInstance(), m_fim_whodata_event(::testing::_))
        .WillOnce(::testing::Invoke(check));

    ebpf_pop_events(mock_kernel_queue);
}

TEST_F(PopEventsTest, EbpfPopUnsetLoginUidLeavesAuditAttributionUnset) {
    pop_one_event((uint32_t)-1, [](whodata_evt* w_evt) {
        EXPECT_EQ(w_evt->audit_uid, nullptr);
        EXPECT_EQ(w_evt->audit_name, nullptr);
        EXPECT_EQ(w_evt->audit_gid, nullptr);
        EXPECT_EQ(w_evt->audit_group_name, nullptr);
    });
}

TEST_F(PopEventsTest, EbpfPopValidLoginUidSetsAuditAttribution) {
    pop_one_event(1000, [](whodata_evt* w_evt) {
        EXPECT_STREQ(w_evt->audit_uid, "1000");
        EXPECT_STREQ(w_evt->audit_name, "mock_user");
    });
}

static int g_user_lookups = 0;
static char* counting_get_user([[maybe_unused]] int uid) {
    g_user_lookups++;
    return strdup("mock_user");
}

TEST_F(PopEventsTest, EbpfPopCachesIdentityLookups) {
    g_user_lookups = 0;
    MockFimebpf::mock_get_user = counting_get_user;
    MockFimebpf::SetMockFunctions();
    MockBoundedQueue<std::unique_ptr<dynamic_file_event>> mock_kernel_queue;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
        .WillOnce(::testing::Return(false))
        .WillOnce(::testing::Return(false))
        .WillOnce(::testing::Return(true));

    EXPECT_CALL(mock_kernel_queue, pop(::testing::_, ::testing::_))
        .Times(2)
        .WillRepeatedly(::testing::DoAll(
            ::testing::Invoke(
                [](std::unique_ptr<dynamic_file_event>& event_arg, [[maybe_unused]]int timeout_arg) {
                    event_arg = std::make_unique<dynamic_file_event>();
                    event_arg->uid = 4242;
                    event_arg->euid = 4242;
                    event_arg->login_uid = 4242;
                }
            ),
            ::testing::Return(true)
        ));

    EXPECT_CALL(MockFimebpf::GetInstance(), m_fim_whodata_event(::testing::_))
        .Times(2);

    ebpf_pop_events(mock_kernel_queue);

    EXPECT_EQ(g_user_lookups, 1);
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
