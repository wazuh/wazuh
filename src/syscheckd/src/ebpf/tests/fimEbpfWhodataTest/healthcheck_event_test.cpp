#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstring>
#include "ebpf_whodata.hpp"

extern volatile bool event_received;
const char* EBPF_HC_FILE = "tmp/ebpf_hc";

void ResetEventReceived()
{
    event_received = false;
}

class HealthcheckEventTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            ResetEventReceived();
        }
        void TearDown() override {}
};

// healthcheck_event() is declared in ebpf_whodata.cpp with C++ linkage (it's
// passed directly as an rt_sink_fn, not exported through the C API), so it
// isn't in a header — forward-declare it here the same way pop_event_test
// declares the pop-thread functions it exercises.
void healthcheck_event(const struct rt_file_event* ev, void* user);

TEST_F(HealthcheckEventTest, TestEventReceivedWhenFileNameContainsEBPF_HC_FILE)
{
    struct rt_file_event ev {};
    snprintf(ev.filename, sizeof(ev.filename), "%s", EBPF_HC_FILE);

    healthcheck_event(&ev, nullptr);

    EXPECT_TRUE(event_received);
}

TEST_F(HealthcheckEventTest, TestEventNotReceivedWhenFileNameDoesNotContainEBPF_HC_FILE)
{
    struct rt_file_event ev {};
    std::strncpy(ev.filename, "testing.txt", sizeof(ev.filename) - 1);

    healthcheck_event(&ev, nullptr);

    EXPECT_FALSE(event_received);
}

TEST_F(HealthcheckEventTest, TestNullEventDoesNotCrash)
{
    healthcheck_event(nullptr, nullptr);

    EXPECT_FALSE(event_received);
}
