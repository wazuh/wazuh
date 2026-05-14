#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstring>
#include "dynamic_library_wrapper.h"
#include "ebpf_mock_utils.hpp"

extern volatile bool event_received;
const char* EBPF_HC_FILE = "tmp/ebpf_hc";

void ResetEventReceived() {
    event_received = false;
}

class HealthcheckEventTest : public ::testing::Test {
protected:
    void SetUp() override {
        ResetEventReceived();
    }
    void TearDown() override {}
};

TEST_F(HealthcheckEventTest, TestEventReceivedWhenFileNameContainsEBPF_HC_FILE) {
    file_event e;
    snprintf(e.filename, sizeof(e.filename), "%s", EBPF_HC_FILE);

    healthcheck_event(nullptr, &e, sizeof(e));

    EXPECT_TRUE(event_received);
}


TEST_F(HealthcheckEventTest, TestEventNotReceivedWhenFileNameDoesNotContainEBPF_HC_FILE) {
    file_event e;
    strcpy(e.filename, "testing.txt");

    healthcheck_event(nullptr, &e, sizeof(e));

    EXPECT_FALSE(event_received);
}
