#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstring>
#include "dynamic_library_wrapper.h"
#include "ebpf_mock_utils.hpp"

extern volatile bool event_received;
const char* EBPF_HC_FILE = "tmp/ebpf_hc";


#define TASK_COMM_LEN 32
#define PATH_MAX 4096
struct file_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 inode;
    __u64 dev;
    char comm[TASK_COMM_LEN];
    char filename[PATH_MAX];
    char cwd[PATH_MAX];
    char parent_cwd[PATH_MAX];
    char parent_comm[TASK_COMM_LEN];
};

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

// Need to review why strstr is returning true when it shouldn't, for the condition:
//  if (strstr(e->filename, EBPF_HC_FILE))

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
