#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "ebpf_mock_utils.hpp"

class HealthcheckEventTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            event_received = false;
            MockFimebpf::mock_loggingFunction = mock_loggingFunction;
            MockFimebpf::mock_fim_conf = mock_fim_conf_success;
            MockFimebpf::SetMockFunctions();
            kernelEventQueue.setMaxSize(16);
        }
        void TearDown() override
        {
            std::unique_ptr<dynamic_file_event> event;

            while (kernelEventQueue.pop(event, 0)) {}
        }
};

TEST_F(HealthcheckEventTest, RequiresExactPathAndType)
{
    healthcheck_context expected {"/tmp/ebpf_hc", RT_EV_FILE_ATTR};
    rt_file_event event {};
    strcpy(event.filename, "/tmp/ebpf_hc");
    event.event_type = RT_EV_FILE_OPEN;
    healthcheck_event(&event, &expected);
    EXPECT_FALSE(event_received);
    event.event_type = RT_EV_FILE_ATTR;
    strcpy(event.filename, "/tmp/ebpf_hc.extra");
    healthcheck_event(&event, &expected);
    EXPECT_FALSE(event_received);
    strcpy(event.filename, "/other/tmp/ebpf_hc");
    healthcheck_event(&event, &expected);
    EXPECT_FALSE(event_received);
    strcpy(event.filename, expected.path);
    healthcheck_event(&event, &expected);
    EXPECT_TRUE(event_received);
}

TEST_F(HealthcheckEventTest, CopiesRealEventDuringHealthcheck)
{
    healthcheck_context expected {"/tmp/ebpf_hc", RT_EV_FILE_OPEN};
    rt_file_event event {};
    strcpy(event.filename, "/monitored/file");
    strcpy(event.comm, "writer");
    strcpy(event.cwd, "/cwd");
    strcpy(event.parent_cwd, "/parent");
    strcpy(event.parent_comm, "parent");
    event.pid = 12;
    event.ppid = 11;
    event.uid = 1000;
    event.gid = 1001;
    event.euid = 1002;
    event.login_uid = 1003;
    event.inode = 42;
    event.dev = 43;
    healthcheck_event(&event, &expected);
    memset(&event, 0, sizeof(event)); // Ring storage may be reused immediately.
    std::unique_ptr<dynamic_file_event> copied;
    ASSERT_TRUE(kernelEventQueue.pop(copied, 0));
    EXPECT_EQ(copied->filename, "/monitored/file");
    EXPECT_EQ(copied->comm, "writer");
    EXPECT_EQ(copied->cwd, "/cwd");
    EXPECT_EQ(copied->parent_cwd, "/parent");
    EXPECT_EQ(copied->parent_comm, "parent");
    EXPECT_EQ(copied->pid, 12u);
    EXPECT_EQ(copied->ppid, 11u);
    EXPECT_EQ(copied->uid, 1000u);
    EXPECT_EQ(copied->gid, 1001u);
    EXPECT_EQ(copied->euid, 1002u);
    EXPECT_EQ(copied->login_uid, 1003u);
    EXPECT_EQ(copied->inode, 42u);
    EXPECT_EQ(copied->dev, 43u);
    EXPECT_FALSE(event_received);
}

TEST_F(HealthcheckEventTest, UnmonitoredEventsAreIgnored)
{
    MockFimebpf::mock_fim_conf = mock_fim_conf_failure;
    MockFimebpf::SetMockFunctions();
    rt_file_event event {};
    strcpy(event.filename, "/unmonitored");
    handle_event(&event, nullptr);
    std::unique_ptr<dynamic_file_event> copied;
    EXPECT_FALSE(kernelEventQueue.pop(copied, 0));
}

TEST_F(HealthcheckEventTest, RenameHalvesAreIndependentInEitherOrder)
{
    for (const char* path :
            {"/destination", "/source"
            })
    {
        rt_file_event event {};
        strcpy(event.filename, path);
        event.event_type = RT_EV_FILE_RENAME;
        handle_event(&event, nullptr);
    }
    std::unique_ptr<dynamic_file_event> copied;
    ASSERT_TRUE(kernelEventQueue.pop(copied, 0));
    EXPECT_EQ(copied->filename, "/destination");
    ASSERT_TRUE(kernelEventQueue.pop(copied, 0));
    EXPECT_EQ(copied->filename, "/source");
}
