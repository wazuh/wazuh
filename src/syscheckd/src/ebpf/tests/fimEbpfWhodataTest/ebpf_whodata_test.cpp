#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <atomic>
#include <unistd.h>
#include <vector>
#include "ebpf_mock_utils.hpp"

extern time_t (*w_time)(time_t*);
static int abi_major = RT_ABI_MAJOR;
// Executable interposition exercises the refusal without expanding the three-call seam.
extern "C" int rt_abi_major(void)
{
    return abi_major;
}

static int opens;
static int closes;
static int polls;
static int fail_action;
static time_t fake_time;
static std::atomic<bool> shutdown_requested;
static std::atomic<bool> polling_active;

class EbpfWhodataTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            opens = closes = polls = 0;
            fail_action = -1;
            fake_time = 0;
            abi_major = RT_ABI_MAJOR;
            shutdown_requested = false;
            polling_active = false;
            MockFimebpf::mock_loggingFunction = mock_loggingFunction;
            MockFimebpf::mock_abspath = mock_abspath;
            MockFimebpf::mock_fim_conf = mock_fim_conf_success;
            MockFimebpf::SetMockFunctions();
            fimebpf::instance().m_queue_size = 32;
            fimebpf::instance().m_fim_shutdown_process_on = []()
            {
                return shutdown_requested.load();
            };
            w_time = [](time_t*)
            {
                return fake_time;
            };
            rt_engine_api.open = [](const rt_filter * filter) -> rt_handle_t
            {
                ++opens;
                EXPECT_EQ(filter->type_mask, RT_FILE_ALL_BITS);
                EXPECT_STREQ(filter->bpf_obj_path, "/tmp/p4-whodata/lib/rt_file.bpf.o");
                EXPECT_STREQ(filter->libbpf_path, "/tmp/p4-whodata/lib/libbpf.so");
                EXPECT_EQ(filter->cgroup_mode, RT_CGROUP_MODE_ALL);
                EXPECT_EQ(filter->skip_mask, 0u);
                EXPECT_NE(filter->log, nullptr);
                return reinterpret_cast<rt_handle_t>(1);
            };
            rt_engine_api.close = [](rt_handle_t handle)
            {
                EXPECT_EQ(handle, reinterpret_cast<rt_handle_t>(1));
                EXPECT_FALSE(polling_active.load());
                ++closes;
            };
            rt_engine_api.poll = [](rt_handle_t handle, rt_sink_fn sink, void* ctx, int timeout) -> int
            {
                EXPECT_EQ(handle, reinterpret_cast<rt_handle_t>(1));

                if (timeout == 0)
                {
                    auto* expected = static_cast<healthcheck_context*>(ctx);
                    EXPECT_EQ(expected->event_type, 0u);
                    return 0;
                }

                polling_active = true;
                const int action = polls++;

                if (action == fail_action)
                {
                    polling_active = false;
                    return -1;
                }

                if (ctx)
                {
                    auto* expected = static_cast<healthcheck_context*>(ctx);
                    const unsigned int types[] = {RT_EV_FILE_OPEN, RT_EV_FILE_OPEN, RT_EV_FILE_ATTR, RT_EV_FILE_UNLINK};
                    EXPECT_EQ(expected->event_type, types[action]);
                    rt_file_event event {};
                    strcpy(event.filename, expected->path);
                    event.event_type = expected->event_type;
                    sink(&event, ctx);
                }
                else
                {
                    shutdown_requested = true;
                }

                polling_active = false;
                return 1;
            };
            fimebpf::instance().m_abspath = [](const char* path, char* buffer, size_t size) -> char*
            {
                snprintf(buffer, size, "%s", strcmp(path, "tmp/ebpf_hc") == 0 ? "/tmp/p4-ebpf-hc" :
                         (strcmp(path, "lib/rt_file.bpf.o") == 0 ? "/tmp/p4-whodata/lib/rt_file.bpf.o" :
                          "/tmp/p4-whodata/lib/libbpf.so"));
                return buffer;
            };
        }
        void TearDown() override
        {
            std::remove("/tmp/p4-ebpf-hc");
            w_time = time;
            rt_engine_api = {};
            std::unique_ptr<dynamic_file_event> event;

            while (kernelEventQueue.pop(event, 0)) {}
        }
};

TEST_F(EbpfWhodataTest, OpensOnceAndHandsOffToPollingBeforeClose)
{
    ASSERT_EQ(ebpf_whodata_healthcheck(), 0);
    EXPECT_EQ(opens, 1);
    EXPECT_EQ(closes, 0);
    EXPECT_EQ(polls, 4);
    EXPECT_EQ(ebpf_whodata(), 0);
    EXPECT_EQ(opens, 1);
    EXPECT_EQ(closes, 1);
    EXPECT_EQ(polls, 5);
    EXPECT_EQ(ebpf_whodata(), 1);
}

TEST_F(EbpfWhodataTest, RefusesAbiMajorMismatchBeforeOpening)
{
    abi_major++;
    EXPECT_EQ(ebpf_whodata_healthcheck(), 1);
    EXPECT_EQ(opens, 0);
    EXPECT_EQ(polls, 0);
    EXPECT_EQ(closes, 0);
}

TEST_F(EbpfWhodataTest, OpenFailure)
{
    rt_engine_api.open = [](const rt_filter*) -> rt_handle_t { return nullptr; };
    EXPECT_EQ(ebpf_whodata_healthcheck(), 1);
    EXPECT_EQ(closes, 0);
}

TEST_F(EbpfWhodataTest, CleansUpEveryFailedAction)
{
    for (int action = 0; action < 4; ++action)
    {
        polls = 0;
        fail_action = action;
        EXPECT_EQ(ebpf_whodata_healthcheck(), 1);
        EXPECT_EQ(access("/tmp/p4-ebpf-hc", F_OK), -1);
        EXPECT_EQ(closes, action + 1);
        EXPECT_EQ(ebpf_whodata(), 1);
    }
}

TEST_F(EbpfWhodataTest, TimeoutCleansUp)
{
    rt_engine_api.poll = [](rt_handle_t, rt_sink_fn, void*, int)
    {
        fake_time += 5;
        return 0;
    };
    EXPECT_EQ(ebpf_whodata_healthcheck(), 1);
    EXPECT_EQ(closes, 1);
    EXPECT_EQ(access("/tmp/p4-ebpf-hc", F_OK), -1);
}

TEST_F(EbpfWhodataTest, PollErrorJoinsBeforeClose)
{
    ASSERT_EQ(ebpf_whodata_healthcheck(), 0);
    fail_action = 4;
    EXPECT_EQ(ebpf_whodata(), 0);
    EXPECT_EQ(closes, 1);
}

TEST_F(EbpfWhodataTest, RealEventMidHealthcheckReachesQueue)
{
    static auto poll = rt_engine_api.poll;
    poll = rt_engine_api.poll;
    rt_engine_api.poll = [](rt_handle_t handle, rt_sink_fn sink, void* ctx, int timeout)
    {
        if (timeout > 0 && polls == 1)
        {
            rt_file_event event {};
            strcpy(event.filename, "/monitored/during-healthcheck");
            event.euid = 1234;
            sink(&event, ctx);
            memset(&event, 0, sizeof(event));
        }

        return poll(handle, sink, ctx, timeout);
    };
    ASSERT_EQ(ebpf_whodata_healthcheck(), 0);
    std::unique_ptr<dynamic_file_event> event;
    ASSERT_TRUE(kernelEventQueue.pop(event, 0));
    EXPECT_EQ(event->filename, "/monitored/during-healthcheck");
    EXPECT_EQ(event->euid, 1234u);
    shutdown_requested = true;
    EXPECT_EQ(ebpf_whodata(), 0);
}

TEST_F(EbpfWhodataTest, EngineDiagnosticsReachFimAtMappedLevels)
{
    static auto open = rt_engine_api.open;
    open = rt_engine_api.open;
    static std::vector<modules_log_level_t> levels;
    levels.clear();
    fimebpf::instance().m_loggingFunction = [](modules_log_level_t level, const char* message)
    {
        if (strcmp(message, "engine diagnostic") == 0)
        {
            levels.push_back(level);
        }
    };
    rt_engine_api.open = [](const rt_filter * filter) -> rt_handle_t
    {
        for (int level = RT_LOG_ERROR; level <= RT_LOG_DEBUG; ++level)
        {
            filter->log(level, "engine diagnostic", filter->log_user);
        }

        return open(filter);
    };
    ASSERT_EQ(ebpf_whodata_healthcheck(), 0);
    EXPECT_EQ(levels, (std::vector<modules_log_level_t> {LOG_ERROR, LOG_WARNING, LOG_INFO, LOG_DEBUG_VERBOSE}));
    shutdown_requested = true;
    EXPECT_EQ(ebpf_whodata(), 0);
}

TEST_F(EbpfWhodataTest, QueuedProbeRecordCannotSatisfyNextAction)
{
    rt_engine_api.poll = [](rt_handle_t, rt_sink_fn sink, void* ctx, int timeout)
    {
        if (timeout == 0)
        {
            rt_file_event stale {};
            strcpy(stale.filename, "/tmp/p4-ebpf-hc");
            stale.event_type = RT_EV_FILE_OPEN;
            sink(&stale, ctx);
        }
        else
        {
            fake_time += 5;
        }
        return 0;
    };
    EXPECT_EQ(ebpf_whodata_healthcheck(), 1);
    EXPECT_EQ(closes, 1);
    EXPECT_EQ(access("/tmp/p4-ebpf-hc", F_OK), -1);
}
