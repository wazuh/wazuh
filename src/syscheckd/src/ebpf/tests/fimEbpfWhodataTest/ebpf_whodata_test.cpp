#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "ebpf_mock_utils.hpp"
#include "ebpf_whodata.h"
#include "bpf_helpers.h"

extern volatile bool event_received;
extern volatile bool ebpf_hc_created;
time_t fake_time_now = 0;
extern time_t (*w_time)(time_t*);

/*
 * #37396/#37533 cutover: these tests used to drive ebpf_whodata()/
 * ebpf_whodata_healthcheck() by mocking a dozen individual libbpf calls
 * through w_bpf_helpers_t. Both functions now only ever call three things —
 * rt_engine_api.open/poll/close — so that's all these mock.
 *
 * ebpf_whodata()'s engine handle (g_engine_handle) is a file-static in
 * ebpf_whodata.cpp, not exposed to tests directly — matching production's
 * own call order (run_check.c always runs the healthcheck before spawning
 * ebpf_whodata() as its own thread), tests that need a live handle call
 * ebpf_whodata_healthcheck() first to populate it, then call ebpf_whodata().
 *
 * That handle is only ever closed/reset inside ebpf_whodata()'s own exit
 * path — by design, so the same handle survives from healthcheck through
 * the main loop within one process. Left alone, that also means it survives
 * across test cases in this same process. TearDown() forces it closed after
 * every test (a throwaway ebpf_whodata() call whose shutdown check fires on
 * the very first iteration) so each test starts from a genuinely clean
 * slate — this was found the hard way: without it, a handle opened by an
 * earlier test silently satisfies a later test that means to exercise the
 * "no handle yet" path, and the later test's own poll mock (whatever it set)
 * combined with a never-firing shutdown mock can loop forever.
 */
class EbpfWhodataTest : public ::testing::Test
{
    protected:
        static void SetUpTestSuite()
        {
            MockFimebpf::mock_loggingFunction = mock_loggingFunction;
            MockFimebpf::mock_abspath = mock_abspath;
            MockFimebpf::mock_get_user = mock_get_user;
            MockFimebpf::mock_get_group = mock_get_group;
            MockFimebpf::mock_fim_conf = mock_fim_conf_success;
            MockFimebpf::SetMockFunctions();
        }

        void SetUp() override
        {
            event_received  = false;
            ebpf_hc_created = false;
            fake_time_now = 0;
            w_time = time;
            MockFimebpf::mock_loggingFunction = mock_loggingFunction;
            MockFimebpf::mock_abspath = mock_abspath;
            MockFimebpf::SetMockFunctions();

            rt_engine_api.open = mock_rt_open_success;
            rt_engine_api.poll = mock_rt_poll_success;
            rt_engine_api.close = mock_rt_close;
        }

        void TearDown() override
        {
            std::remove("/tmp/ebpf_hc");
            event_received = false;
            ebpf_hc_created = false;
            w_time = time;

            // Force any handle this test opened closed, so the next test
            // starts clean (see the class comment above).
            EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
            .WillRepeatedly(::testing::Return(true));
            rt_engine_api.poll = mock_rt_poll_success;
            ebpf_whodata();
        }
};

time_t mock_time(time_t* t)
{
    if (t)
    {
        *t = fake_time_now;
    }

    return fake_time_now;
}

TEST_F(EbpfWhodataTest, HealthcheckSuccess)
{
    rt_engine_api.poll = mock_rt_poll_healthcheck_success;

    EXPECT_FALSE(ebpf_whodata_healthcheck());
}

TEST_F(EbpfWhodataTest, HealthcheckEngineOpenFails)
{
    rt_engine_api.open = mock_rt_open_failure;

    EXPECT_TRUE(ebpf_whodata_healthcheck());
}

TEST_F(EbpfWhodataTest, HealthcheckTimeoutWhenNoEventArrives)
{
    event_received = false;
    w_time = mock_time;
    rt_engine_api.poll = [](rt_handle_t, rt_sink_fn, void*, int)
    {
        fake_time_now += 5;
        return 0;
    };

    EXPECT_TRUE(ebpf_whodata_healthcheck());
}

TEST_F(EbpfWhodataTest, WhodataFailsWithoutAPriorHealthcheck)
{
    // No call to ebpf_whodata_healthcheck() in this test, so the engine
    // handle ebpf_whodata() depends on was never populated.
    int result = ebpf_whodata();
    EXPECT_EQ(result, 1);
}

TEST_F(EbpfWhodataTest, SuccessfulRun)
{
    // mock_rt_poll_healthcheck_success actually fires the healthcheck sink
    // with a matching event — mock_rt_poll_success (SetUp()'s default)
    // never calls the sink at all, so the healthcheck's wait-for-event loop
    // would just spin for the real 10s timeout and report failure.
    rt_engine_api.poll = mock_rt_poll_healthcheck_success;
    ASSERT_FALSE(ebpf_whodata_healthcheck()); // populates the engine handle

    // No barrier needed here (unlike the pre-cutover version): ebpf_pop_events()
    // is a plain function ebpf_whodata() calls directly now, not a mockable
    // pointer — the spawned pop thread runs for real against an empty
    // kernelEventQueue in the background, which is harmless and detached.
    rt_engine_api.poll = mock_rt_poll_success;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
    .WillOnce(::testing::Return(false))
    .WillOnce(::testing::Return(true));

    int result = ebpf_whodata();
    EXPECT_EQ(result, 0);
}

TEST_F(EbpfWhodataTest, PollErrorStillReturnsZero)
{
    rt_engine_api.poll = mock_rt_poll_healthcheck_success;
    ASSERT_FALSE(ebpf_whodata_healthcheck()); // populates the engine handle

    rt_engine_api.poll = mock_rt_poll_failure;

    EXPECT_CALL(MockFimebpf::GetInstance(), mock_fim_shutdown_process_on())
    .WillOnce(::testing::Return(false));

    int result = ebpf_whodata();
    EXPECT_EQ(result, 0);
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
