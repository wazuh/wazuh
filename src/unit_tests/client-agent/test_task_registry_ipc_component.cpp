/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * Component test for the durable dedup + IPC round-trip.
 *
 * What is REAL here (unmodified production code, statically linked, no
 * mocks/fakes/wraps for any of it):
 *   - task_registry_client.c's task_registry_check_and_record(): opens a
 *     real AF_UNIX socket to WM_LOCAL_SOCK ("queue/sockets/wmodules",
 *     relative to CWD) and speaks the real wire protocol
 *     (OS_SendSecureTCP/OS_RecvSecureTCP framing).
 *   - wmcom_dispatch() (wazuh_modules/src/wmcom.c): the real "query "
 *     command parser, unmodified.
 *   - wm_module_query()/wm_find_module() (wazuh_modules/src/wmodules.c):
 *     the real generic per-module query dispatcher, unmodified. It walks
 *     the real `wmodules` linked list, which this test populates with one
 *     real wm_context (WM_AGENT_INFO_CONTEXT) -- this is the one piece that
 *     would otherwise come from XML config parsing at startup, which this
 *     test bypasses since it is not what this test is exercising.
 *   - wm_agent_info_query() (wazuh_modules/src/wm_agent_info.c): the real
 *     query handler, unmodified.
 *   - agent_info_task_check_and_record()/agent_info_task_registry_init()/
 *     agent_info_cleanup() (wazuh_modules/agent_info/src/agent_info.cpp,
 *     linked from the real libagent_info.so): the real dedup wiring,
 *     unmodified. In production these are reached through
 *     dlopen()+dlsym() (so_get_function_sym); this test links the same
 *     library directly and assigns the same function pointer
 *     (agent_info_task_check_and_record_ptr) wm_agent_info_query() already
 *     reads from -- the dlopen machinery itself is not under test here,
 *     only the query/dedup logic it wires up.
 *   - AgentInfoImpl::checkAndRecordTask()/cleanupExpiredTasks() (wazuh_modules/
 *     agent_info/agent_info_impl/src/agent_info_impl.cpp): the real `tasks`
 *     table in agent_info.db (the same DBSync-managed SQLite database
 *     agent_metadata/agent_groups live in), reached via
 *     agent_info_ensure_database() -- construction only, not the metadata
 *     sync loop agent_info_start() would otherwise block this test on.
 *
 * What is test harness (authored here, not production code):
 *   - The accept() loop that binds WM_LOCAL_SOCK and hands each connection
 *     to wmcom_dispatch(). Production's real loop is wmcom_main()
 *     (wazuh_modules/src/wmcom.c), which additionally chowns the socket to
 *     the wazuh group (OS_BindUnixDomainWithPerms) and runs until
 *     wm_shutdown_requested -- neither of which is relevant to the
 *     dedup/IPC logic under test, so this test uses a plain
 *     OS_BindUnixDomain() + a bounded accept loop instead.
 *   - Populating the `wmodules` linked list with one entry pointing at
 *     WM_AGENT_INFO_CONTEXT, standing in for wm_agent_info_read()'s real
 *     job of building that list from XML config at startup.
 *
 * This is single-process (both "client" and "module" run as threads in one
 * test binary, not two OS processes), so it is a strong step up from a pure
 * unit test of AgentInfoImpl's task methods in isolation, but it is NOT a
 * substitute for a genuine two-process/restart-the-real-modulesd-binary test
 * -- see the PR notes for why that harness was judged not worth building here.
 */

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

extern "C" {
#include "shared.h"
#include "os_net.h"
#include "task_registry_client.h"
#include "wmodules.h"
#include "wm_agent_info.h"
#include "agent_info.h"
#include "cJSON.h"

/* wm_agent_info.c's real dedup callback slot (populated via dlopen/dlsym in
 * production -- see so_get_function_sym(agent_info_module, ...) in
 * wm_agent_info_start()). Not declared in any header since only
 * wm_agent_info.c itself normally needs to see it; re-declared here to wire
 * it directly to the real, statically-linked agent_info_task_check_and_record()
 * without going through dlopen -- the dlopen step is deliberately not what
 * this test exercises (see file banner).
 */
extern agent_info_task_check_and_record_func agent_info_task_check_and_record_ptr;
}

namespace
{
    constexpr uint32_t MAX_ENTRIES = 100;
    constexpr uint32_t TTL_SECONDS = 3600;

    /// Server-side loop standing in for wmcom_main()'s accept loop (see file
    /// banner): binds the real WM_LOCAL_SOCK path and, for exactly
    /// `requestCount` connections, hands the raw bytes to the real
    /// wmcom_dispatch() -- unmodified production code all the way down to
    /// the real `tasks` table in agent_info.db.
    void runModuleSideDispatchLoop(int serverSock, int requestCount)
    {
        for (int i = 0; i < requestCount; i++)
        {
            int peer = accept(serverSock, nullptr, nullptr);
            if (peer < 0)
            {
                continue;
            }

            char buffer[OS_MAXSTR + 1] = {0};
            ssize_t len = OS_RecvSecureTCP(peer, buffer, OS_MAXSTR);

            if (len > 0)
            {
                buffer[len] = '\0';
                char* response = nullptr;
                size_t responseLen = wmcom_dispatch(buffer, static_cast<size_t>(len), &response);

                if (responseLen > 0 && response)
                {
                    OS_SendSecureTCP(peer, responseLen, response);
                }

                free(response);
            }

            close(peer);
        }

        close(serverSock);
    }

    /// Raw client round-trip, bypassing task_registry_client.c (which only
    /// ever builds "task_check_and_record" queries): opens the same real
    /// WM_LOCAL_SOCK, sends an arbitrary "query agent-info {...}" payload
    /// and returns whatever the real dispatch chain answers. Used to pin
    /// error-path envelopes (e.g. the unknown-command response) that the
    /// production client never triggers.
    std::string sendRawQuery(const std::string& query)
    {
        int sock = OS_ConnectUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
        if (sock < 0)
        {
            return "";
        }

        // Bounded, same as task_registry_client.c's own recv timeout: a real
        // blocking socket with no cap could hang this whole test binary
        // (rather than just failing this one test) if the dispatch chain
        // ever regressed into not responding.
        OS_SetRecvTimeout(sock, 5, 0);

        if (OS_SendSecureTCP(sock, query.size(), const_cast<char*>(query.c_str())) < 0)
        {
            close(sock);
            return "";
        }

        char buffer[OS_MAXSTR + 1] = {0};
        ssize_t len = OS_RecvSecureTCP(sock, buffer, OS_MAXSTR);
        close(sock);

        if (len <= 0)
        {
            return "";
        }

        buffer[len] = '\0';
        return std::string(buffer);
    }

    /// agent-info logs through a C callback; without one its own failures are
    /// silent, which is what hid this test's missing setup. Route it to stderr so
    /// a future breakage says why.
    void testLogCallback(modules_log_level_t level, const char* msg, const char* tag)
    {
        if (level == LOG_ERROR || level == LOG_WARNING)
        {
            fprintf(stderr, "[%s] %s\n", tag ? tag : "agent-info", msg ? msg : "");
        }
    }

    /// agent-info can query sibling modules; nothing in this test's path does, but
    /// the constructor requires the function to be present.
    int testQueryModuleCallback(const char*, const char*, char** response)
    {
        if (response)
        {
            *response = nullptr;
        }

        return -1;
    }

    class TaskRegistryIpcComponentTest : public ::testing::Test
    {
        protected:
            void SetUp() override
            {
                // Isolate this test's CWD: WM_LOCAL_SOCK ("queue/sockets/wmodules")
                // and agent_info.db's disk path ("queue/agent_info/db/agent_info.db")
                // are both relative, exactly as in production.
                m_scratchDir = ::testing::TempDir() + "task_registry_ipc_" +
                               ::testing::UnitTest::GetInstance()->current_test_info()->name();
                std::string rm = "rm -rf '" + m_scratchDir + "'";
                system(rm.c_str());
                ASSERT_EQ(0, mkdir(m_scratchDir.c_str(), 0755));
                ASSERT_EQ(0, chdir(m_scratchDir.c_str()));
                ASSERT_EQ(0, mkdirHierarchy("queue/sockets"));
                ASSERT_EQ(0, mkdirHierarchy("queue/agent_info/db"));

                m_module.thread = 0;
                m_module.context = &WM_AGENT_INFO_CONTEXT;
                m_module.tag = nullptr;
                m_module.data = nullptr;
                m_module.next = nullptr;
                wmodules = &m_module;

                // AgentInfoImpl's constructor requires both a log and a query-module
                // function and throws std::invalid_argument without them. It builds its
                // DBSync member first, so agent_info.db and its schema appear on disk
                // either way; the throw then leaves g_agent_info_impl null and
                // agent_info_ensure_database() reports it through the log callback that
                // is not set yet, so skipping these two reads as "the database is there
                // but every task query answers MQ_ERR_INTERNAL".
                agent_info_set_log_function(testLogCallback);
                agent_info_set_query_module_function(testQueryModuleCallback);

                // agent_info_task_registry_init() constructs agent_info.db as a side effect
                // (see its own comment) -- no separate agent_info_start()/blocking sync loop
                // needed just to exercise the task dedup path.
                agent_info_task_registry_init(MAX_ENTRIES, TTL_SECONDS);
                agent_info_task_check_and_record_ptr = agent_info_task_check_and_record;
            }

            void TearDown() override
            {
                agent_info_cleanup();
                agent_info_task_check_and_record_ptr = nullptr;
                wmodules = nullptr;
            }

            static int mkdirHierarchy(const std::string& path)
            {
                std::string cmd = "mkdir -p '" + path + "'";
                return system(cmd.c_str());
            }

            /// Simulates a module-side restart for durability purposes: tears down
            /// AgentInfoImpl (closing the DBSync connection) and reconstructs it
            /// against the same backing agent_info.db file, exactly what
            /// agent_info_cleanup() + a fresh agent_info_ensure_database() do across
            /// a real process restart (the file is what survives; the DBSync
            /// connection/in-memory state does not).
            static void simulateModuleRestart()
            {
                agent_info_cleanup();
                agent_info_task_registry_init(MAX_ENTRIES, TTL_SECONDS);
                agent_info_task_check_and_record_ptr = agent_info_task_check_and_record;
            }

            wmodule m_module {};
            std::string m_scratchDir;
    };
} // namespace

TEST_F(TaskRegistryIpcComponentTest, FirstDeliveryDispatchesSecondOverRealIpcIsDiscarded)
{
    int serverSock = OS_BindUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
    ASSERT_GE(serverSock, 0);

    std::thread server(runModuleSideDispatchLoop, serverSock, /*requestCount=*/2);

    // Real client -> real socket -> real wmcom_dispatch -> real
    // wm_agent_info_query -> real `tasks` table in agent_info.db, round-tripped
    // twice for the exact same task_id. task_registry_check_and_record() returns a
    // tri-state task_registry_result_t, not a bool -- compare explicitly rather
    // than relying on truthiness, since TASK_REGISTRY_RESULT_NEW is not guaranteed nonzero.
    EXPECT_EQ(task_registry_check_and_record("ipc-real-task-1"), TASK_REGISTRY_RESULT_NEW);
    EXPECT_EQ(task_registry_check_and_record("ipc-real-task-1"), TASK_REGISTRY_RESULT_DUPLICATE);

    server.join();
}

TEST_F(TaskRegistryIpcComponentTest, DuplicateSurvivesARealRestartOfTheRegistry)
{
    {
        int serverSock = OS_BindUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
        ASSERT_GE(serverSock, 0);
        std::thread server(runModuleSideDispatchLoop, serverSock, /*requestCount=*/1);
        EXPECT_EQ(task_registry_check_and_record("ipc-restart-task"), TASK_REGISTRY_RESULT_NEW);
        server.join();
    }

    // "Restart" the module side only: destroy and reconstruct the
    // AgentInfoImpl/DBSync connection backed by the very same agent_info.db
    // file on disk. No process is actually killed/recreated here (see file
    // banner) -- this is what a restart means for durability purposes: only
    // the file survives, the DBSync connection/in-memory state does not.
    simulateModuleRestart();

    {
        int serverSock = OS_BindUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
        ASSERT_GE(serverSock, 0);
        std::thread server(runModuleSideDispatchLoop, serverSock, /*requestCount=*/2);

        // Re-delivery of the SAME task_id after the "restart": the durable
        // file (not the in-memory map, which was just wiped) is what makes
        // this still a duplicate.
        EXPECT_EQ(task_registry_check_and_record("ipc-restart-task"), TASK_REGISTRY_RESULT_DUPLICATE);

        // A genuinely new task_id is still accepted post-restart: the
        // registry as a whole still works, this isn't fail-closed-forever.
        EXPECT_EQ(task_registry_check_and_record("ipc-restart-task-new"), TASK_REGISTRY_RESULT_NEW);

        server.join();
    }
}

// Pins wm_agent_info_query()'s unknown-command envelope against a real
// round trip: it must echo the offending command back under "data.command",
// the same shape SCA's and Syscollector's own query() unknown-command
// responses use (sca_impl.cpp/syscollectorImp.cpp:
// response["data"]["command"] = command). A reviewer comparing the three
// side by side should see the same envelope, not a bespoke one.
TEST_F(TaskRegistryIpcComponentTest, UnknownCommandEchoesCommandNameLikeScaAndSyscollector)
{
    int serverSock = OS_BindUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
    ASSERT_GE(serverSock, 0);
    std::thread server(runModuleSideDispatchLoop, serverSock, /*requestCount=*/1);

    std::string response = sendRawQuery("query agent-info {\"command\":\"bogus_command\"}");
    server.join();

    ASSERT_FALSE(response.empty());
    cJSON* parsed = cJSON_Parse(response.c_str());
    ASSERT_NE(nullptr, parsed);

    cJSON* error = cJSON_GetObjectItem(parsed, "error");
    ASSERT_NE(nullptr, error);
    EXPECT_EQ(1, error->valueint); // MQ_ERR_UNKNOWN_COMMAND

    cJSON* data = cJSON_GetObjectItem(parsed, "data");
    ASSERT_NE(nullptr, data);
    cJSON* command = cJSON_GetObjectItem(data, "command");
    ASSERT_NE(nullptr, command);
    EXPECT_STREQ("bogus_command", command->valuestring);

    cJSON_Delete(parsed);
}
