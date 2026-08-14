/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * Component test for the VD feed offset IPC round-trip (issue #38204).
 * Modeled directly on test_task_registry_ipc_component.cpp -- see that
 * file's banner for the general rationale; this one calls out only what
 * differs.
 *
 * What is REAL here (unmodified production code, statically linked, no
 * mocks/fakes/wraps for any of it):
 *   - vd_offset_client.c's vd_offset_client_observe()/
 *     vd_offset_client_clear_pending(): open a real AF_UNIX socket to
 *     WM_LOCAL_SOCK and speak the real wire protocol.
 *   - wmcom_dispatch()/wm_module_query()/wm_find_module() (wazuh_modules/
 *     src/wmcom.c, wmodules.c): the real generic per-module query chain,
 *     unmodified.
 *   - wm_agent_info_query() (wazuh_modules/src/wm_agent_info.c): the real
 *     query handler, unmodified, including the new vd_offset_observe/
 *     vd_offset_clear_pending/vd_offset_get_state branches.
 *   - agent_info_vd_offset_observe()/clear_pending()/get_state() (wazuh_modules/
 *     agent_info/src/agent_info.cpp, linked from the real libagent_info.so):
 *     the real wiring, unmodified. As in the task_registry component test,
 *     the dlopen()+dlsym() step itself is not under test -- this test wires
 *     the same function pointers directly to the statically-linked symbols.
 *   - AgentInfoImpl::observeVdFeedOffset()/clearVdRescanPending()/
 *     getVdFeedState() (agent_info_impl.cpp): the real `vd_feed_state` table
 *     in a REAL SQLite-backed agent_info.db -- unlike the mocked-DBSync unit
 *     tests (agent_info_vd_offset_test.cpp), this is the first place the
 *     actual persistence (DBSyncTxn write + re-read) is exercised end to end.
 *
 * What is test harness (authored here, not production code):
 *   - The accept() loop and the `wmodules` linked-list stub, identical in
 *     spirit to the task registry component test.
 *   - A queryModuleFunction standing in for agent-info's cross-module query
 *     seam (agent_info_set_query_module_function): answers
 *     get_vd_first_sync_completed for "syscollector" with a test-controlled
 *     flag, the same seam production wires to a real cross-module IPC this
 *     test does not exercise (consistent with the task registry test also
 *     stubbing this same seam with an unconditional -1).
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
#include "vd_offset_client.h"
#include "wmodules.h"
#include "wm_agent_info.h"
#include "agent_info.h"
#include "cJSON.h"

/* wm_agent_info.c's real VD offset function pointer slots (populated via
 * dlopen/dlsym in production). Re-declared here to wire them directly to the
 * real, statically-linked agent_info_vd_offset_* functions, same trick the
 * task registry component test uses for its own function pointer. */
extern agent_info_vd_offset_observe_func agent_info_vd_offset_observe_ptr;
extern agent_info_vd_offset_clear_pending_func agent_info_vd_offset_clear_pending_ptr;
extern agent_info_vd_offset_get_state_func agent_info_vd_offset_get_state_ptr;
}

namespace
{
    constexpr uint32_t MAX_ENTRIES = 100;
    constexpr uint32_t TTL_SECONDS = 3600;

    /// Server-side loop standing in for wmcom_main()'s accept loop, identical to
    /// the task registry component test's own.
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

    void testLogCallback(modules_log_level_t level, const char* msg, const char* tag)
    {
        if (level == LOG_ERROR || level == LOG_WARNING)
        {
            fprintf(stderr, "[%s] %s\n", tag ? tag : "agent-info", msg ? msg : "");
        }
    }

    /// Stands in for agent-info's cross-module query seam. Answers
    /// get_vd_first_sync_completed for "syscollector" with a test-controlled
    /// flag (see setVdFirstSyncDone()); anything else fails, matching the task
    /// registry component test's own unconditional -1 for this same seam.
    std::atomic<bool> g_vdFirstSyncDone {true};

    int testQueryModuleCallback(const char* moduleName, const char* query, char** response)
    {
        if (!response)
        {
            return -1;
        }

        *response = nullptr;

        if (!moduleName || std::string(moduleName) != "syscollector")
        {
            return -1;
        }

        cJSON* request = cJSON_Parse(query);

        if (!request)
        {
            return -1;
        }

        cJSON* commandItem = cJSON_GetObjectItem(request, "command");
        const bool isVdFirstQuery = commandItem && cJSON_IsString(commandItem) &&
                                    strcmp(commandItem->valuestring, "get_vd_first_sync_completed") == 0;
        cJSON_Delete(request);

        if (!isVdFirstQuery)
        {
            return -1;
        }

        cJSON* responseJson = cJSON_CreateObject();
        cJSON_AddNumberToObject(responseJson, "error", 0);
        cJSON* data = cJSON_CreateObject();
        cJSON_AddNumberToObject(data, "vd_first_sync_completed", g_vdFirstSyncDone.load() ? 1 : 0);
        cJSON_AddItemToObject(responseJson, "data", data);
        char* dumped = cJSON_PrintUnformatted(responseJson);
        *response = strdup(dumped);
        free(dumped);
        cJSON_Delete(responseJson);
        return 0;
    }

    class VdOffsetIpcComponentTest : public ::testing::Test
    {
        protected:
            void SetUp() override
            {
                g_vdFirstSyncDone = true;

                m_scratchDir = ::testing::TempDir() + "vd_offset_ipc_" +
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

                agent_info_set_log_function(testLogCallback);
                agent_info_set_query_module_function(testQueryModuleCallback);

                agent_info_task_registry_init(MAX_ENTRIES, TTL_SECONDS);
                agent_info_vd_offset_observe_ptr = agent_info_vd_offset_observe;
                agent_info_vd_offset_clear_pending_ptr = agent_info_vd_offset_clear_pending;
                agent_info_vd_offset_get_state_ptr = agent_info_vd_offset_get_state;
            }

            void TearDown() override
            {
                agent_info_cleanup();
                agent_info_vd_offset_observe_ptr = nullptr;
                agent_info_vd_offset_clear_pending_ptr = nullptr;
                agent_info_vd_offset_get_state_ptr = nullptr;
                wmodules = nullptr;
            }

            static int mkdirHierarchy(const std::string& path)
            {
                std::string cmd = "mkdir -p '" + path + "'";
                return system(cmd.c_str());
            }

            /// Simulates a module-side restart: tears down and reconstructs
            /// AgentInfoImpl against the same backing agent_info.db file, exactly
            /// what a real modulesd restart does for durability purposes (the
            /// file survives, the DBSync connection/in-memory state does not).
            static void simulateModuleRestart()
            {
                agent_info_cleanup();
                agent_info_task_registry_init(MAX_ENTRIES, TTL_SECONDS);
                agent_info_vd_offset_observe_ptr = agent_info_vd_offset_observe;
                agent_info_vd_offset_clear_pending_ptr = agent_info_vd_offset_clear_pending;
                agent_info_vd_offset_get_state_ptr = agent_info_vd_offset_get_state;
            }

            wmodule m_module {};
            std::string m_scratchDir;
    };
} // namespace

TEST_F(VdOffsetIpcComponentTest, ObserveOverRealIpcPersistsOffsetAndMarksPendingWhenVDFirstDone)
{
    int serverSock = OS_BindUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
    ASSERT_GE(serverSock, 0);
    std::thread server(runModuleSideDispatchLoop, serverSock, /*requestCount=*/1);

    bool changed = false;
    bool pending = false;
    uint64_t pendingOffset = 0;
    ASSERT_TRUE(vd_offset_client_observe(100, &changed, &pending, &pendingOffset));
    server.join();

    EXPECT_TRUE(changed);
    EXPECT_TRUE(pending);
    EXPECT_EQ(100u, pendingOffset);
}

TEST_F(VdOffsetIpcComponentTest, ObserveOverRealIpcDoesNotMarkPendingWhenVDFirstNotDone)
{
    g_vdFirstSyncDone = false;

    int serverSock = OS_BindUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
    ASSERT_GE(serverSock, 0);
    std::thread server(runModuleSideDispatchLoop, serverSock, /*requestCount=*/1);

    bool changed = false;
    bool pending = true; // Deliberately wrong initial value: must be set to false.
    uint64_t pendingOffset = 999;
    ASSERT_TRUE(vd_offset_client_observe(50, &changed, &pending, &pendingOffset));
    server.join();

    EXPECT_TRUE(changed);
    EXPECT_FALSE(pending);
}

TEST_F(VdOffsetIpcComponentTest, MonotonicOffsetOverRealIpc)
{
    {
        int serverSock = OS_BindUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
        ASSERT_GE(serverSock, 0);
        std::thread server(runModuleSideDispatchLoop, serverSock, /*requestCount=*/1);
        bool changed = false;
        ASSERT_TRUE(vd_offset_client_observe(100, &changed, nullptr, nullptr));
        server.join();
        ASSERT_TRUE(changed);
    }

    {
        // A lower offset, over a fresh real round trip, must be a no-op: the
        // durable state (not an in-memory cache) is what enforces monotonicity.
        int serverSock = OS_BindUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
        ASSERT_GE(serverSock, 0);
        std::thread server(runModuleSideDispatchLoop, serverSock, /*requestCount=*/1);
        bool changed = true; // Deliberately wrong initial value: must become false.
        ASSERT_TRUE(vd_offset_client_observe(50, &changed, nullptr, nullptr));
        server.join();
        EXPECT_FALSE(changed);
    }
}

// A10: a pending re-scan request must survive a real module-side restart --
// the durable file is what makes it still pending, not any in-memory state.
TEST_F(VdOffsetIpcComponentTest, PendingRescanSurvivesARealRestartOfTheRegistry)
{
    {
        int serverSock = OS_BindUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
        ASSERT_GE(serverSock, 0);
        std::thread server(runModuleSideDispatchLoop, serverSock, /*requestCount=*/1);
        bool pending = false;
        ASSERT_TRUE(vd_offset_client_observe(100, nullptr, &pending, nullptr));
        server.join();
        ASSERT_TRUE(pending);
    }

    simulateModuleRestart();

    {
        int serverSock = OS_BindUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
        ASSERT_GE(serverSock, 0);
        std::thread server(runModuleSideDispatchLoop, serverSock, /*requestCount=*/1);

        // Re-observing the SAME offset post-restart takes the no-op path (not
        // newer), which still must report the persisted pending state -- this
        // is exactly how a real agentd resumes an outstanding request after its
        // own restart, with no separate recovery call needed (see
        // maybeRequestVdRescan's contract in controlStream.cpp).
        bool changed = true; // Deliberately wrong: must become false (no-op).
        bool pending = false;
        uint64_t pendingOffset = 0;
        ASSERT_TRUE(vd_offset_client_observe(100, &changed, &pending, &pendingOffset));
        server.join();

        EXPECT_FALSE(changed);
        EXPECT_TRUE(pending);
        EXPECT_EQ(100u, pendingOffset);
    }
}

TEST_F(VdOffsetIpcComponentTest, ClearPendingOverRealIpcClearsOnlyMatchingOffset)
{
    {
        int serverSock = OS_BindUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
        ASSERT_GE(serverSock, 0);
        std::thread server(runModuleSideDispatchLoop, serverSock, /*requestCount=*/1);
        bool pending = false;
        ASSERT_TRUE(vd_offset_client_observe(100, nullptr, &pending, nullptr));
        server.join();
        ASSERT_TRUE(pending);
    }

    {
        // A mismatched offset must be a no-op: the pending flag stays set.
        int serverSock = OS_BindUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
        ASSERT_GE(serverSock, 0);
        std::thread server(runModuleSideDispatchLoop, serverSock, /*requestCount=*/1);
        EXPECT_FALSE(vd_offset_client_clear_pending(50));
        server.join();
    }

    {
        int serverSock = OS_BindUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
        ASSERT_GE(serverSock, 0);
        std::thread server(runModuleSideDispatchLoop, serverSock, /*requestCount=*/1);
        EXPECT_TRUE(vd_offset_client_clear_pending(100));
        server.join();
    }

    {
        int serverSock = OS_BindUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
        ASSERT_GE(serverSock, 0);
        std::thread server(runModuleSideDispatchLoop, serverSock, /*requestCount=*/1);
        bool pending = true; // Deliberately wrong: must become false.
        ASSERT_TRUE(vd_offset_client_observe(100, nullptr, &pending, nullptr));
        server.join();
        EXPECT_FALSE(pending);
    }
}
