/**
 * @file reload_agent.cpp
 * @brief C++17 implementation of agent reload and remote config verification.
 *
 * Replaces reload_agent.c. Encapsulates reload logic in
 * AgentReloader and provides extern "C" trampolines.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#include "agent_reloader.hpp"

extern "C"
{
#include "sendmsg.h"

#include "localfile-config.h"
#include "rootcheck-config.h"
#include "syscheck-config.h"
#ifdef WIN32
#include "execd.h"
#endif
}

#include <cerrno>
#include <cstdio>
#include <cstring>

#ifndef WIN32
#include <unistd.h>
#endif

namespace agentd
{

    static const char AG_IN_RCON[] = "wazuh: Invalid remote configuration";

    // ── Singleton ────────────────────────────────────────────────────

    AgentReloader& AgentReloader::instance()
    {
        static AgentReloader inst;
        return inst;
    }

    // ── reload ───────────────────────────────────────────────────────

    void* AgentReloader::reload()
    {
        char req[] = "reload";

#ifndef WIN32

        auto length = static_cast<uint32_t>(strlen(req));

        int sock = -1;
        char sockname[PATH_MAX + 1] {};

        strcpy(sockname, COM_LOCAL_SOCK);

        if (sock = OS_ConnectUnixDomain(sockname, SOCK_STREAM, OS_MAXSTR), sock < 0)
        {
            switch (errno)
            {
                case ECONNREFUSED: merror("Could not auto-reload agent. Is Active Response enabled?"); break;
                default:
                    merror("At reloadAgent(): Could not connect to socket '%s': %s (%d).",
                           sockname,
                           strerror(errno),
                           errno);
                    break;
            }
        }
        else
        {
            if (OS_SendSecureTCP(sock, length, req))
            {
                merror("OS_SendSecureTCP(): %s", strerror(errno));
            }

            close(sock);
        }

#else

        char* output = nullptr;
        wcom_dispatch(req, &output);
        if (output)
            free(output);

#endif

        return nullptr;
    }

    // ── verifyRemoteConf ─────────────────────────────────────────────

    int AgentReloader::verifyRemoteConf()
    {
        const char* configPath = AGENTCONFIG;
        char msg_output[OS_MAXSTR] {};

        if (Test_Syscheck(configPath) < 0)
        {
            snprintf(msg_output, OS_MAXSTR, "%c:%s:%s: '%s'. ", LOCALFILE_MQ, "wazuh-agent", AG_IN_RCON, "syscheck");
            goto fail;
        }
        else if (Test_Rootcheck(configPath) < 0)
        {
            snprintf(msg_output, OS_MAXSTR, "%c:%s:%s: '%s'. ", LOCALFILE_MQ, "wazuh-agent", AG_IN_RCON, "rootcheck");
            goto fail;
        }
        else if (Test_Localfile(configPath) < 0)
        {
            snprintf(msg_output, OS_MAXSTR, "%c:%s:%s: '%s'. ", LOCALFILE_MQ, "wazuh-agent", AG_IN_RCON, "localfile");
            goto fail;
        }
        else if (Test_Client(configPath) < 0)
        {
            snprintf(msg_output, OS_MAXSTR, "%c:%s:%s: '%s'. ", LOCALFILE_MQ, "wazuh-agent", AG_IN_RCON, "client");
            goto fail;
        }
        else if (Test_ClientBuffer(configPath) < 0)
        {
            snprintf(
                msg_output, OS_MAXSTR, "%c:%s:%s: '%s'. ", LOCALFILE_MQ, "wazuh-agent", AG_IN_RCON, "client_buffer");
            goto fail;
        }
        else if (Test_WModule(configPath) < 0)
        {
            snprintf(msg_output, OS_MAXSTR, "%c:%s:%s: '%s'. ", LOCALFILE_MQ, "wazuh-agent", AG_IN_RCON, "wodle");
            goto fail;
        }
        else if (Test_Labels(configPath) < 0)
        {
            snprintf(msg_output, OS_MAXSTR, "%c:%s:%s: '%s'. ", LOCALFILE_MQ, "wazuh-agent", AG_IN_RCON, "labels");
            goto fail;
        }

        return 0;

    fail:
        mdebug2("Invalid remote configuration received");
        send_msg(msg_output, -1);
        return OS_INVALID;
    }

} // namespace agentd

// =====================================================================
//  extern "C" trampolines
// =====================================================================

extern "C"
{

    void* reloadAgent()
    {
        return agentd::AgentReloader::instance().reload();
    }

    int verifyRemoteConf()
    {
        return agentd::AgentReloader::instance().verifyRemoteConf();
    }

} // extern "C"
