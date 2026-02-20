/**
 * @file state.cpp
 * @brief C++17 implementation of agent state management.
 *
 * Replaces state.c with an AgentState class that uses std::mutex
 * instead of pthread_mutex_t.  Provides extern "C" trampolines
 * so that the preserved C headers (agentd.h, state.h) continue
 * to expose the original API.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#include "agent_state.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>

// ── Singleton ────────────────────────────────────────────────────────

namespace agentd
{

    AgentState& AgentState::instance()
    {
        static AgentState inst;
        return inst;
    }

    // ── Initialisation ───────────────────────────────────────────────────

    void AgentState::init()
    {
        interval_ = getDefine_Int("agent", "state_interval", 0, 86400);
    }

    // ── Main loop (runs in its own thread) ───────────────────────────────

    void AgentState::run()
    {
        if (interval_ == 0)
        {
            minfo("State file is disabled.");
            return;
        }

        mdebug1("State file updating thread started.");

        while (true)
        {
            writeFile();
            std::this_thread::sleep_for(std::chrono::seconds(interval_));
        }
    }

    // ── State updates ────────────────────────────────────────────────────

    void AgentState::update(w_agentd_state_update_t type, void* data)
    {
        std::lock_guard<std::mutex> lock(mutex_);

        switch (type)
        {
            case UPDATE_STATUS: state_.status = static_cast<agent_status_t>(reinterpret_cast<intptr_t>(data)); break;
            case UPDATE_KEEPALIVE:
                if (data != nullptr)
                {
                    state_.last_keepalive = *static_cast<time_t*>(data);
                }
                break;
            case UPDATE_ACK:
                if (data != nullptr)
                {
                    state_.last_ack = *static_cast<time_t*>(data);
                }
                break;
            case INCREMENT_MSG_COUNT: state_.msg_count++; break;
            case INCREMENT_MSG_SEND: state_.msg_sent++; break;
            case RESET_MSG_COUNT_ON_SHRINK:
                if (data != nullptr)
                {
                    state_.msg_count = *static_cast<unsigned int*>(data);
                }
                break;
            default: break;
        }
    }

    // ── JSON snapshot ────────────────────────────────────────────────────

    char* AgentState::getJson()
    {
        std::string last_keepalive_str;
        std::string last_ack_str;
        unsigned int count {};
        unsigned int sent {};
        const char* status {};

        {
            std::lock_guard<std::mutex> lock(mutex_);
            status = statusToString(state_.status);
            last_keepalive_str = formatTime(state_.last_keepalive);
            last_ack_str = formatTime(state_.last_ack);
            count = state_.msg_count;
            sent = state_.msg_sent;
        }

        int buffered_event = w_agentd_get_buffer_lenght();
        bool buffer_enable = true;
        if (buffered_event < 0)
        {
            buffer_enable = false;
            buffered_event = 0;
        }

        // Build JSON response
        auto json_retval = make_cjson(cJSON_CreateObject());
        cJSON* data = cJSON_CreateObject();

        cJSON_AddNumberToObject(json_retval.get(), W_AGENTD_JSON_ERROR, 0);
        cJSON_AddItemToObject(json_retval.get(), W_AGENTD_JSON_DATA, data); // ownership transferred

        cJSON_AddStringToObject(data, W_AGENTD_FIELD_STATUS, status);
        cJSON_AddStringToObject(data, W_AGENTD_FIELD_KEEP_ALIVE, last_keepalive_str.c_str());
        cJSON_AddStringToObject(data, W_AGENTD_FIELD_LAST_ACK, last_ack_str.c_str());
        cJSON_AddNumberToObject(data, W_AGENTD_FIELD_MSG_COUNT, count);
        cJSON_AddNumberToObject(data, W_AGENTD_FIELD_MSG_SENT, sent);
        cJSON_AddNumberToObject(data, W_AGENTD_FIELD_MSG_BUFF, buffered_event);
        cJSON_AddBoolToObject(data, W_AGENTD_FIELD_EN_BUFF, buffer_enable);

        return cJSON_PrintUnformatted(json_retval.get()); // caller frees with free()
    }

    // ── State-file writer ────────────────────────────────────────────────

    int AgentState::writeFile()
    {
        if (std::strcmp(__local_name, "unset") == 0)
        {
            merror("At write_state(): __local_name is unset.");
            return -1;
        }

        mdebug2("Updating state file.");

        int buffered_event = w_agentd_get_buffer_lenght();

        // Snapshot under lock
        std::string last_keepalive_str;
        std::string last_ack_str;
        const char* status {};
        unsigned int msg_count {};
        unsigned int msg_sent {};

        {
            std::lock_guard<std::mutex> lock(mutex_);
            status = statusToString(state_.status);
            last_keepalive_str = formatTime(state_.last_keepalive);
            last_ack_str = formatTime(state_.last_ack);
            msg_count = state_.msg_count;
            msg_sent = state_.msg_sent;
        }

        // Write file (platform-specific)
#ifdef WIN32
        char path[PATH_MAX - 8];
        snprintf(path, sizeof(path), "%s.state", __local_name);

        FILE* fp = wfopen(path, "w");
        if (!fp)
        {
            merror(FOPEN_ERROR, path, errno, strerror(errno));
            return -1;
        }
#else
        char path[PATH_MAX - 8];
        char path_temp[PATH_MAX + 1];
        snprintf(path, sizeof(path), OS_PIDFILE "/%s.state", __local_name);
        snprintf(path_temp, sizeof(path_temp), "%s.temp", path);

        FILE* fp = wfopen(path_temp, "w");
        if (!fp)
        {
            merror(FOPEN_ERROR, path_temp, errno, strerror(errno));
            return -1;
        }
#endif

        fprintf(fp,
                "# State file for %s\n"
                "\n"
                "# Agent status:\n"
                "# - pending:      waiting to get connected.\n"
                "# - connected:    connection established with manager in the last %d seconds.\n"
                "# - disconnected: connection lost or no ACK received in the last %d seconds.\n" W_AGENTD_FIELD_STATUS
                "='%s'\n"
                "\n"
                "# Last time a keepalive was sent\n" W_AGENTD_FIELD_KEEP_ALIVE "='%s'\n"
                "\n"
                "# Last time a control message was received\n" W_AGENTD_FIELD_LAST_ACK "='%s'\n"
                "\n"
                "# Number of generated events\n" W_AGENTD_FIELD_MSG_COUNT "='%u'\n"
                "\n"
                "# Number of messages (events + control messages) sent to the manager\n" W_AGENTD_FIELD_MSG_SENT
                "='%u'\n"
                "\n"
                "# Number of events currently buffered\n"
                "# Empty if anti-flooding mechanism is disabled\n",
                __local_name,
                agt->notify_time,
                agt->max_time_reconnect_try,
                status,
                last_keepalive_str.c_str(),
                last_ack_str.c_str(),
                msg_count,
                msg_sent);

        if (buffered_event >= 0)
        {
            fprintf(fp, W_AGENTD_FIELD_MSG_BUFF "='%d'\n", buffered_event);
        }
        else
        {
            fprintf(fp, W_AGENTD_FIELD_MSG_BUFF "=''\n");
        }

        fclose(fp);

#ifndef WIN32
        if (rename(path_temp, path) < 0)
        {
            merror("Renaming %s to %s: %s", path_temp, path, strerror(errno));
            if (unlink(path_temp) < 0)
            {
                merror("Deleting %s: %s", path_temp, strerror(errno));
            }
            return -1;
        }
#endif

        return 0;
    }

    // ── Helpers (private, static) ────────────────────────────────────────

    std::string AgentState::formatTime(std::time_t t)
    {
        if (t == 0)
        {
            return {};
        }
        struct tm tm {};
        localtime_r(&t, &tm);
        char buf[W_AGENTD_STATE_TIME_LENGHT] {};
        strftime(buf, sizeof(buf), W_AGENTD_STATE_TIME_FORMAT, &tm);
        return buf;
    }

    const char* AgentState::statusToString(agent_status_t status)
    {
        switch (status)
        {
            case GA_STATUS_PENDING: return "pending";
            case GA_STATUS_ACTIVE: return "connected";
            case GA_STATUS_NACTIVE: return "disconnected";
            default: merror("At get_str_status(): Unknown status (%d)", static_cast<int>(status)); return "unknown";
        }
    }

} // namespace agentd

// =====================================================================
//  extern "C" trampolines
// =====================================================================

extern "C"
{

    /** Global required by state.h. */
    int interval;

    void w_agentd_state_init()
    {
        auto& s = agentd::AgentState::instance();
        s.init();
        interval = s.getInterval();
    }

#ifdef WIN32
    DWORD WINAPI state_main(__attribute__((unused)) LPVOID arg)
    {
        agentd::AgentState::instance().run();
        return 0;
    }
#else
    void* state_main(__attribute__((unused)) void* args)
    {
        agentd::AgentState::instance().run();
        return nullptr;
    }
#endif

    void w_agentd_state_update(w_agentd_state_update_t type, void* data)
    {
        agentd::AgentState::instance().update(type, data);
    }

    char* w_agentd_state_get()
    {
        return agentd::AgentState::instance().getJson();
    }

} // extern "C"
