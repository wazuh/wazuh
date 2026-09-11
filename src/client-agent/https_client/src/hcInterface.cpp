/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * The C ABI of the HTTPS client. This file is the entire C<->C++ boundary,
 * the same contract shape remoted_module uses on the manager side: the C
 * caller includes only include/https_client.h, and every exported function
 * catches all exceptions so nothing ever throws into C.
 */

#include "https_client.h"
#include "httpsClientFacade.hpp"
#include "syncIntake.hpp"

#include "curlHandle.hpp"
#include "curlPerformer.hpp"
#include "enrollClient.hpp"
#include "moduleConfig.hpp"
#include "moduleLog.hpp"
#include "sysSeams.hpp"

#include <cstring>
#include <string>

namespace Log
{
    // Single definition of the DSO-global log sink used by loggerHelper.h.
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
    GLOBAL_LOG_FUNCTION;
} // namespace Log

struct hc_handle
{
    HttpsClientFacade impl;

    hc_handle(const hc_config_t& config, const hc_callbacks_t& callbacks)
        : impl(config, callbacks)
    {
    }
};

namespace
{
    // Route the module's LOGFN_* calls back through the agent's logger.
    void assignModuleLogSink(full_log_fnc_t callbackLog)
    {
        Log::assignLogFunction(
            [callbackLog](const int level,
                          const char* tag,
                          const char* file,
                          const int line,
                          const char* func,
                          const char* logMessage,
                          va_list args)
        {
            if (callbackLog)
            {
                callbackLog(level, tag, file, line, func, logMessage, args);
            }
        });
    }

    // Fixed-size C buffers are not guaranteed NUL-terminated when the caller
    // filled them completely; bound every read (same idiom as
    // moduleConfig.cpp's boundedString()).
    std::string boundedField(const char* field, size_t capacity)
    {
        return std::string(field, strnlen(field, capacity));
    }
} // namespace

extern "C"
{

    hc_handle* hc_create(const hc_config_t* config, const hc_callbacks_t* callbacks)
    {
        if (config == nullptr || callbacks == nullptr)
        {
            return nullptr;
        }

        try
        {
            assignModuleLogSink(callbacks->log);
            return new hc_handle(*config, *callbacks);
        }
        catch (...)
        {
            return nullptr; // LCOV_EXCL_LINE: only reachable on allocation failure.
        }
    }

    bool hc_start(hc_handle* handle)
    {
        if (handle == nullptr)
        {
            return false;
        }

        try
        {
            return handle->impl.start();
        }
        catch (...)
        {
            return false; // LCOV_EXCL_LINE: nothing throws into C.
        }
    }

    void hc_stop(hc_handle* handle)
    {
        if (handle == nullptr)
        {
            return;
        }

        try
        {
            handle->impl.stop();
        }
        catch (...)
        {
            // LCOV_EXCL_LINE: nothing throws into C.
        }
    }

    void hc_destroy(hc_handle* handle)
    {
        try
        {
            delete handle; // Destructor stops the client first.
        }
        catch (...)
        {
            // LCOV_EXCL_LINE: nothing throws into C.
        }
    }

    bool hc_submit_event(hc_handle* handle, const uint8_t* frame, size_t length)
    {
        if (handle == nullptr)
        {
            return false;
        }

        try
        {
            return handle->impl.submitEvent(frame, length);
        }
        catch (...)
        {
            return false; // LCOV_EXCL_LINE: nothing throws into C.
        }
    }

    bool hc_submit_sync_session(hc_handle* handle, const char* session_id, const uint8_t* buffer,
                                size_t length)
    {
        if (handle == nullptr)
        {
            return false;
        }

        try
        {
            return handle->impl.submitSyncSession(session_id, buffer, length);
        }
        catch (...)
        {
            return false; // LCOV_EXCL_LINE: nothing throws into C.
        }
    }

    bool hc_submit_sync_session_file(hc_handle* handle, const char* session_id, const char* file_path,
                                     uint64_t size)
    {
        if (handle == nullptr)
        {
            return false;
        }

        try
        {
            return handle->impl.submitSyncSessionFile(session_id, file_path, size);
        }
        catch (...)
        {
            return false; // LCOV_EXCL_LINE: nothing throws into C.
        }
    }

    bool hc_send_sync_session(const char* socket_path, const char* session_id, const uint8_t* body,
                              size_t length)
    {
        if (socket_path == nullptr || session_id == nullptr)
        {
            return false;
        }

        try
        {
            return sendSyncSession(socket_path, session_id, body, length);
        }
        catch (...)
        {
            return false; // LCOV_EXCL_LINE: nothing throws into C.
        }
    }

    void hc_notify_now(hc_handle* handle)
    {
        if (handle == nullptr)
        {
            return;
        }

        try
        {
            handle->impl.notifyNow();
        }
        catch (...)
        {
            // LCOV_EXCL_LINE: nothing throws into C.
        }
    }

    bool hc_set_config_hash(hc_handle* handle, const char* config_hash)
    {
        if (handle == nullptr || config_hash == nullptr)
        {
            return false;
        }

        try
        {
            handle->impl.setConfigHash(config_hash);
            return true;
        }
        catch (...)
        {
            return false; // LCOV_EXCL_LINE: nothing throws into C.
        }
    }

    bool hc_set_agent_identity(hc_handle* handle, const char* agent_id, const char* key_hex)
    {
        if (handle == nullptr)
        {
            return false;
        }

        try
        {
            return handle->impl.setAgentIdentity(agent_id, key_hex);
        }
        catch (...)
        {
            return false; // LCOV_EXCL_LINE: nothing throws into C.
        }
    }

    int hc_get_state(const hc_handle* handle)
    {
        if (handle == nullptr)
        {
            return HC_STATE_STOPPED;
        }

        try
        {
            return handle->impl.state();
        }
        catch (...)
        {
            return HC_STATE_STOPPED; // LCOV_EXCL_LINE: nothing throws into C.
        }
    }

    bool hc_enroll(const hc_config_t* config, const hc_enroll_request_t* request,
                   hc_enroll_result_t* result)
    {
        if (config == nullptr || request == nullptr || result == nullptr)
        {
            return false;
        }

        // Zeroed before anything that could throw: a caller reading *result
        // after a false return (e.g. an exception below) must never see
        // uninitialized memory. http_code stays 0, correctly signaling
        // "nothing was sent" either way.
        *result = {};

        try
        {
            // hc_enroll() may run before hc_create() ever does (first-boot
            // enrollment has no handle yet), so it cannot rely on a sink
            // already being assigned -- it assigns its own, exactly like
            // hc_create() does for the handle-based path.
            assignModuleLogSink(request->log);

            const auto typedConfig = ModuleConfig::fromC(*config);
            FsProbe fsProbe;
            // SkewCorrectedClock, not a bare SystemClock: EnrollClient's own
            // 401 grace-retry (#38440, extended to /enroll) calls
            // correctToServerTime() on a skewed clock reading, which is a
            // silent no-op on SystemClock. This instance is local to one
            // hc_enroll() call (no handle/facade exists yet on first boot to
            // share one with), so it does not persist a learned correction
            // past this call -- a re-enroll that hits skew again just pays
            // one extra round trip to relearn it, same one-shot-retry cost as
            // every other 401 here.
            SystemClock systemClock;
            SkewCorrectedClock clock {systemClock};
            CurlPerformer performer(typedConfig, defaultCurlHandleFactory());
            EnrollClient client(typedConfig, performer, fsProbe, clock, HTTPS_CLIENT_LOGTAG);

            const std::string bodyJson = boundedField(request->body_json, sizeof(request->body_json));
            const std::string password = boundedField(request->password, sizeof(request->password));
            const HttpResponse response = client.enroll(bodyJson, password);

            result->http_code = response.httpCode;
            result->retry_after_seconds = response.retryAfterSeconds;
            std::strncpy(result->body, response.body.c_str(), sizeof(result->body) - 1);
            std::strncpy(result->transport_error, response.curlError.c_str(),
                         sizeof(result->transport_error) - 1);

            return response.httpCode != 0;
        }
        catch (...)
        {
            return false; // LCOV_EXCL_LINE: nothing throws into C.
        }
    }

} /* extern "C" */
