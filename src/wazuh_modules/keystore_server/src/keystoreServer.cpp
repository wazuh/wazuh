/*
 * Wazuh keystore server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "keystore_server.h"

#include "keyStore.hpp"
#include "loggerHelper.h"
#include "socketServer.hpp"

#include <json.hpp>

#include <cstdarg>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

// Log::GLOBAL_LOG_FUNCTION is deliberately NOT defined here: the statically linked keystore
// library already defines it, and this module routes its own logging through that same symbol.

namespace
{
    constexpr auto KEYSTORE_SERVER_LOGTAG {"wazuh-manager-modulesd:keystore-server"};
    constexpr auto KEYSTORE_SOCKET_PATH {"queue/sockets/keystore"};

    const LogFn& logFn()
    {
        static const LogFn instance {KEYSTORE_SERVER_LOGTAG};
        return instance;
    }

    using KeystoreSocketServer = SocketServer<Socket<OSPrimitives, SizeHeaderProtocol>, EpollWrapper>;

    std::mutex gLifecycleMutex;
    std::unique_ptr<KeystoreSocketServer> gServer;

    /**
     * The request handler, MOVED VERBATIM from the legacy inventory_sync facade
     * (now deleted). The pipe protocol -- `GET|cf|key`, `PUT|cf|key|value`,
     * `DELETE|cf|key` (a DELETE is a PUT of empty) answered with
     * `{"status","operation","columnFamily","key"[,"value"]}` -- is a live contract with the
     * Python framework's KeystoreClient (framework/wazuh/core/indexer/credential_manager.py), so
     * nothing about it may change here. That includes the oddest corner: a GET whose value is
     * empty/absent answers the literal "wazuh-manager" -- deliberately preserved, not fixed.
     */
    void handleRequest(KeystoreSocketServer* server, const int fd, const char* body, const uint32_t bodySize)
    {
        std::string_view queryView(body, bodySize);
        nlohmann::json result;

        try
        {
            size_t pos1 = queryView.find('|');
            size_t pos2 = queryView.find('|', pos1 + 1);
            size_t pos3 = queryView.find('|', pos2 + 1);

            if (pos1 == std::string_view::npos || pos2 == std::string_view::npos)
            {
                throw std::runtime_error("Invalid query format");
            }

            auto queryOp = queryView.substr(0, pos1);
            auto queryCf = queryView.substr(pos1 + 1, pos2 - pos1 - 1);
            auto key = (pos3 == std::string_view::npos) ? queryView.substr(pos2 + 1)
                                                        : queryView.substr(pos2 + 1, pos3 - pos2 - 1);
            auto val = (pos3 == std::string_view::npos) ? std::string_view() : queryView.substr(pos3 + 1);

            if (queryOp == "GET")
            {
                std::string value;
                Keystore::get(std::string(queryCf), std::string(key), value);
                result["status"] = "ok";
                result["operation"] = "get";
                result["columnFamily"] = queryCf;
                result["key"] = key;
                if (!value.empty())
                {
                    result["value"] = value;
                }
                else
                {
                    result["value"] = "wazuh-manager";
                }
            }
            else if (queryOp == "PUT")
            {
                Keystore::put(std::string(queryCf), std::string(key), std::string(val));
                result["status"] = "ok";
                result["operation"] = "put";
                result["columnFamily"] = queryCf;
                result["key"] = key;
            }
            else if (queryOp == "DELETE")
            {
                Keystore::put(std::string(queryCf), std::string(key), "");
                result["status"] = "ok";
                result["operation"] = "delete";
                result["columnFamily"] = queryCf;
                result["key"] = key;
            }
            else
            {
                result["status"] = "error";
                result["message"] = "Unknown operation";
            }
        }
        catch (const std::exception& e)
        {
            result["status"] = "error";
            result["message"] = e.what();
        }

        auto response = result.dump();
        server->send(fd, response.c_str(), response.size());
    }
} // namespace

#ifdef __cplusplus
extern "C"
{
#endif

    int keystore_server_start(full_log_fnc_t callbackLog, const char* socketPath)
    {
        std::lock_guard<std::mutex> lock(gLifecycleMutex);

        if (callbackLog)
        {
            Log::assignLogFunction([callbackLog](const int level,
                                                 const char* tag,
                                                 const char* file,
                                                 const int line,
                                                 const char* func,
                                                 const char* message,
                                                 va_list args)
                                   { callbackLog(level, tag, file, line, func, message, args); });
        }

        if (gServer)
        {
            LOGFN_WARN(logFn(), "keystore server already started, ignoring start request.");
            return 0;
        }

        const std::string path = socketPath ? socketPath : KEYSTORE_SOCKET_PATH;

        try
        {
            gServer = std::make_unique<KeystoreSocketServer>(path);
            gServer->listen([server = gServer.get()](
                                const int fd, const char* body, const uint32_t bodySize, const char*, const uint32_t)
                            { handleRequest(server, fd, body, bodySize); });
        }
        catch (const std::exception& e)
        {
            LOGFN_ERROR(logFn(), "The keystore server could not bind '%s': %s.", path.c_str(), e.what());
            gServer.reset();
            return -1;
        }

        LOGFN_INFO(logFn(), "keystore server listening on '%s'.", path.c_str());
        return 0;
    }

    void keystore_server_stop(void)
    {
        std::lock_guard<std::mutex> lock(gLifecycleMutex);

        if (!gServer)
        {
            return;
        }

        // The SocketServer's destructor stops its epoll loop and closes the socket -- the same
        // one-line teardown the legacy facade used.
        gServer.reset();
        LOGFN_INFO(logFn(), "keystore server stopped.");
    }

#ifdef __cplusplus
}
#endif
