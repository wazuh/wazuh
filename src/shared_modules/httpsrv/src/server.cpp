/*
 * Wazuh shared modules
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "server.hpp"

#include <cerrno>
#include <cstring>
#include <pthread.h>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>

#include "loggerHelper.h"

constexpr auto WM_HTTPSRV_LOGTAG = "httpsrv";

namespace httpsrv
{

    Server::Server(const std::string& id, size_t payloadMaxBytes, bool enableDetailedLogging)
        : m_srv(std::make_shared<httplib::Server>())
        , m_id(id)
        , m_socketPath()
        , m_payloadMaxBytes(payloadMaxBytes)
        , m_enableDetailedLogging(enableDetailedLogging)
    {
        const auto excptFnName = "Server::Server(" + id + ")::set_exception_handler";
        m_srv->set_exception_handler(
            [id, excptFnName](const auto&, auto& res, std::exception_ptr ep)
            {
                try
                {
                    std::rethrow_exception(ep);
                }
                catch (std::exception& e)
                {
                    logError(
                        WM_HTTPSRV_LOGTAG, "[%s] uncaught route handler exception: %s.", excptFnName.c_str(), e.what());
                }
                catch (...)
                {
                    logError(WM_HTTPSRV_LOGTAG, "[%s] uncaught route handler unknown exception.", excptFnName.c_str());
                }

                res.status = httplib::StatusCode::InternalServerError_500;
                res.set_content("Internal server error", "text/plain");
            });

        applyPayloadLimit();

        m_srv->set_error_handler(
            [this](const httplib::Request&, httplib::Response& res) -> httplib::Server::HandlerResponse
            {
                if (res.status == httplib::StatusCode::PayloadTooLarge_413)
                {
                    if (!res.body.empty())
                    {
                        return httplib::Server::HandlerResponse::Unhandled;
                    }

                    const auto maxBytes = m_payloadMaxBytes;
                    if (maxBytes == 0)
                    {
                        res.set_content("Payload too large.", "text/plain");
                    }
                    else
                    {
                        const auto msg = "Payload too large. Max allowed: " + std::to_string(maxBytes) + " bytes (" +
                                         std::to_string(maxBytes / 1024) + " KiB).";
                        res.set_content(msg, "text/plain");
                    }
                    return httplib::Server::HandlerResponse::Handled;
                }
                return httplib::Server::HandlerResponse::Unhandled;
            });

        if (m_enableDetailedLogging)
        {
            m_srv->set_logger(
                [id](const auto& req, const auto& res)
                {
                    auto truncateBody = [](const std::string& body, size_t maxLen = 1024) -> std::string
                    {
                        if (body.size() <= maxLen)
                            return body;
                        return body.substr(0, maxLen) + "...";
                    };

                    logDebug2(WM_HTTPSRV_LOGTAG,
                              "Request: %s %s '%s' - Response: %d '%s'.",
                              req.method.c_str(),
                              req.path.c_str(),
                              truncateBody(req.body).c_str(),
                              res.status,
                              res.body.c_str());
                });
        }
        else
        {
            m_srv->set_logger([id](const auto& /*req*/, const auto& /*res*/)
                              { logDebug2(WM_HTTPSRV_LOGTAG, "[Server] %s request received.", id.c_str()); });
        }
    }

    void Server::addRoute(Method method,
                          const std::string& route,
                          const std::function<void(const httplib::Request&, httplib::Response&)>& handler)
    {
        std::function<void(const httplib::Request&, httplib::Response&)> wrapped;

        if (m_enableDetailedLogging)
        {
            wrapped = [this, handler](const httplib::Request& req, httplib::Response& res)
            {
                logDebug2(
                    WM_HTTPSRV_LOGTAG, "Request: %s %s '%s'.", req.method.c_str(), req.path.c_str(), req.body.c_str());
                handler(req, res);
            };
        }
        else
        {
            wrapped = handler;
        }

        try
        {
            switch (method)
            {
                case Method::GET: m_srv->Get(route, wrapped); break;
                case Method::POST: m_srv->Post(route, wrapped); break;
                case Method::PUT: m_srv->Put(route, wrapped); break;
                case Method::DELETE: m_srv->Delete(route, wrapped); break;
                default: throw std::runtime_error("Invalid method");
            }
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error("[Server] " + m_id + " failed to add route: " + e.what());
        }

        logDebug1(
            WM_HTTPSRV_LOGTAG, "[Server] %s added route: %s %s.", m_id.c_str(), methodToStr(method), route.c_str());
    }

    void Server::applyPayloadLimit()
    {
        const auto maxLen = (m_payloadMaxBytes == 0) ? std::numeric_limits<size_t>::max() : m_payloadMaxBytes;
        m_srv->set_payload_max_length(maxLen);
    }

    bool Server::bindAndListen()
    {
        if (m_socketPath.empty())
        {
            logError(WM_HTTPSRV_LOGTAG, "[Server] %s cannot bind and listen: empty socket path.", m_id.c_str());
            return false;
        }

        if (!m_srv->bind_to_port(m_socketPath.string(), 80))
        {
            logError(WM_HTTPSRV_LOGTAG, "[Server] %s failed to bind to socket %s.", m_id.c_str(), m_socketPath.c_str());
            return false;
        }

        if (chmod(m_socketPath.c_str(), 0660) != 0)
        {
            logWarn(WM_HTTPSRV_LOGTAG,
                    "[Server] %s failed to change socket permissions: %s (%d).",
                    m_id.c_str(),
                    std::strerror(errno),
                    errno);
        }
        else
        {
            logDebug2(WM_HTTPSRV_LOGTAG,
                      "[Server] %s changed socket permissions to 660 for %s.",
                      m_id.c_str(),
                      m_socketPath.c_str());
        }

        logDebug1(WM_HTTPSRV_LOGTAG, "[Server] %s bound to socket %s.", m_id.c_str(), m_socketPath.c_str());

        return m_srv->listen_after_bind();
    }

    void Server::start(const std::filesystem::path& socketPath, bool useThread)
    {
        if (socketPath.empty())
        {
            throw std::runtime_error("Cannot start server " + m_id + ": empty socket path");
        }

        if (isRunning())
        {
            throw std::runtime_error("Cannot start server " + m_id + ": already running");
        }

        if (!std::filesystem::exists(socketPath.parent_path()))
        {
            throw std::runtime_error("Cannot start server " + m_id + ": parent directory " +
                                     socketPath.parent_path().string() + " does not exist");
        }

        m_srv->set_address_family(AF_UNIX);

        if (std::filesystem::exists(socketPath.string()))
        {
            std::filesystem::remove(socketPath);
            logDebug2(
                WM_HTTPSRV_LOGTAG, "[Server] %s removed existing socket file %s.", m_id.c_str(), socketPath.c_str());
        }
        m_socketPath = socketPath;

        if (useThread)
        {
            auto threadFailed = std::make_shared<std::atomic<bool>>(false);

            m_thread = std::thread(
                [this, threadFailed]()
                {
#if defined(__linux__)
                    pthread_setname_np(pthread_self(), m_id.substr(0, 15).c_str());
#elif defined(__APPLE__)
                    pthread_setname_np(m_id.substr(0, 63).c_str());
#endif
                    if (!bindAndListen())
                    {
                        threadFailed->store(true, std::memory_order_release);
                    }
                });

            const auto timeout = std::chrono::steady_clock::now() + std::chrono::seconds(10);

            while (!threadFailed->load(std::memory_order_acquire) && std::chrono::steady_clock::now() < timeout)
            {
                if (m_srv->is_running())
                {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            if (threadFailed->load(std::memory_order_acquire))
            {
                if (m_thread.joinable())
                {
                    m_thread.join();
                }
                throw std::runtime_error("[Server] " + m_id + " failed to start at " + socketPath.string());
            }

            if (!m_srv->is_running())
            {
                if (m_thread.joinable())
                {
                    m_thread.join();
                }
                throw std::runtime_error("[Server] " + m_id + " timed out waiting to start at " + socketPath.string());
            }

            std::stringstream ss;
            ss << m_thread.get_id();
            logDebug1(WM_HTTPSRV_LOGTAG,
                      "[Server] %s started in thread %s at %s.",
                      m_id.c_str(),
                      ss.str().c_str(),
                      socketPath.c_str());
        }
        else
        {
            logInfo(WM_HTTPSRV_LOGTAG, "[Server] Starting %s at %s.", m_id.c_str(), socketPath.c_str());
            if (!bindAndListen())
            {
                throw std::runtime_error("[Server] " + m_id + " failed to start at " + socketPath.string());
            }
        }
    }

    void Server::stop() noexcept
    {
        try
        {
            if (isRunning())
            {
                m_srv->stop();
            }

            if (m_thread.joinable())
            {
                m_thread.join();
            }

            if (!m_socketPath.empty())
            {
                std::filesystem::remove(m_socketPath);
                logDebug2(WM_HTTPSRV_LOGTAG, "[Server] %s removed socket file %s.", m_id.c_str(), m_socketPath.c_str());
                m_socketPath.clear();
            }

            logInfo(WM_HTTPSRV_LOGTAG, "[Server] %s stopped.", m_id.c_str());
        }
        catch (const std::exception& e)
        {
            logError(WM_HTTPSRV_LOGTAG, "[Server] %s error while stopping: %s.", m_id.c_str(), e.what());
        }
    }

} // namespace httpsrv
