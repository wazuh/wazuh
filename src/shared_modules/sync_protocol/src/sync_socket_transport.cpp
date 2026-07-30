/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "sync_socket_transport.hpp"

#include "sync_session_wire.hpp"

#include <utility>

SyncSocketTransport::SyncSocketTransport(std::string socketPath, std::string moduleName, LoggerFunc logger,
                                         std::chrono::milliseconds ioTimeout)
    : m_socketPath(std::move(socketPath))
    , m_moduleName(std::move(moduleName))
    , m_logger(std::move(logger))
    , m_ioTimeout(ioTimeout)
{
}

std::string SyncSocketTransport::frameSessionId(uint64_t session) const
{
    // "<module>-<session>": agentd routes the manager's answer back to the right
    // module on this prefix, so it never has to parse the session itself. Both
    // halves must stay inside the wire's session-id charset, which is what keeps
    // the id safe to put in a request header; sendSession() enforces it.
    return m_moduleName + "-" + std::to_string(session);
}

#ifndef _WIN32

#include <cerrno>
#include <cstring>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0 // macOS: SIGPIPE is ignored process-wide by the agent instead.
#endif

namespace
{
    /// sun_path is a fixed field with no way to report truncation, so an
    /// over-long path has to be refused rather than silently shortened.
    bool fitsInSunPath(const std::string& path)
    {
        return !path.empty() && path.size() < sizeof(sockaddr_un::sun_path);
    }

    int connectTo(const std::string& path)
    {
        if (!fitsInSunPath(path))
        {
            return -1;
        }

        const int fd = socket(AF_UNIX, SOCK_STREAM, 0);

        if (fd < 0)
        {
            return -1;
        }

        sockaddr_un addr {};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

        if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
        {
            close(fd);
            return -1;
        }

        return fd;
    }

    /// Bounds every send/recv on the socket so a wedged intake turns into a
    /// failed attempt (the sync worker retries) instead of an eternal hang.
    bool boundSocketIo(int fd, std::chrono::milliseconds timeout)
    {
        timeval bound {};
        bound.tv_sec = static_cast<time_t>(timeout.count() / 1000);
        bound.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);

        return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &bound, sizeof(bound)) == 0 &&
               setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &bound, sizeof(bound)) == 0;
    }

    bool writeAll(int fd, const void* data, size_t length)
    {
        const auto* cursor = static_cast<const uint8_t*>(data);
        size_t remaining = length;

        while (remaining > 0)
        {
            const auto written = send(fd, cursor, remaining, MSG_NOSIGNAL);

            if (written < 0 && errno == EINTR)
            {
                continue; // A signal is not a transport failure.
            }

            if (written <= 0)
            {
                return false;
            }

            cursor += written;
            remaining -= static_cast<size_t>(written);
        }

        return true;
    }

    bool readStatusByte(int fd, uint8_t& status)
    {
        while (true)
        {
            const auto got = recv(fd, &status, sizeof(status), 0);

            if (got < 0 && errno == EINTR)
            {
                continue;
            }

            return got == static_cast<ssize_t>(sizeof(status));
        }
    }

    void putLittleEndian(std::vector<uint8_t>& out, uint64_t value, int bytes)
    {
        for (int index = 0; index < bytes; index++)
        {
            out.push_back(static_cast<uint8_t>((value >> (index * 8)) & 0xff));
        }
    }
} // namespace

void setInProcessSyncSessionSender(asp_sync_session_sender_fn)
{
    // No-op here: POSIX uses the real AF_UNIX socket above. Exists so
    // asp_set_session_sender() -- one C ABI symbol shared by every platform -- links everywhere.
}

bool SyncSocketTransport::checkStatus()
{
    const int fd = connectTo(m_socketPath);

    if (fd < 0)
    {
        m_logger(LOG_DEBUG, "Sync intake socket " + m_socketPath + " is not available.");
        return false;
    }

    close(fd);
    return true;
}

bool SyncSocketTransport::sendSession(uint64_t session, const std::vector<uint8_t>& message)
{
    const std::string sessionId = frameSessionId(session);

    // The intake rejects an out-of-contract id after reading the whole frame;
    // checking here fails fast and names the culprit. Only a bad module name
    // can trip this, since the session half is always decimal.
    if (!isValidSessionId(sessionId))
    {
        m_logger(LOG_ERROR, "Sync session id '" + sessionId + "' violates the wire contract.");
        return false;
    }

    const int fd = connectTo(m_socketPath);

    if (fd < 0)
    {
        m_logger(LOG_DEBUG, "Failed to connect to the sync intake socket " + m_socketPath + ".");
        return false;
    }

    if (!boundSocketIo(fd, m_ioTimeout))
    {
        m_logger(LOG_DEBUG, "Failed to bound I/O on the sync intake socket " + m_socketPath + ".");
        close(fd);
        return false;
    }

    std::vector<uint8_t> header;
    header.reserve(SYNC_FRAME_MAGIC.size() + 4 + sessionId.size() + 8);
    header.insert(header.end(), SYNC_FRAME_MAGIC.begin(), SYNC_FRAME_MAGIC.end());
    putLittleEndian(header, sessionId.size(), 4);
    header.insert(header.end(), sessionId.begin(), sessionId.end());
    putLittleEndian(header, message.size(), 8);

    bool ok = writeAll(fd, header.data(), header.size()) &&
              (message.empty() || writeAll(fd, message.data(), message.size()));

    if (ok)
    {
        // The status byte is what makes this return value honest: the agent may
        // have taken the bytes and still refused the session (a full queue), and
        // silence would read as success.
        uint8_t status = SYNC_FRAME_REFUSED;
        ok = readStatusByte(fd, status) && status == SYNC_FRAME_ACCEPTED;

        if (!ok)
        {
            m_logger(LOG_DEBUG,
                     "The agent refused sync session " + sessionId + "; it is still ours to retry.");
        }
    }

    close(fd);
    return ok;
}

#else // _WIN32 — modules run in-process; sessions go to an in-process sender instead of a
// socket that would never have a listener (see the class doc above).

#include <atomic>

namespace
{
    // Process-global: this library is one instance per process on Windows, shared by every
    // module (agent-info, SCA, syscollector, FIM) -- there is only ever one https_client to
    // reach, so one slot is enough. Unregistered (nullptr) before https_client has started, or
    // once it is stopping; both read as an honest "not available" below, same as the POSIX
    // socket being down.
    std::atomic<asp_sync_session_sender_fn> g_sessionSender {nullptr};
}

void setInProcessSyncSessionSender(asp_sync_session_sender_fn sender)
{
    g_sessionSender.store(sender);
}

bool SyncSocketTransport::checkStatus()
{
    return g_sessionSender.load() != nullptr;
}

bool SyncSocketTransport::sendSession(uint64_t session, const std::vector<uint8_t>& message)
{
    const auto sender = g_sessionSender.load();

    if (!sender)
    {
        m_logger(LOG_DEBUG, "No in-process sync session sender registered (https_client not running?).");
        return false;
    }

    const std::string sessionId = frameSessionId(session);
    return sender(sessionId.c_str(), message.data(), message.size());
}

#endif // _WIN32
