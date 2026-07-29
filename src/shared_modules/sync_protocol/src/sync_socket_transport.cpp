/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "sync_socket_transport.hpp"

#include <utility>

SyncSocketTransport::SyncSocketTransport(std::string socketPath, std::string moduleName, LoggerFunc logger)
    : m_socketPath(std::move(socketPath))
    , m_moduleName(std::move(moduleName))
    , m_logger(std::move(logger))
{
}

std::string SyncSocketTransport::frameSessionId(uint64_t session) const
{
    // "<module>-<session>": agentd routes the manager's answer back to the right
    // module on this prefix, so it never has to parse the session itself. Both
    // halves stay inside the agent's session-id charset (alphanumerics, '-',
    // '_', '.'), which is what keeps it safe to put in a request header.
    return m_moduleName + "-" + std::to_string(session);
}

#ifndef _WIN32

#include <array>
#include <cstring>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0 // macOS: SIGPIPE is ignored process-wide by the agent instead.
#endif

namespace
{
    constexpr std::array<uint8_t, 4> SYNC_FRAME_MAGIC {'W', 'Z', 'S', 'Y'};
    constexpr uint8_t SYNC_FRAME_ACCEPTED = 1;

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

    bool writeAll(int fd, const void* data, size_t length)
    {
        const auto* cursor = static_cast<const uint8_t*>(data);
        size_t remaining = length;

        while (remaining > 0)
        {
            const auto written = send(fd, cursor, remaining, MSG_NOSIGNAL);

            if (written <= 0)
            {
                return false;
            }

            cursor += written;
            remaining -= static_cast<size_t>(written);
        }

        return true;
    }

    void putLittleEndian(std::vector<uint8_t>& out, uint64_t value, int bytes)
    {
        for (int index = 0; index < bytes; index++)
        {
            out.push_back(static_cast<uint8_t>((value >> (index * 8)) & 0xff));
        }
    }
} // namespace

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
    const int fd = connectTo(m_socketPath);

    if (fd < 0)
    {
        m_logger(LOG_DEBUG, "Failed to connect to the sync intake socket " + m_socketPath + ".");
        return false;
    }

    const std::string sessionId = frameSessionId(session);

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
        uint8_t status = 0;
        ok = recv(fd, &status, sizeof(status), 0) == static_cast<ssize_t>(sizeof(status)) &&
             status == SYNC_FRAME_ACCEPTED;

        if (!ok)
        {
            m_logger(LOG_DEBUG,
                     "The agent refused sync session " + sessionId + "; it is still ours to retry.");
        }
    }

    close(fd);
    return ok;
}

#else // _WIN32 — modules run in-process, so there is no socket in the path.

bool SyncSocketTransport::checkStatus()
{
    return false;
}

bool SyncSocketTransport::sendSession(uint64_t, const std::vector<uint8_t>&)
{
    return false;
}

#endif // _WIN32
