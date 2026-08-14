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

#include "syncIntake.hpp"

#include "syncFrame.hpp"

#include <utility>

SyncIntake::SyncIntake(std::string socketPath, std::string spoolDir, SessionSink sink)
    : m_socketPath(std::move(socketPath))
    , m_spoolDir(std::move(spoolDir))
    , m_sink(std::move(sink))
{
}

SyncIntake::~SyncIntake()
{
    stop();
}

#ifndef _WIN32

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0 // macOS: SIGPIPE is ignored process-wide by the agent instead.
#endif

namespace
{
    /// How long a half-sent session may go quiet before the connection is
    /// dropped. A producer streaming a session keeps data flowing, so this only
    /// fires on one that died mid-frame; it exists so a single stalled peer
    /// cannot pin the acceptor thread against every other producer.
    constexpr int PEER_IDLE_TIMEOUT_MS = 30 * 1000;

    void closeFd(int& fd)
    {
        if (fd >= 0)
        {
            close(fd);
            fd = -1;
        }
    }

    /// sun_path is a fixed 108-byte field with no way to signal truncation, so
    /// an over-long path has to be refused rather than silently shortened.
    bool fitsInSunPath(const std::string& path)
    {
        return !path.empty() && path.size() < sizeof(sockaddr_un::sun_path);
    }

    /// Waits for data on peerFd while watching stopFd, then reads once. Returns
    /// a transport error (<0) when the stop is signalled or the peer goes quiet,
    /// so a producer that stalls mid-frame can never pin the thread that stop()
    /// joins. stopFd stays readable once written (it is never drained), so every
    /// subsequent read of the same connection short-circuits here too.
    long readWatchingStop(int peerFd, int stopFd, void* buffer, size_t n)
    {
        while (true)
        {
            std::array<pollfd, 2> fds {{{peerFd, POLLIN, 0}, {stopFd, POLLIN, 0}}};
            const int ready = poll(fds.data(), fds.size(), PEER_IDLE_TIMEOUT_MS);

            if (ready < 0)
            {
                if (errno == EINTR)
                {
                    continue; // LCOV_EXCL_LINE: signal race, just re-poll.
                }

                return -1; // LCOV_EXCL_LINE
            }

            if (ready == 0 || (fds[1].revents & POLLIN) != 0)
            {
                return -1; // Idle for too long, or stopping.
            }

            return static_cast<long>(recv(peerFd, buffer, n, 0));
        }
    }

    /// Streams the framed session on peerFd into a fresh temp file. Returns the
    /// spool path (and fills id/size) on success, or an empty string.
    std::string spoolConnection(int peerFd, int stopFd, const std::string& spoolDir,
                                std::string& sessionId, uint64_t& size)
    {
        std::string tmpl = spoolDir + "/hc_sync_intake_XXXXXX";
        const int fd = mkstemp(tmpl.data());

        if (fd < 0)
        {
            return {};
        }

        std::FILE* out = fdopen(fd, "wb");

        if (out == nullptr)
        {
            close(fd);
            unlink(tmpl.c_str());
            return {};
        }

        const auto read = [peerFd, stopFd](void* buffer, size_t n) -> long
        {
            return readWatchingStop(peerFd, stopFd, buffer, n);
        };
        const SyncFrameResult result = readSyncSessionFrame(read, out, sessionId, size);
        // The last buffered bytes are only written at close, so a full disk can
        // still fail here after every fwrite() reported success. Promoting the
        // spool without checking would ship a truncated session.
        const bool flushed = fclose(out) == 0;

        if (result != SyncFrameResult::Ok || !flushed)
        {
            unlink(tmpl.c_str());
            return {};
        }

        return tmpl;
    }
} // namespace

bool SyncIntake::start()
{
    if (m_running)
    {
        return true;
    }

    if (!fitsInSunPath(m_socketPath))
    {
        // Binding the truncated path while unlink() targets the full one would
        // leave a stale socket behind and make the next start fail on EADDRINUSE.
        return false;
    }

    if (pipe(m_stopPipe) != 0)
    {
        return false; // LCOV_EXCL_LINE: pipe() failure is not reproducible in tests.
    }

    m_listenFd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (m_listenFd < 0)
    {
        closeFd(m_stopPipe[0]); // LCOV_EXCL_LINE
        closeFd(m_stopPipe[1]); // LCOV_EXCL_LINE
        return false;           // LCOV_EXCL_LINE
    }

    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, m_socketPath.c_str(), sizeof(addr.sun_path) - 1);
    unlink(m_socketPath.c_str());

    if (bind(m_listenFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
            listen(m_listenFd, 16) != 0)
    {
        closeFd(m_listenFd);
        closeFd(m_stopPipe[0]);
        closeFd(m_stopPipe[1]);
        return false;
    }

    m_running = true;
    m_thread = std::thread(&SyncIntake::acceptLoop, this);
    return true;
}

void SyncIntake::stop()
{
    if (!m_running.exchange(false))
    {
        return;
    }

    const char wake = 'x';
    (void)!write(m_stopPipe[1], &wake, 1); // Wake poll(); ignore the result.

    if (m_thread.joinable())
    {
        m_thread.join();
    }

    closeFd(m_listenFd);
    closeFd(m_stopPipe[0]);
    closeFd(m_stopPipe[1]);
    unlink(m_socketPath.c_str());
}

void SyncIntake::acceptLoop()
{
    while (m_running)
    {
        std::array<pollfd, 2> fds {{{m_listenFd, POLLIN, 0}, {m_stopPipe[0], POLLIN, 0}}};

        if (poll(fds.data(), fds.size(), -1) < 0)
        {
            continue; // LCOV_EXCL_LINE: EINTR/spurious — just re-poll.
        }

        if ((fds[1].revents & POLLIN) != 0)
        {
            break; // Stop requested.
        }

        if ((fds[0].revents & POLLIN) == 0)
        {
            continue; // LCOV_EXCL_LINE
        }

        const int peer = accept(m_listenFd, nullptr, nullptr);

        if (peer < 0)
        {
            continue; // LCOV_EXCL_LINE
        }

        handleConnection(peer);
        close(peer);
    }
}

void SyncIntake::handleConnection(int peerFd)
{
    std::string sessionId;
    uint64_t size = 0;
    const std::string path = spoolConnection(peerFd, m_stopPipe[0], m_spoolDir, sessionId, size);
    const bool accepted = !path.empty() && m_sink && m_sink(sessionId, path, size);

    // Tell the producer what happened to it. A refused session is still theirs,
    // so silence here would read as a successful hand-off.
    const auto write = [peerFd](const void* buffer, size_t n) -> long
    {
        return static_cast<long>(send(peerFd, buffer, n, MSG_NOSIGNAL));
    };
    (void)writeSyncSessionAck(write, accepted);
}

bool sendSyncSession(const std::string& socketPath, const std::string& sessionId,
                     const uint8_t* body, size_t length)
{
    if (!fitsInSunPath(socketPath))
    {
        return false; // A truncated path would connect somewhere else, or nowhere.
    }

    const int fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd < 0)
    {
        return false; // LCOV_EXCL_LINE
    }

    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, socketPath.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        close(fd);
        return false;
    }

    // Bound the wait for the status byte: the intake is single-threaded, so it
    // may still be streaming another producer's session, but it must never pin
    // this one indefinitely.
    timeval timeout {};
    timeout.tv_sec = PEER_IDLE_TIMEOUT_MS / 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    const auto write = [fd](const void* buffer, size_t n) -> long
    {
        return static_cast<long>(send(fd, buffer, n, MSG_NOSIGNAL));
    };
    const auto read = [fd](void* buffer, size_t n) -> long
    {
        return static_cast<long>(recv(fd, buffer, n, 0));
    };
    // Only report success once the agent says it took the session.
    const bool ok = writeSyncSessionFrame(write, sessionId, body, length) &&
                    readSyncSessionAck(read);
    close(fd);
    return ok;
}

#else // _WIN32 — the Windows agent runs modules in-process; no local socket intake.

bool SyncIntake::start()
{
    return false;
}

void SyncIntake::stop()
{
}

void SyncIntake::acceptLoop()
{
}

void SyncIntake::handleConnection(int)
{
}

bool sendSyncSession(const std::string&, const std::string&, const uint8_t*, size_t)
{
    return false;
}

#endif // _WIN32
