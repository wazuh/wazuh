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

#ifndef _HC_SYNC_INTAKE_HPP
#define _HC_SYNC_INTAKE_HPP

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

/**
 * @brief The stateful sync intake: a STREAM Unix-socket listener that receives
 *        whole sync sessions from local producers, bypassing the 64 KB DGRAM
 *        cap of the legacy event queue. This is the second, separate queue for
 *        stateful traffic — stateless events keep using the DGRAM queue.
 *
 * Each accepted connection carries one framed session (see syncFrame.hpp); the
 * body is streamed straight into a temp spool file (never held in memory), and
 * the session is handed to the injected sink as (id, spool_path, size). The
 * sink owns the spool file thereafter (the stateful stream deletes it once
 * sent, or immediately if it cannot take it). Whatever the sink answers is
 * relayed to the producer as the frame's status byte, so a session that could
 * not be queued is not mistaken for a delivered one.
 *
 * Unix-only: the Windows agent runs its modules in-process, so it has no local
 * socket intake. On Windows start() is a no-op that returns false.
 */
class SyncIntake final
{
    public:
        /// Returns true when the session was taken; false makes the intake
        /// refuse it to the producer, which then still owns the session.
        using SessionSink =
            std::function<bool(const std::string& sessionId, const std::string& spoolPath, uint64_t size)>;

        SyncIntake(std::string socketPath, std::string spoolDir, SessionSink sink);
        ~SyncIntake();

        SyncIntake(const SyncIntake&) = delete;
        SyncIntake& operator=(const SyncIntake&) = delete;

        /// Bind + listen on the socket and spawn the acceptor thread. Returns
        /// false when the socket cannot be created (or on Windows).
        bool start();

        /// Stop the acceptor thread, close and unlink the socket. Idempotent.
        void stop();

    private:
        void acceptLoop();
        void handleConnection(int peerFd);

        std::string m_socketPath;
        std::string m_spoolDir;
        SessionSink m_sink;
        int m_listenFd {-1};
        int m_stopPipe[2] {-1, -1};
        std::thread m_thread;
        std::atomic<bool> m_running {false};
};

/**
 * @brief Producer-side helper: connect to the sync intake socket and stream a
 *        whole session (framed). Returns false on connect/write failure.
 *        (This is the API the modulesd agent_sync_protocol transport will call
 *        in place of chunked DGRAM sends; used here by tests and the demo.)
 */
bool sendSyncSession(const std::string& socketPath, const std::string& sessionId,
                     const uint8_t* body, size_t length);

#endif // _HC_SYNC_INTAKE_HPP
