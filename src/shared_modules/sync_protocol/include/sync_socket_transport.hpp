/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#pragma once

#include "agent_sync_protocol_c_interface_types.h" // asp_sync_session_sender_fn
#include "agent_sync_protocol_types.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

/// @brief Registers the in-process sender used by SyncSocketTransport's Windows stub (see the
/// class doc below) to hand a session directly to https_client, bypassing the local socket that
/// has no listener there. NULL deregisters. No-op on platforms where SyncSocketTransport uses a
/// real socket (POSIX) -- exists there only so asp_set_session_sender(), a single cross-platform
/// C ABI symbol, links on every platform. Process-global to match this library's
/// one-instance-per-process reality.
void setInProcessSyncSessionSender(asp_sync_session_sender_fn sender);

/**
 * @brief What AgentSyncProtocol needs from whatever carries a session.
 *
 * Injected so tests can drive a session without a socket, the same way the
 * persistent queue already is.
 */
class ISyncSessionTransport
{
    public:
        virtual ~ISyncSessionTransport() = default;

        /// @brief Whether the transport can carry a session right now.
        virtual bool checkStatus() = 0;

        /// @brief Hands one whole session over. True only once the far side
        ///        confirms it took it.
        virtual bool sendSession(uint64_t session, const std::vector<uint8_t>& message) = 0;
};

/**
 * @brief Sends a whole synchronization session over the agent's local STREAM
 *        socket (`queue-sync`), which the HTTPS client's intake binds.
 *
 * This is the transport that makes FullSession worth having. The DGRAM queue
 * the sessions used to ride is bounded by OS_MAXSTR (65536), which is the only
 * reason a session was ever split into ~60 KB batches; a STREAM socket has no
 * such bound, so one session is one write.
 *
 * The frame is the same `WZSY` layout the intake reads (sync_session_wire.hpp,
 * the one definition both ends include), and the intake answers with one
 * status byte. That byte is the only thing that makes the return value honest:
 * without it a full queue on the other side looks exactly like a successful
 * send.
 *
 * Note this reports whether the AGENT took the session, not whether the
 * manager accepted it. The manager's verdict arrives asynchronously on the
 * HTTPS response and is routed separately.
 *
 * POSIX only for the socket itself: the Windows agent runs its modules
 * in-process, so there is no socket to connect to there. On Windows this
 * class instead hands the session to whatever sender is registered via
 * setInProcessSyncSessionSender() (https_client's own bridge, while it is
 * running) -- checkStatus()/sendSession() honestly report "not available"
 * when nothing is registered yet, same as a down socket would on POSIX.
 */
class SyncSocketTransport final : public ISyncSessionTransport
{
    public:
        /// @param socketPath The agent's queue-sync intake socket.
        /// @param moduleName Prefixed onto the frame's session id, which is how
        ///        agentd knows which module's *com socket the manager's answer
        ///        belongs to - it never parses the session itself.
        /// @param logger Logger function.
        /// @param ioTimeout Bound on each socket send/receive, so a wedged
        ///        intake fails the attempt instead of hanging the sync worker
        ///        forever. The default is generous because the intake spools
        ///        the whole body to disk before it answers.
        SyncSocketTransport(std::string socketPath, std::string moduleName, LoggerFunc logger,
                            std::chrono::milliseconds ioTimeout = std::chrono::seconds {60});

        /// @brief Whether the intake socket is reachable.
        bool checkStatus() override;

        /// @brief Streams one whole session across and waits for the intake's
        ///        status byte.
        /// @param session Session id; also becomes the frame's id, in decimal.
        /// @param message The serialized FullSession message.
        /// @return True only once the agent confirms it queued the session.
        bool sendSession(uint64_t session, const std::vector<uint8_t>& message) override;

        /// @brief The id put on the wire for a session: "<module>-<session>".
        ///        Kept public so the response router can be tested against the
        ///        exact string the producer sends.
        std::string frameSessionId(uint64_t session) const;

    private:
        std::string m_socketPath;
        std::string m_moduleName;
        LoggerFunc m_logger;
        std::chrono::milliseconds m_ioTimeout;
};
