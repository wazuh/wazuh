/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#pragma once

#include "agent_sync_protocol_types.hpp"

#include <cstdint>
#include <string>
#include <vector>

/**
 * @brief Sends a whole synchronization session over the agent's local STREAM
 *        socket (`queue-sync`), which the HTTPS client's intake binds.
 *
 * This is the transport that makes FullSession worth having. The DGRAM queue
 * behind MQueueTransport is bounded by OS_MAXSTR (65536), which is the only
 * reason a session was ever split into ~60 KB batches; a STREAM socket has no
 * such bound, so one session is one write.
 *
 * The frame is the same `WZSY` layout the intake reads:
 *   [magic "WZSY"][id_len u32][id][body_len u64][body]
 * and the intake answers with one status byte. That byte is the only thing
 * that makes the return value honest: without it a full queue on the other
 * side looks exactly like a successful send.
 *
 * Note this reports whether the AGENT took the session, not whether the
 * manager accepted it. The manager's verdict arrives asynchronously on the
 * HTTPS response and is routed separately.
 *
 * Unix-only: the Windows agent runs its modules in-process, so there is no
 * socket in the path and sendSession() always fails there.
 */
class SyncSocketTransport
{
    public:
        /// @param socketPath The agent's queue-sync intake socket.
        /// @param moduleName Prefixed onto the frame's session id, which is how
        ///        agentd knows which module's *com socket the manager's answer
        ///        belongs to - it never parses the session itself.
        /// @param logger Logger function.
        SyncSocketTransport(std::string socketPath, std::string moduleName, LoggerFunc logger);

        /// @brief Whether the intake socket is reachable.
        bool checkStatus();

        /// @brief Streams one whole session across and waits for the intake's
        ///        status byte.
        /// @param session Session id; also becomes the frame's id, in decimal.
        /// @param message The serialized FullSession message.
        /// @return True only once the agent confirms it queued the session.
        bool sendSession(uint64_t session, const std::vector<uint8_t>& message);

        /// @brief The id put on the wire for a session: "<module>-<session>".
        ///        Kept public so the response router can be tested against the
        ///        exact string the producer sends.
        std::string frameSessionId(uint64_t session) const;

    private:
        std::string m_socketPath;
        std::string m_moduleName;
        LoggerFunc m_logger;
};
