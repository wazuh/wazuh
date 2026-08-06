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

#ifndef _HC_CALLBACK_SINK_HPP
#define _HC_CALLBACK_SINK_HPP

#include "https_client.h"
#include "spoolFile.hpp"

#include <memory>
#include <string>

/**
 * @brief Where the streams emit results toward the C core. The production
 *        sink serializes these onto the single dispatcher thread; tests use a
 *        recording sink. Streams depend only on this interface.
 */
class ICallbackSink
{
    public:
        virtual ~ICallbackSink() = default;

        virtual void onStartupResult(bool accepted, const std::string& handshakeJson) = 0;
        /// The signing credential was rejected (401); the module has paused all
        /// traffic. Fired once per incident until the key is replaced.
        virtual void onReenrollRequired() = 0;
        virtual void onTask(const std::string& taskId, const std::string& taskType,
                            const std::string& payloadJson) = 0;
        /// The file lives while the callback chain holds the shared_ptr; the
        /// production sink drops it right after the C callback returns.
        virtual void onConfigDownloaded(const std::string& configHash,
                                        std::shared_ptr<SpoolFile> file) = 0;
        /// A remote_upgrade task's WPK was downloaded and sha1-verified; taskId's durable
        /// record already happened before this is ever called (an ordering guarantee). file
        /// lives while the callback chain holds the shared_ptr, same convention as
        /// onConfigDownloaded.
        virtual void onUpgradeReady(const std::string& taskId, const std::string& wpkFile,
                                    std::shared_ptr<SpoolFile> file, const std::string& installer) = 0;
        /// A task's durable record already happened, but it will never reach onTask()/
        /// onUpgradeReady(): malformed payload, or (remote_upgrade only) a WPK download/sha1
        /// failure. Distinct from a duplicate -- lets the consumer count it as a real failure.
        virtual void onTaskFailed(const std::string& taskId, const std::string& taskType,
                                  const std::string& reason) = 0;
        virtual void onManagerConfigHash(const std::string& configHash) = 0;
        /// The agent's current group set (comma-joined, manager's own order, empty
        /// meaning none), fired only when it changed since the last report.
        virtual void onAgentGroups(const std::string& groupsCsv) = 0;
        virtual void onSyncResponse(const std::string& sessionId, int result, const std::string& body) = 0;
        virtual void onStateChange(hc_conn_state_t state) = 0;
        virtual void onBufferLevel(hc_buffer_level_t level) = 0;
        /// /control is confirmed unreachable (true) or reachable again (false);
        /// the core arms/disarms its producer lock. Emitted on transitions only.
        virtual void onProducerPause(bool paused) = 0;
};

#endif // _HC_CALLBACK_SINK_HPP
