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

#ifndef _HC_MOCK_CALLBACK_SINK_HPP
#define _HC_MOCK_CALLBACK_SINK_HPP

#include "callbackSink.hpp"

#include <gmock/gmock.h>

class MockCallbackSink : public ICallbackSink
{
    public:
        MOCK_METHOD(void, onStartupResult, (bool accepted, const std::string& handshakeJson), (override));
        MOCK_METHOD(void, onReenrollRequired, (), (override));
        MOCK_METHOD(void, onTask,
                    (const std::string& taskId, const std::string& taskType,
                     const std::string& payloadJson),
                    (override));
        MOCK_METHOD(void, onConfigDownloaded,
                    (const std::string& configHash, std::shared_ptr<SpoolFile> file), (override));
        MOCK_METHOD(void, onUpgradeReady,
                    (const std::string& taskId, const std::string& wpkFile,
                     std::shared_ptr<SpoolFile> file, const std::string& installer),
                    (override));
        MOCK_METHOD(void, onTaskFailed,
                    (const std::string& taskId, const std::string& taskType, const std::string& reason),
                    (override));
        MOCK_METHOD(void, onManagerConfigHash, (const std::string& configHash), (override));
        MOCK_METHOD(void, onAgentGroups, (const std::string& groupsCsv), (override));
        MOCK_METHOD(void, onSyncResponse,
                    (const std::string& sessionId, int result, const std::string& body), (override));
        MOCK_METHOD(void, onStateChange, (hc_conn_state_t state), (override));
        MOCK_METHOD(void, onBufferLevel, (hc_buffer_level_t level), (override));
        MOCK_METHOD(void, onProducerPause, (bool paused), (override));
};

#endif // _HC_MOCK_CALLBACK_SINK_HPP
