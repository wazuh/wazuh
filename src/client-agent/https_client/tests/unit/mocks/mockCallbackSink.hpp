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
        MOCK_METHOD(void, onConfigDownloaded,
                    (const std::string& configHash, std::shared_ptr<SpoolFile> file), (override));
        MOCK_METHOD(void, onStateChange, (hc_conn_state_t state), (override));
};

#endif // _HC_MOCK_CALLBACK_SINK_HPP
