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

#ifndef _HC_MOCK_CURL_HANDLE_HPP
#define _HC_MOCK_CURL_HANDLE_HPP

#include "iCurlHandle.hpp"

#include <gmock/gmock.h>

class MockCurlHandle : public ICurlHandle
{
    public:
        MockCurlHandle()
        {
            // A real handle accepts these; without a default the mock answers
            // false and CurlPerformer would abort every request as a rejected
            // TLS option. Tests that want a rejection say so explicitly.
            ON_CALL(*this, setOptionLong(::testing::_, ::testing::_))
            .WillByDefault(::testing::Return(true));
            ON_CALL(*this, setOptionString(::testing::_, ::testing::_))
            .WillByDefault(::testing::Return(true));
            ON_CALL(*this, setOptionPtr(::testing::_, ::testing::_))
            .WillByDefault(::testing::Return(true));
        }

        MOCK_METHOD(bool, setOptionLong, (CurlOption option, long value), (override));
        MOCK_METHOD(bool, setOptionString, (CurlOption option, const std::string& value), (override));
        MOCK_METHOD(bool, setOptionPtr, (CurlOption option, const void* value), (override));
        MOCK_METHOD(void, appendHeader, (const std::string& header), (override));
        MOCK_METHOD(void, captureResponseBody, (std::string* output), (override));
        MOCK_METHOD(void, captureResponseToFile, (std::FILE* file, uint64_t maxBytes), (override));
        MOCK_METHOD(void, captureRetryAfter, (long* output), (override));
        MOCK_METHOD(void, streamBodyFromFile, (std::FILE* file, uint64_t size), (override));
        MOCK_METHOD(void, wireAbort, (const std::atomic<bool>* abortFlag), (override));
        MOCK_METHOD(TransportStatus, perform, (), (override));
        MOCK_METHOD(long, responseCode, (), (override));
        MOCK_METHOD(std::string, localIp, (), (override));
};

#endif // _HC_MOCK_CURL_HANDLE_HPP
