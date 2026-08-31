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
            // Same rationale as above, now that these five report success/failure
            // too: a real handle accepts them, so default to true and let tests
            // that want to exercise the failure path override it explicitly.
            ON_CALL(*this, captureResponseBody(::testing::_))
            .WillByDefault(::testing::Return(true));
            ON_CALL(*this, captureResponseToFile(::testing::_, ::testing::_))
            .WillByDefault(::testing::Return(true));
            ON_CALL(*this, captureResponseHeaders(::testing::_))
            .WillByDefault(::testing::Return(true));
            ON_CALL(*this, streamBodyFromFile(::testing::_, ::testing::_))
            .WillByDefault(::testing::Return(true));
            ON_CALL(*this, wireAbort(::testing::_))
            .WillByDefault(::testing::Return(true));
        }

        MOCK_METHOD(bool, setOptionLong, (CurlOption option, long value), (override));
        MOCK_METHOD(bool, setOptionString, (CurlOption option, const std::string& value), (override));
        MOCK_METHOD(bool, setOptionPtr, (CurlOption option, const void* value), (override));
        MOCK_METHOD(void, appendHeader, (const std::string& header), (override));
        MOCK_METHOD(bool, captureResponseBody, (std::string* output), (override));
        MOCK_METHOD(bool, captureResponseToFile, (std::FILE* file, uint64_t maxBytes), (override));
        MOCK_METHOD(bool, captureResponseHeaders, (HeaderCapture capture), (override));
        MOCK_METHOD(bool, streamBodyFromFile, (std::FILE* file, uint64_t size), (override));
        MOCK_METHOD(bool, wireAbort, (const std::atomic<bool>* abortFlag), (override));
        MOCK_METHOD(TransportStatus, perform, (), (override));
        MOCK_METHOD(long, responseCode, (), (override));
        MOCK_METHOD(std::string, localIp, (), (override));
        MOCK_METHOD(std::string, curlError, (), (override));
};

#endif // _HC_MOCK_CURL_HANDLE_HPP
