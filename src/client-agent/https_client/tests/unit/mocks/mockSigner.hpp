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

#ifndef _HC_MOCK_SIGNER_HPP
#define _HC_MOCK_SIGNER_HPP

#include "cmacSigner.hpp"

#include <gmock/gmock.h>

class MockSigner : public ISigner
{
public:
    MOCK_METHOD(std::optional<SignedHeaders>, sign,
                (const std::string& method, const std::string& target, const uint8_t* body,
                 size_t bodyLength, std::time_t timestamp),
                (const, override));
    MOCK_METHOD(std::optional<SignedHeaders>, signFile,
                (const std::string& method, const std::string& target,
                 const std::string& bodyFilePath, std::time_t timestamp),
                (const, override));
};

class MockKeyProvider : public IKeyProvider
{
public:
    MOCK_METHOD(std::optional<std::vector<uint8_t>>, cmacKey, (), (const, override));
};

#endif // _HC_MOCK_SIGNER_HPP
