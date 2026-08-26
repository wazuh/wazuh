/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_MOCK_FILE_DECOMPRESSOR_HPP
#define _HC_MOCK_FILE_DECOMPRESSOR_HPP

#include "fileDecompressor.hpp"

#include <gmock/gmock.h>

class MockFileDecompressor : public IFileDecompressor
{
    public:
        MOCK_METHOD((std::optional<uint64_t>), decompress,
                    (const std::string& pathToReplace, uint64_t maxDecompressedBytes,
                     const std::string& spoolDir, const std::atomic<bool>* abortFlag),
                    (override));
};

#endif // _HC_MOCK_FILE_DECOMPRESSOR_HPP
