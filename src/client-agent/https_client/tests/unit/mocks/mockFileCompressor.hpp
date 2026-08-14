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

#ifndef _HC_MOCK_FILE_COMPRESSOR_HPP
#define _HC_MOCK_FILE_COMPRESSOR_HPP

#include "fileCompressor.hpp"

#include <gmock/gmock.h>

class MockFileCompressor : public IFileCompressor
{
    public:
        MOCK_METHOD((std::optional<std::pair<std::unique_ptr<SpoolFile>, uint64_t>>), compress,
                    (const std::string& sourcePath, uint64_t sourceSize, const std::string& spoolDir,
                     const std::atomic<bool>* abortFlag),
                    (override));
};

#endif // _HC_MOCK_FILE_COMPRESSOR_HPP
