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

#ifndef _HC_MOCK_SPOOL_FACTORY_HPP
#define _HC_MOCK_SPOOL_FACTORY_HPP

#include "spoolFile.hpp"

#include <gmock/gmock.h>

class MockSpoolFactory : public ISpoolFileFactory
{
    public:
        MOCK_METHOD(std::unique_ptr<SpoolFile>, spool, (const uint8_t* buffer, size_t length), (override));
};

#endif // _HC_MOCK_SPOOL_FACTORY_HPP
