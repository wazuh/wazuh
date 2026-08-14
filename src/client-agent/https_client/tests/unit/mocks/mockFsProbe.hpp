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

#ifndef _HC_MOCK_FS_PROBE_HPP
#define _HC_MOCK_FS_PROBE_HPP

#include "sysSeams.hpp"

#include <gmock/gmock.h>

class MockFsProbe : public IFsProbe
{
    public:
        MOCK_METHOD(bool, isReadableFile, (const std::string& path), (const, override));
};

#endif // _HC_MOCK_FS_PROBE_HPP
