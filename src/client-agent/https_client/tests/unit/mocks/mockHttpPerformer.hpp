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

#ifndef _HC_MOCK_HTTP_PERFORMER_HPP
#define _HC_MOCK_HTTP_PERFORMER_HPP

#include "iHttpPerformer.hpp"

#include <gmock/gmock.h>

class MockHttpPerformer : public IHttpPerformer
{
    public:
        MOCK_METHOD(HttpResponse, perform, (const HttpRequestSpec& spec), (override));
};

#endif // _HC_MOCK_HTTP_PERFORMER_HPP
