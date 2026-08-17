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

#ifndef _HC_I_HTTP_PERFORMER_HPP
#define _HC_I_HTTP_PERFORMER_HPP

#include "httpTypes.hpp"

/**
 * @brief The high transport seam: one call performs exactly one signed HTTP
 *        attempt. Everything above it (retry, signing, batching, control) is
 *        tested against a mock of this interface with zero libcurl involved.
 */
class IHttpPerformer
{
    public:
        virtual ~IHttpPerformer() = default;
        virtual HttpResponse perform(const HttpRequestSpec& spec) = 0;
};

#endif // _HC_I_HTTP_PERFORMER_HPP
