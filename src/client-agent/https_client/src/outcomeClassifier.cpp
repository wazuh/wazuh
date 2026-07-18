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

#include "outcomeClassifier.hpp"

OutcomeClass classifyOutcome(const HttpResponse& response)
{
    if (response.status == TransportStatus::Aborted)
    {
        return OutcomeClass::Interrupted;
    }

    if (response.status != TransportStatus::Ok)
    {
        return OutcomeClass::Retryable; // timeout / connect / TLS / other transport error
    }

    const long code = response.httpCode;

    if (code >= 200 && code < 300)
    {
        return OutcomeClass::Ok;
    }

    if (code == 401 || code == 403) // 401 per #37732; 403 kept until FR7.4 is reconciled (T2)
    {
        return OutcomeClass::AuthFail;
    }

    if (code == 426)
    {
        return OutcomeClass::VersionRejected;
    }

    if (code == 429 || code == 503)
    {
        return OutcomeClass::BackPressure;
    }

    return (code >= 500) ? OutcomeClass::Retryable : OutcomeClass::Permanent;
}
