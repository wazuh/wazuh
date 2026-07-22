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

    // 413: the /stateless batch exceeds what the manager accepts; the stream
    // splits it and resends smaller (#37835), never dropping events.
    if (code == 413)
    {
        return OutcomeClass::PayloadTooLarge;
    }

    // Version/protocol rejection: 426 per the #37732 proposal, 409 per the
    // #37733 Task Manager OpenAPI ("Protocol version not supported"). Both
    // accepted until the two specs reconcile; either way the client goes
    // REJECTED and re-tries Startup on the slow cadence.
    if (code == 426 || code == 409)
    {
        return OutcomeClass::VersionRejected;
    }

    if (code == 429 || code == 503)
    {
        return OutcomeClass::BackPressure;
    }

    return (code >= 500) ? OutcomeClass::Retryable : OutcomeClass::Permanent;
}
