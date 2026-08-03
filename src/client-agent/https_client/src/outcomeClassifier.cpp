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

    if (code == 401) // Generic auth failure, the only auth code in the contract.
    {
        return OutcomeClass::AuthFail;
    }

    // 413: the /stateless batch exceeds what the manager accepts; the stream
    // splits it and resends smaller (#37835), never dropping events.
    if (code == 413)
    {
        return OutcomeClass::PayloadTooLarge;
    }

    // 409 Conflict: protocol/agent version not supported (the #37733 /control
    // contract). The client goes REJECTED and re-tries Startup on the slow
    // cadence.
    if (code == 409)
    {
        return OutcomeClass::VersionRejected;
    }

    if (code == 429 || code == 503)
    {
        return OutcomeClass::BackPressure;
    }

    // 403/426 are not part of the manager contract: they reach the agent only
    // from an intermediary (reverse proxy, WAF, mTLS gateway). Treat them as
    // transient so a /stateless batch is preserved and retried, never dropped
    // (Permanent would consume the batch and count it as lost).
    if (code == 403 || code == 426)
    {
        return OutcomeClass::Retryable;
    }

    return (code >= 500) ? OutcomeClass::Retryable : OutcomeClass::Permanent;
}
