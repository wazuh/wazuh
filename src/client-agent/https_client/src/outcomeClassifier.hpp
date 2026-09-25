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

#ifndef _HC_OUTCOME_CLASSIFIER_HPP
#define _HC_OUTCOME_CLASSIFIER_HPP

#include "httpTypes.hpp"

/// D9 classification of one completed attempt. Pure; the full table is
/// enumerated by its unit test. An aborted transfer is always Interrupted,
/// never a silent success (lesson H3 from the in-tree wrapper audit).
OutcomeClass classifyOutcome(const HttpResponse& response);

/// True when @p response is a TLS handshake failure whose cause is the ordinary
/// chain/CA-trust class (self-signed leaf, unknown/unpinned CA, ...) -- exactly the
/// class classifyTlsVerifyFailure() deliberately leaves as TlsFailureKind::None
/// (a hostname mismatch or a certificate-date problem is already reported elsewhere; see
/// tlsCertDiagnostics.hpp). False for every other TransportStatus, for a TlsFail already
/// classified as hostname/date, and for a TlsFail that never reached certificate inspection
/// at all (a cipher-negotiation failure, a corrupt local CA file -- see
/// TlsFailureDetail::sawDepth0/caFileLoadFailed) -- none of those are a trust decision an
/// operator can act on by fixing the manager's/agent's CA.
bool isCertificateVerificationFailure(const HttpResponse& response);

#endif // _HC_OUTCOME_CLASSIFIER_HPP
