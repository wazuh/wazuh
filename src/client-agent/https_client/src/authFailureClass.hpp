/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 10, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_AUTH_FAILURE_CLASS_HPP
#define _HC_AUTH_FAILURE_CLASS_HPP

#include <string_view>

/**
 * @brief The authentication failure class the manager names on a 401 (issue #39064).
 *
 * Up to #39040 every 401 was one undifferentiated fact and the agent's only possible answer was
 * "my credential is dead, re-enroll". The manager now names the class in the body's `code` (a
 * string, unlike every other status where `code` is the numeric status) and in the RFC 6750
 * `WWW-Authenticate` challenge, so the agent can finally tell the three actions apart:
 *
 *   - re-enroll:          UnknownAgent -- the manager has no entry for this id any more.
 *   - fix the clock:      StaleToken -- the signature was good, the timestamp was not.
 *   - keep the credential and never re-enroll: everything else. A signature, token-shape,
 *     identity, address or unusable-key failure is not fixed by a new identity, and an
 *     enrollment token's own state (TokenUnknown/Expired/Revoked) says nothing about the agent's.
 *
 * The body is the agent's source of truth rather than the challenge: HttpResponse::body is already
 * captured for every non-2xx, while the header callback only ever reads Retry-After and Date, so
 * reading `code` needs no new transport plumbing. Both carry the same value by construction
 * (remoted's errorResponseFor(), endpoints/endpoint.cpp).
 */
enum class AuthFailClass
{
    UnknownAgent,             ///< The credential names an agent the manager does not know.
    StaleToken,               ///< Valid signature, timestamp outside the accepted window.
    InvalidSignature,         ///< Judged and refused: signature/shape/identity/address/unusable key.
    InvalidRequest,           ///< No usable credential was presented at all.
    EnrollmentKeyUnavailable, ///< The manager could not judge the credential (no enrollment key).
    TokenUnknown,             ///< The enrollment token's `kid` is not in this node's store.
    TokenExpired,             ///< The enrollment token is past its expiry.
    TokenRevoked,             ///< The enrollment token was revoked.
    Unclassified              ///< No class could be read: see parseAuthFailClass().
};

/// Name of an AuthFailClass, for logs. Exactly the manager's own spelling for the eight real
/// classes, so an agent log line and a manager log line about the same rejection read the same.
const char* authFailClassName(AuthFailClass authClass);

/**
 * @brief Reads the failure class out of a 401's response body.
 *
 * Strict, and fail-safe rather than fail-closed: the body must be a JSON object whose `code` is
 * one of the eight class strings. A numeric `code` (every non-401 status, and an older manager's
 * 401), an unknown string, a `code` nested anywhere else, a non-JSON or empty body -- all of them
 * are Unclassified, which every caller must treat as "retry, and do not touch the identity".
 *
 * Ambiguity must never cost an identity: §2.9's rule 3. A manager that cannot tell us why it
 * refused us has not told us to throw away our key, and a proxy that replaced the body certainly
 * has not either.
 *
 * @param body The response body as received; may be empty.
 * @return The named class, or Unclassified.
 */
AuthFailClass parseAuthFailClass(std::string_view body);

#endif // _HC_AUTH_FAILURE_CLASS_HPP
