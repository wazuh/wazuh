/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 16, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_CLOCK_SKEW_HPP
#define _HC_CLOCK_SKEW_HPP

#include "sysSeams.hpp"

#include <cmath>
#include <cstdint>
#include <ctime>

/// Below this, a Date-vs-local gap is plausibly latency or rounding rather than real skew, and is
/// not worth perturbing a signing timestamp over -- it is inside what any manager already
/// tolerates. The failures this targets (VM snapshot restore, dead CMOS battery, no NTP) are
/// minutes to hours off, far above the floor.
constexpr std::int64_t kSkewNoiseFloorSeconds = 5;

/**
 * @brief Corrects @p clock to the manager's Date header when the gap is real skew.
 *
 * Shared by RetrySender (a 401 on a signed request) and EnrollClient (a 401 on /enroll): both
 * answer the same question -- "was that rejection our clock?" -- and answering it differently in
 * the two places is how one of them ends up with a floor the other does not have.
 *
 * Date is not itself authenticated (no signature covers it), so this trusts whoever answered the
 * TLS handshake -- no different from trusting the 401 status and body it arrived with. Under the
 * required TLS verification modes that is the real manager; under verify_mode=none (opt-in,
 * insecure) a MITM could already forge the whole response, so feeding it a bogus Date is a new use
 * of an existing capability, not a new capability.
 *
 * The wallSeconds() read here is only a heuristic pre-check, for the noise floor and the caller's
 * log line. It can race another sender's concurrent correction and see a stale value, which risks
 * no more than a skipped or duplicated log line, or one redundant call: correctToServerTime()
 * recomputes the real offset itself from its own raw clock read taken at commit time, so a stale
 * delta here never corrupts the applied correction (see IClock::correctToServerTime's contract).
 *
 * @param clock Corrected in place when, and only when, a non-zero delta is returned.
 * @param serverDateSeconds The response's parsed Date; 0 when none was captured.
 * @return The observed skew in seconds when a correction was applied, 0 when none was -- whether
 *         because no Date arrived or because the gap was inside the noise floor. A delta of
 *         exactly 0 is itself inside the floor, so 0 is never an applied correction. Callers log
 *         their own message: the wording differs by call site, and the number is what they share.
 */
inline std::int64_t correctClockFromServerDate(IClock& clock, std::time_t serverDateSeconds)
{
    if (serverDateSeconds == 0)
    {
        return 0; // No Date captured/parsed: nothing to measure skew against.
    }

    const auto delta =
        static_cast<std::int64_t>(serverDateSeconds) - static_cast<std::int64_t>(clock.wallSeconds());

    if (std::abs(delta) < kSkewNoiseFloorSeconds)
    {
        return 0; // Aligned enough: leave the clock alone, the 401 is likely a dead credential.
    }

    clock.correctToServerTime(serverDateSeconds);
    return delta;
}

#endif // _HC_CLOCK_SKEW_HPP
