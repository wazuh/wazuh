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

#include <gtest/gtest.h>

#include <ostream>

namespace
{
    HttpResponse makeResponse(TransportStatus status, long code)
    {
        HttpResponse response;
        response.status = status;
        response.httpCode = code;
        return response;
    }
} // namespace

struct ClassifierCase
{
    TransportStatus status;
    long httpCode;
    OutcomeClass expected;
};

/// Without a printer gtest falls back to hex-dumping the raw object when it
/// names a case, and this aggregate carries padding (4 bytes after the enum,
/// 4 at the end, hence the 24-byte object) that no initializer writes. Reading
/// it is what valgrind reports under the RTR. A printer removes the fallback,
/// and a failure now names the case instead of dumping bytes.
inline void PrintTo(const ClassifierCase& value, std::ostream* stream)
{
    *stream << "transport=" << static_cast<int>(value.status) << " http=" << value.httpCode
            << " expected=" << static_cast<int>(value.expected);
}

class OutcomeClassifierTable : public ::testing::TestWithParam<ClassifierCase>
{
};

TEST_P(OutcomeClassifierTable, ClassifiesAsExpected)
{
    const auto& param = GetParam();
    EXPECT_EQ(param.expected, classifyOutcome(makeResponse(param.status, param.httpCode)));
}

INSTANTIATE_TEST_SUITE_P(
    D9Table,
    OutcomeClassifierTable,
    ::testing::Values(
        // Success family.
        ClassifierCase {TransportStatus::Ok, 200, OutcomeClass::Ok},
        ClassifierCase {TransportStatus::Ok, 201, OutcomeClass::Ok},
        ClassifierCase {TransportStatus::Ok, 299, OutcomeClass::Ok},
        // Transport errors: retryable AND the confirmed-disconnect class that
        // arms the producer pause. TlsFail is deliberately in here too: no HTTP
        // status arrived, so the manager did not answer.
        ClassifierCase {TransportStatus::Timeout, 0, OutcomeClass::Unreachable},
        ClassifierCase {TransportStatus::ConnectFail, 0, OutcomeClass::Unreachable},
        ClassifierCase {TransportStatus::TlsFail, 0, OutcomeClass::Unreachable},
        ClassifierCase {TransportStatus::OtherError, 0, OutcomeClass::Unreachable},
        // Auth: 401 only. 403 is not an auth code in the final contract; as a
        // non-contract intermediary code it is transient, so events are kept.
        ClassifierCase {TransportStatus::Ok, 401, OutcomeClass::AuthFail},
        ClassifierCase {TransportStatus::Ok, 403, OutcomeClass::ServerError},
        // Version rejection: 409 Conflict per the #37733 /control contract.
        // 426 was the superseded #37732 proposal; now a transient intermediary
        // code rather than a batch-dropping Permanent.
        ClassifierCase {TransportStatus::Ok, 409, OutcomeClass::VersionRejected},
        ClassifierCase {TransportStatus::Ok, 426, OutcomeClass::ServerError},
        // Back-pressure signals.
        ClassifierCase {TransportStatus::Ok, 429, OutcomeClass::BackPressure},
        ClassifierCase {TransportStatus::Ok, 503, OutcomeClass::BackPressure},
        // Retryable but NOT a disconnect: an HTTP status came back, so something
        // answered. 503 is BackPressure above; 403/426 share this class.
        ClassifierCase {TransportStatus::Ok, 500, OutcomeClass::ServerError},
        ClassifierCase {TransportStatus::Ok, 502, OutcomeClass::ServerError},
        ClassifierCase {TransportStatus::Ok, 504, OutcomeClass::ServerError},
        // 413: the /stateless split-and-resend class (#37835), distinct from
        // the generic permanent drop.
        ClassifierCase {TransportStatus::Ok, 413, OutcomeClass::PayloadTooLarge},
        // 415: the manager rejects Content-Encoding: zstd --
        // RetrySender retries once, uncompressed.
        ClassifierCase {TransportStatus::Ok, 415, OutcomeClass::CompressionRejected},
        // Permanent for this payload.
        ClassifierCase {TransportStatus::Ok, 400, OutcomeClass::Permanent},
        ClassifierCase {TransportStatus::Ok, 404, OutcomeClass::Permanent}));

TEST(OutcomeClassifierTest, AbortedIsInterruptedNeverOk)
{
    // Even with a 2xx already received, an aborted transfer must surface as
    // Interrupted (H3: interruption is never a silent success).
    EXPECT_EQ(OutcomeClass::Interrupted, classifyOutcome(makeResponse(TransportStatus::Aborted, 200)));
    EXPECT_EQ(OutcomeClass::Interrupted, classifyOutcome(makeResponse(TransportStatus::Aborted, 0)));
}

TEST(OutcomeClassifierTest, HcResultMapping)
{
    EXPECT_EQ(HC_RESULT_OK, toHcResult(OutcomeClass::Ok));
    // Both halves of the former Retryable class still cross the ABI as
    // RETRYABLE: the split is internal to the module (#38010).
    EXPECT_EQ(HC_RESULT_RETRYABLE, toHcResult(OutcomeClass::Unreachable));
    EXPECT_EQ(HC_RESULT_RETRYABLE, toHcResult(OutcomeClass::ServerError));
    EXPECT_EQ(HC_RESULT_BACKPRESSURE, toHcResult(OutcomeClass::BackPressure));
    EXPECT_EQ(HC_RESULT_AUTH_FAIL, toHcResult(OutcomeClass::AuthFail));
    EXPECT_EQ(HC_RESULT_PERMANENT, toHcResult(OutcomeClass::Permanent));
    EXPECT_EQ(HC_RESULT_PERMANENT, toHcResult(OutcomeClass::VersionRejected));
    EXPECT_EQ(HC_RESULT_PERMANENT, toHcResult(OutcomeClass::CompressionRejected));
    EXPECT_EQ(HC_RESULT_ERROR, toHcResult(OutcomeClass::Interrupted));
}
