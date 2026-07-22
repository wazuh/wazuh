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
        // Transport errors are retryable.
        ClassifierCase {TransportStatus::Timeout, 0, OutcomeClass::Retryable},
        ClassifierCase {TransportStatus::ConnectFail, 0, OutcomeClass::Retryable},
        ClassifierCase {TransportStatus::TlsFail, 0, OutcomeClass::Retryable},
        ClassifierCase {TransportStatus::OtherError, 0, OutcomeClass::Retryable},
        // Auth: 401 per #37732; 403 kept until FR7.4 is reconciled (T2).
        ClassifierCase {TransportStatus::Ok, 401, OutcomeClass::AuthFail},
        ClassifierCase {TransportStatus::Ok, 403, OutcomeClass::AuthFail},
        // Version rejection: 426 per #37732, 409 per the #37733 OpenAPI
        // ("Protocol version not supported"); both accepted until reconciled.
        ClassifierCase {TransportStatus::Ok, 426, OutcomeClass::VersionRejected},
        ClassifierCase {TransportStatus::Ok, 409, OutcomeClass::VersionRejected},
        // Back-pressure signals.
        ClassifierCase {TransportStatus::Ok, 429, OutcomeClass::BackPressure},
        ClassifierCase {TransportStatus::Ok, 503, OutcomeClass::BackPressure},
        // Server errors are retryable.
        ClassifierCase {TransportStatus::Ok, 500, OutcomeClass::Retryable},
        ClassifierCase {TransportStatus::Ok, 502, OutcomeClass::Retryable},
        ClassifierCase {TransportStatus::Ok, 504, OutcomeClass::Retryable},
        // 413: the /stateless split-and-resend class (#37835), distinct from
        // the generic permanent drop.
        ClassifierCase {TransportStatus::Ok, 413, OutcomeClass::PayloadTooLarge},
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
    EXPECT_EQ(HC_RESULT_RETRYABLE, toHcResult(OutcomeClass::Retryable));
    EXPECT_EQ(HC_RESULT_BACKPRESSURE, toHcResult(OutcomeClass::BackPressure));
    EXPECT_EQ(HC_RESULT_AUTH_FAIL, toHcResult(OutcomeClass::AuthFail));
    EXPECT_EQ(HC_RESULT_PERMANENT, toHcResult(OutcomeClass::Permanent));
    EXPECT_EQ(HC_RESULT_PERMANENT, toHcResult(OutcomeClass::VersionRejected));
    EXPECT_EQ(HC_RESULT_ERROR, toHcResult(OutcomeClass::Interrupted));
}
