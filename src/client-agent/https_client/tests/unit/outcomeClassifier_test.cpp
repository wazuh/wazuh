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
        // status arrived, so the manager did not answer -- including a TlsFail
        // CurlPerformer's verify_mode=system fallback (#39123) already decided was
        // not eligible (a classified hostname/date failure, or no fallback path
        // configured) or had already exhausted; CurlPerformer resolves the
        // retry-eligible case before a response ever gets here.
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
        // 404 is NOT Permanent: nothing at the target says nothing about the
        // payload, so the two classes get opposite treatment downstream.
        ClassifierCase {TransportStatus::Ok, 404, OutcomeClass::RouteNotFound}));

TEST(OutcomeClassifierTest, AbortedIsInterruptedNeverOk)
{
    // Even with a 2xx already received, an aborted transfer must surface as
    // Interrupted (H3: interruption is never a silent success).
    EXPECT_EQ(OutcomeClass::Interrupted, classifyOutcome(makeResponse(TransportStatus::Aborted, 200)));
    EXPECT_EQ(OutcomeClass::Interrupted, classifyOutcome(makeResponse(TransportStatus::Aborted, 0)));
}

struct CertVerificationCase
{
    TransportStatus status;
    TlsFailureKind kind;
    bool depth0VerificationFailed;
    bool chainTrustRejectedAboveDepth0;
    bool expected;
};

inline void PrintTo(const CertVerificationCase& value, std::ostream* stream)
{
    *stream << "status=" << static_cast<int>(value.status) << " kind=" << static_cast<int>(value.kind)
            << " depth0Failed=" << value.depth0VerificationFailed
            << " chainAboveDepth0=" << value.chainTrustRejectedAboveDepth0
            << " expected=" << value.expected;
}

class IsCertificateVerificationFailureTable : public ::testing::TestWithParam<CertVerificationCase>
{
};

TEST_P(IsCertificateVerificationFailureTable, ClassifiesAsExpected)
{
    const auto& param = GetParam();
    HttpResponse response = makeResponse(param.status, 0);
    response.tlsFailure.kind = param.kind;
    response.tlsFailure.depth0VerificationFailed = param.depth0VerificationFailed;
    response.tlsFailure.chainTrustRejectedAboveDepth0 = param.chainTrustRejectedAboveDepth0;
    EXPECT_EQ(param.expected, isCertificateVerificationFailure(response));
}

INSTANTIATE_TEST_SUITE_P(
    D9Table,
    IsCertificateVerificationFailureTable,
    ::testing::Values(
        // The ordinary chain/CA-trust class this issue is about: leaf-depth rejection.
        CertVerificationCase {TransportStatus::TlsFail, TlsFailureKind::None, true, false, true},
        // Chain-trust rejection above the leaf (an untrusted intermediate/root) -- OpenSSL's
        // chain builder can reject before ever reaching depth 0, so depth0VerificationFailed
        // stays false in this case.
        CertVerificationCase {TransportStatus::TlsFail, TlsFailureKind::None, false, true, true},
        // Already classified elsewhere as hostname/date: must not double-report.
        CertVerificationCase {TransportStatus::TlsFail, TlsFailureKind::HostnameMismatch, true, false, false},
        CertVerificationCase {TransportStatus::TlsFail, TlsFailureKind::CertExpired, true, false, false},
        CertVerificationCase {TransportStatus::TlsFail, TlsFailureKind::CertNotYetValid, false, true, false},
        // A TlsFail that never reached certificate inspection at all (a cipher-negotiation
        // failure, or a corrupt local CA file -- HttpResponse::caFileLoadFailed's case):
        // neither flag is ever set, so this must stay generic, unclassified TlsFail.
        CertVerificationCase {TransportStatus::TlsFail, TlsFailureKind::None, false, false, false},
        // Not a TLS failure at all: never a cert-verification failure regardless of what the
        // (irrelevant here) tlsFailure fields happen to say.
        CertVerificationCase {TransportStatus::Ok, TlsFailureKind::None, true, true, false},
        CertVerificationCase {TransportStatus::Timeout, TlsFailureKind::None, true, true, false},
        CertVerificationCase {TransportStatus::ConnectFail, TlsFailureKind::None, true, true, false},
        CertVerificationCase {TransportStatus::Aborted, TlsFailureKind::None, true, true, false},
        CertVerificationCase {TransportStatus::OtherError, TlsFailureKind::None, true, true, false}));

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
    // Split from Permanent inside the module only: both are terminal for the
    // request as sent, so the C ABI sees no change.
    EXPECT_EQ(HC_RESULT_PERMANENT, toHcResult(OutcomeClass::RouteNotFound));
    EXPECT_EQ(HC_RESULT_PERMANENT, toHcResult(OutcomeClass::VersionRejected));
    EXPECT_EQ(HC_RESULT_PERMANENT, toHcResult(OutcomeClass::CompressionRejected));
    EXPECT_EQ(HC_RESULT_ERROR, toHcResult(OutcomeClass::Interrupted));
}
