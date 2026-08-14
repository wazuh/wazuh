/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 4, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sync/fullSessionValidator.hpp"

#include "testSessionBuilder.hpp"

#include <gtest/gtest.h>

#include <string>
#include <variant>

using invsync::sync::ValidatedSession;
using invsync::sync::validateFullSession;
using invsync::sync::ValidationFailure;
using invsync::test::SessionSpec;

namespace
{
    constexpr auto CLUSTER {"test-cluster"};

    const ValidationFailure& failureOf(const invsync::sync::ValidationResult& result)
    {
        const auto* failure = std::get_if<ValidationFailure>(&result);
        EXPECT_NE(nullptr, failure);
        static const ValidationFailure fallback {};
        return failure ? *failure : fallback;
    }

    const ValidatedSession& sessionOf(const invsync::sync::ValidationResult& result)
    {
        const auto* session = std::get_if<ValidatedSession>(&result);
        EXPECT_NE(nullptr, session) << "expected the session to validate";
        static const ValidatedSession fallback {};
        return session ? *session : fallback;
    }
} // namespace

TEST(FullSessionValidatorTest, GarbageFailsTheVerifierWith400)
{
    const auto result = validateFullSession("definitely not a flatbuffer", "1", CLUSTER);
    EXPECT_EQ(400, failureOf(result).status);
}

TEST(FullSessionValidatorTest, ALegacyDirectMemberIsRejectedWith400)
{
    const auto body = invsync::test::buildLegacyStartMessage(SessionSpec {});
    const auto result = validateFullSession(body, "1", CLUSTER);
    const auto& failure = failureOf(result);
    EXPECT_EQ(400, failure.status);
    EXPECT_NE(std::string::npos, failure.reason.find("FullSession"));
}

TEST(FullSessionValidatorTest, AMissingModuleNameIs400)
{
    SessionSpec spec;
    spec.moduleName.clear();
    const auto body = invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}});
    EXPECT_EQ(400, failureOf(validateFullSession(body, "1", CLUSTER)).status);
}

TEST(FullSessionValidatorTest, AgentIdMismatchIs403EvenWithLeadingZeros)
{
    const auto body = invsync::test::buildSyncDataSession(SessionSpec {}, {invsync::test::ValueSpec {}});

    // agent "1" claimed, authenticated as "2" -> spoofing.
    EXPECT_EQ(403, failureOf(validateFullSession(body, "2", CLUSTER)).status);

    // Leading zeros must NOT defeat the comparison: "001" == "1".
    EXPECT_TRUE(std::holds_alternative<ValidatedSession>(validateFullSession(body, "001", CLUSTER)));
}

TEST(FullSessionValidatorTest, NonNumericAgentIdsAre400NotSpoofing)
{
    SessionSpec spec;
    spec.agentId = "agent-one";
    const auto body = invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}});
    EXPECT_EQ(400, failureOf(validateFullSession(body, "1", CLUSTER)).status);

    const auto valid = invsync::test::buildSyncDataSession(SessionSpec {}, {invsync::test::ValueSpec {}});
    EXPECT_EQ(400, failureOf(validateFullSession(valid, "not-numeric", CLUSTER)).status);
}

TEST(FullSessionValidatorTest, ClusterMismatchIs403AndMissingClusterIs400)
{
    const auto body = invsync::test::buildSyncDataSession(SessionSpec {}, {invsync::test::ValueSpec {}});
    EXPECT_EQ(403, failureOf(validateFullSession(body, "1", "another-cluster")).status);

    SessionSpec spec;
    spec.clusterName.clear();
    const auto missing = invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}});
    EXPECT_EQ(400, failureOf(validateFullSession(missing, "1", CLUSTER)).status);
}

TEST(FullSessionValidatorTest, TheModeXPayloadMatrixIsEnforced)
{
    namespace fb = invsync::schema::fb;

    // Valid combinations (doc 02 §2): they must all validate.
    for (const auto mode : {fb::Mode_ModuleDelta})
    {
        SessionSpec spec;
        spec.mode = mode;
        EXPECT_TRUE(std::holds_alternative<ValidatedSession>(validateFullSession(
            invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}}), "1", CLUSTER)))
            << "ModuleDelta x SyncData";
        EXPECT_TRUE(std::holds_alternative<ValidatedSession>(validateFullSession(
            invsync::test::buildCleansSession(spec, {"wazuh-states-inventory-packages"}), "1", CLUSTER)))
            << "ModuleDelta x Cleans (D6)";
    }
    {
        SessionSpec spec;
        spec.mode = fb::Mode_ModuleCheck;
        EXPECT_TRUE(std::holds_alternative<ValidatedSession>(validateFullSession(
            invsync::test::buildChecksumSession(spec, "wazuh-states-inventory-packages", "abc"), "1", CLUSTER)));
    }
    for (const auto mode : {fb::Mode_MetadataDelta, fb::Mode_MetadataCheck, fb::Mode_GroupDelta, fb::Mode_GroupCheck})
    {
        SessionSpec spec;
        spec.mode = mode;
        EXPECT_TRUE(std::holds_alternative<ValidatedSession>(
            validateFullSession(invsync::test::buildBareSession(spec), "1", CLUSTER)))
            << "mode " << static_cast<int>(mode) << " x NONE";
    }

    // Invalid combinations: every payload against a mode that does not accept it.
    {
        SessionSpec spec;
        spec.mode = fb::Mode_ModuleCheck; // wants ChecksumModule
        EXPECT_EQ(400,
                  failureOf(validateFullSession(
                                invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}}), "1", CLUSTER))
                      .status);
        EXPECT_EQ(400, failureOf(validateFullSession(invsync::test::buildBareSession(spec), "1", CLUSTER)).status);
    }
    {
        SessionSpec spec;
        spec.mode = fb::Mode_MetadataDelta; // wants NONE
        EXPECT_EQ(400,
                  failureOf(validateFullSession(
                                invsync::test::buildCleansSession(spec, {"wazuh-states-fim-files"}), "1", CLUSTER))
                      .status);
        EXPECT_EQ(400,
                  failureOf(validateFullSession(
                                invsync::test::buildChecksumSession(spec, "wazuh-states-fim-files", "x"), "1", CLUSTER))
                      .status);
    }
    {
        SessionSpec spec;
        spec.mode = fb::Mode_ModuleDelta; // data modes need a payload
        EXPECT_EQ(400, failureOf(validateFullSession(invsync::test::buildBareSession(spec), "1", CLUSTER)).status);
    }
}

TEST(FullSessionValidatorTest, SyncDataWithoutValuesIs400EvenWithContexts)
{
    // D8: contexts cannot stand alone; values >= 1 is the shape contract.
    const auto onlyContexts = invsync::test::buildSyncDataSession(SessionSpec {}, {}, {invsync::test::ContextSpec {}});
    EXPECT_EQ(400, failureOf(validateFullSession(onlyContexts, "1", CLUSTER)).status);

    const auto empty = invsync::test::buildSyncDataSession(SessionSpec {}, {});
    EXPECT_EQ(400, failureOf(validateFullSession(empty, "1", CLUSTER)).status);
}

TEST(FullSessionValidatorTest, EmptyCleansIs400)
{
    EXPECT_EQ(
        400,
        failureOf(validateFullSession(invsync::test::buildCleansSession(SessionSpec {}, {}), "1", CLUSTER)).status);
}

TEST(FullSessionValidatorTest, ChecksumRulesRejectBadIndexAndMissingChecksum)
{
    SessionSpec spec;
    spec.mode = invsync::schema::fb::Mode_ModuleCheck;

    // Index outside the allowlist is 400 (not skip-with-WARN: the whole session IS the check).
    EXPECT_EQ(400,
              failureOf(validateFullSession(invsync::test::buildChecksumSession(spec, "alerts", "abc"), "1", CLUSTER))
                  .status);
    EXPECT_EQ(
        400, failureOf(validateFullSession(invsync::test::buildChecksumSession(spec, "", "abc"), "1", CLUSTER)).status);
    EXPECT_EQ(
        400,
        failureOf(validateFullSession(
                      invsync::test::buildChecksumSession(spec, "wazuh-states-inventory-packages", ""), "1", CLUSTER))
            .status);
}

TEST(FullSessionValidatorTest, AValidatedSessionCarriesThePaddedIdAndTheStartFields)
{
    SessionSpec spec;
    spec.option = invsync::schema::fb::Option_VDFirst;
    spec.indices = {"wazuh-states-inventory-packages", "wazuh-states-inventory-processes"};
    spec.groups = {"default", "linux"};
    const auto body = invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}});

    const auto result = validateFullSession(body, "1", CLUSTER);
    const auto& session = sessionOf(result);

    EXPECT_EQ("001", session.agentId) << "the id every _id and wazuh.agent.id has always used";
    EXPECT_TRUE(session.isVD);
    EXPECT_EQ("syscollector", session.moduleName);
    EXPECT_EQ("agent-one", session.agentName);
    EXPECT_EQ(CLUSTER, session.clusterName);
    EXPECT_EQ(3U, session.globalVersion);
    EXPECT_EQ(2U, session.indices.size());
    EXPECT_EQ(2U, session.groups.size());
    ASSERT_NE(nullptr, session.session);
    EXPECT_EQ(invsync::schema::fb::SessionPayload_SyncData, session.payloadType);
}
