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

#include <cstddef>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

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
    const auto result = validateFullSession("definitely not a flatbuffer", "001", CLUSTER);
    EXPECT_EQ(400, failureOf(result).status);
}

TEST(FullSessionValidatorTest, ALegacyDirectMemberIsRejectedWith400)
{
    const auto body = invsync::test::buildLegacyStartMessage(SessionSpec {});
    const auto result = validateFullSession(body, "001", CLUSTER);
    const auto& failure = failureOf(result);
    EXPECT_EQ(400, failure.status);
    EXPECT_NE(std::string::npos, failure.reason.find("FullSession"));
}

TEST(FullSessionValidatorTest, AnAbsentFullSessionValueIs400)
{
    // content_type says FullSession but the union value is absent: it passes the verifier.
    const auto result = validateFullSession(invsync::test::buildMessageWithAbsentFullSession(), "001", CLUSTER);
    const auto& failure = failureOf(result);
    EXPECT_EQ(400, failure.status);
    EXPECT_NE(std::string::npos, failure.reason.find("FullSession"));
}

TEST(FullSessionValidatorTest, AnAbsentPayloadValueIs400)
{
    namespace fb = invsync::schema::fb;

    // payload_type passes the mode x payload matrix, but the union value is absent.
    const std::pair<fb::Mode, fb::SessionPayload> cases[] {{fb::Mode_ModuleDelta, fb::SessionPayload_SyncData},
                                                           {fb::Mode_ModuleDelta, fb::SessionPayload_Cleans},
                                                           {fb::Mode_ModuleCheck, fb::SessionPayload_ChecksumModule}};
    for (const auto& [mode, payloadType] : cases)
    {
        SessionSpec spec;
        spec.mode = mode;
        const auto body = invsync::test::buildSessionWithAbsentPayload(spec, payloadType);
        EXPECT_EQ(400, failureOf(validateFullSession(body, "001", CLUSTER)).status)
            << "payload " << static_cast<int>(payloadType);
    }
}

TEST(FullSessionValidatorTest, AMissingModuleNameIs400)
{
    SessionSpec spec;
    spec.moduleName.clear();
    const auto body = invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}});
    EXPECT_EQ(400, failureOf(validateFullSession(body, "001", CLUSTER)).status);
}

TEST(FullSessionValidatorTest, AnotherAgentsIdIs403)
{
    const auto body = invsync::test::buildSyncDataSession(SessionSpec {}, {invsync::test::ValueSpec {}});

    // agent "001" claimed, authenticated as "002" -> spoofing.
    EXPECT_EQ(403, failureOf(validateFullSession(body, "002", CLUSTER)).status);
    EXPECT_TRUE(std::holds_alternative<ValidatedSession>(validateFullSession(body, "001", CLUSTER)));
}

TEST(FullSessionValidatorTest, AnAgentIdIsAStringSoOtherSpellingsOfTheSameNumberAre400)
{
    // The phantom-document case: agent 001 claiming "0001" passed a numeric comparison and then
    // indexed under "0001", which the deletion of agent 001 never matches. Every spelling but the
    // canonical one is now malformed, whatever number it denotes.
    for (const auto* claimed : {"0001", "01", "1", "00001"})
    {
        SessionSpec spec;
        spec.agentId = claimed;
        const auto body = invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}});
        EXPECT_EQ(400, failureOf(validateFullSession(body, "001", CLUSTER)).status) << "claimed " << claimed;
    }

    // Wider ids keep their digits: "1000" is canonical, "01000" is not.
    SessionSpec wide;
    wide.agentId = "1000";
    EXPECT_TRUE(std::holds_alternative<ValidatedSession>(validateFullSession(
        invsync::test::buildSyncDataSession(wide, {invsync::test::ValueSpec {}}), "1000", CLUSTER)));
    wide.agentId = "01000";
    EXPECT_EQ(400,
              failureOf(validateFullSession(
                            invsync::test::buildSyncDataSession(wide, {invsync::test::ValueSpec {}}), "1000", CLUSTER))
                  .status);
}

TEST(FullSessionValidatorTest, OutOfRangeAgentIdsAre400AndNeverWrap)
{
    // 4294967297 = 2^32 + 1: atoi() wrapped it to 1 on glibc LP64, so it passed for agent 001.
    for (const auto* claimed : {"4294967297", "4294967296", "99999999999", "18446744073709551617"})
    {
        SessionSpec spec;
        spec.agentId = claimed;
        const auto body = invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}});
        EXPECT_EQ(400, failureOf(validateFullSession(body, "001", CLUSTER)).status) << "claimed " << claimed;
    }

    // The top of the range is still an id.
    SessionSpec top;
    top.agentId = "4294967295";
    EXPECT_TRUE(std::holds_alternative<ValidatedSession>(validateFullSession(
        invsync::test::buildSyncDataSession(top, {invsync::test::ValueSpec {}}), "4294967295", CLUSTER)));
}

TEST(FullSessionValidatorTest, NonNumericAgentIdsAre400NotSpoofing)
{
    SessionSpec spec;
    spec.agentId = "agent-one";
    const auto body = invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}});
    EXPECT_EQ(400, failureOf(validateFullSession(body, "001", CLUSTER)).status);

    const auto valid = invsync::test::buildSyncDataSession(SessionSpec {}, {invsync::test::ValueSpec {}});
    EXPECT_EQ(400, failureOf(validateFullSession(valid, "not-numeric", CLUSTER)).status);
}

TEST(FullSessionValidatorTest, ANonCanonicalAuthenticatedHeaderIs400)
{
    // remoted only ever forwards the canonical id; any other header means the request bypassed it.
    SessionSpec spec;
    spec.agentId = "1";
    const auto body = invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}});
    EXPECT_EQ(400, failureOf(validateFullSession(body, "1", CLUSTER)).status);

    const auto valid = invsync::test::buildSyncDataSession(SessionSpec {}, {invsync::test::ValueSpec {}});
    EXPECT_EQ(400, failureOf(validateFullSession(valid, "0001", CLUSTER)).status);
}

TEST(FullSessionValidatorTest, ClusterMismatchIs403AndMissingClusterIs400)
{
    const auto body = invsync::test::buildSyncDataSession(SessionSpec {}, {invsync::test::ValueSpec {}});
    EXPECT_EQ(403, failureOf(validateFullSession(body, "001", "another-cluster")).status);

    SessionSpec spec;
    spec.clusterName.clear();
    const auto missing = invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}});
    EXPECT_EQ(400, failureOf(validateFullSession(missing, "001", CLUSTER)).status);
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
            invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}}), "001", CLUSTER)))
            << "ModuleDelta x SyncData";
        EXPECT_TRUE(std::holds_alternative<ValidatedSession>(validateFullSession(
            invsync::test::buildCleansSession(spec, {"wazuh-states-inventory-packages"}), "001", CLUSTER)))
            << "ModuleDelta x Cleans (D6)";
    }
    {
        SessionSpec spec;
        spec.mode = fb::Mode_ModuleCheck;
        EXPECT_TRUE(std::holds_alternative<ValidatedSession>(validateFullSession(
            invsync::test::buildChecksumSession(spec, "wazuh-states-inventory-packages", "abc"), "001", CLUSTER)));
    }
    for (const auto mode : {fb::Mode_MetadataDelta, fb::Mode_MetadataCheck, fb::Mode_GroupDelta, fb::Mode_GroupCheck})
    {
        SessionSpec spec;
        spec.mode = mode;
        EXPECT_TRUE(std::holds_alternative<ValidatedSession>(
            validateFullSession(invsync::test::buildBareSession(spec), "001", CLUSTER)))
            << "mode " << static_cast<int>(mode) << " x NONE";
    }

    // Invalid combinations: every payload against a mode that does not accept it.
    {
        SessionSpec spec;
        spec.mode = fb::Mode_ModuleCheck; // wants ChecksumModule
        EXPECT_EQ(
            400,
            failureOf(validateFullSession(
                          invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}}), "001", CLUSTER))
                .status);
        EXPECT_EQ(400, failureOf(validateFullSession(invsync::test::buildBareSession(spec), "001", CLUSTER)).status);
    }
    {
        SessionSpec spec;
        spec.mode = fb::Mode_MetadataDelta; // wants NONE
        EXPECT_EQ(400,
                  failureOf(validateFullSession(
                                invsync::test::buildCleansSession(spec, {"wazuh-states-fim-files"}), "001", CLUSTER))
                      .status);
        EXPECT_EQ(
            400,
            failureOf(validateFullSession(
                          invsync::test::buildChecksumSession(spec, "wazuh-states-fim-files", "x"), "001", CLUSTER))
                .status);
    }
    {
        SessionSpec spec;
        spec.mode = fb::Mode_ModuleDelta; // data modes need a payload
        EXPECT_EQ(400, failureOf(validateFullSession(invsync::test::buildBareSession(spec), "001", CLUSTER)).status);
    }
}

TEST(FullSessionValidatorTest, SyncDataWithoutValuesIs400EvenWithContexts)
{
    // D8: contexts cannot stand alone; values >= 1 is the shape contract.
    const auto onlyContexts = invsync::test::buildSyncDataSession(SessionSpec {}, {}, {invsync::test::ContextSpec {}});
    EXPECT_EQ(400, failureOf(validateFullSession(onlyContexts, "001", CLUSTER)).status);

    const auto empty = invsync::test::buildSyncDataSession(SessionSpec {}, {});
    EXPECT_EQ(400, failureOf(validateFullSession(empty, "001", CLUSTER)).status);
}

TEST(FullSessionValidatorTest, EmptyCleansIs400)
{
    EXPECT_EQ(
        400,
        failureOf(validateFullSession(invsync::test::buildCleansSession(SessionSpec {}, {}), "001", CLUSTER)).status);
}

TEST(FullSessionValidatorTest, ChecksumRulesRejectBadIndexAndMissingChecksum)
{
    SessionSpec spec;
    spec.mode = invsync::schema::fb::Mode_ModuleCheck;

    // Index outside the allowlist is 400 (not skip-with-WARN: the whole session IS the check).
    EXPECT_EQ(400,
              failureOf(validateFullSession(invsync::test::buildChecksumSession(spec, "alerts", "abc"), "001", CLUSTER))
                  .status);
    EXPECT_EQ(
        400,
        failureOf(validateFullSession(invsync::test::buildChecksumSession(spec, "", "abc"), "001", CLUSTER)).status);
    EXPECT_EQ(
        400,
        failureOf(validateFullSession(
                      invsync::test::buildChecksumSession(spec, "wazuh-states-inventory-packages", ""), "001", CLUSTER))
            .status);
}

TEST(FullSessionValidatorTest, AValidatedSessionCarriesTheAuthenticatedIdAndTheStartFields)
{
    SessionSpec spec;
    spec.option = invsync::schema::fb::Option_VDFirst;
    spec.indices = {"wazuh-states-inventory-packages", "wazuh-states-inventory-processes"};
    spec.groups = {"default", "linux"};
    const auto body = invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}});

    const auto result = validateFullSession(body, "001", CLUSTER);
    const auto& session = sessionOf(result);

    EXPECT_EQ("001", session.agentId) << "the authenticated canonical id, the one every _id and wazuh.agent.id uses";
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

TEST(FullSessionValidatorTest, StartGroupsOverTheMultigroupLimitsAre400)
{
    SessionSpec tooMany;
    tooMany.groups.clear();
    for (std::size_t i = 0; i <= invsync::sync::MAX_START_GROUPS; ++i)
    {
        tooMany.groups.push_back("group-" + std::to_string(i));
    }
    const auto many = invsync::test::buildSyncDataSession(tooMany, {invsync::test::ValueSpec {}});
    EXPECT_EQ(400, failureOf(validateFullSession(many, "001", CLUSTER)).status);

    SessionSpec tooLong;
    tooLong.groups = {std::string(invsync::sync::MAX_START_GROUP_NAME_BYTES + 1, 'g')};
    const auto longName = invsync::test::buildSyncDataSession(tooLong, {invsync::test::ValueSpec {}});
    EXPECT_EQ(400, failureOf(validateFullSession(longName, "001", CLUSTER)).status);
}

TEST(FullSessionValidatorTest, StartIndicesOverTheirLimitsAre400)
{
    SessionSpec tooMany;
    tooMany.indices.assign(invsync::sync::MAX_START_INDICES + 1, "wazuh-states-inventory-packages");
    const auto many = invsync::test::buildSyncDataSession(tooMany, {invsync::test::ValueSpec {}});
    EXPECT_EQ(400, failureOf(validateFullSession(many, "001", CLUSTER)).status);

    SessionSpec tooLong;
    tooLong.indices = {std::string(invsync::sync::MAX_START_INDEX_NAME_BYTES + 1, 'i')};
    const auto longName = invsync::test::buildSyncDataSession(tooLong, {invsync::test::ValueSpec {}});
    EXPECT_EQ(400, failureOf(validateFullSession(longName, "001", CLUSTER)).status);
}

TEST(FullSessionValidatorTest, StartListsAtTheirLimitsValidate)
{
    // Both caps are inclusive: an honest agent in 128 groups with maximal names must still sync.
    SessionSpec spec;
    spec.groups.clear();
    for (std::size_t i = 0; i < invsync::sync::MAX_START_GROUPS; ++i)
    {
        auto name = std::to_string(i);
        name.resize(invsync::sync::MAX_START_GROUP_NAME_BYTES, 'g');
        spec.groups.push_back(std::move(name));
    }
    spec.indices.assign(invsync::sync::MAX_START_INDICES, std::string(invsync::sync::MAX_START_INDEX_NAME_BYTES, 'i'));
    const auto body = invsync::test::buildSyncDataSession(spec, {invsync::test::ValueSpec {}});

    const auto result = validateFullSession(body, "001", CLUSTER);
    const auto& session = sessionOf(result);
    EXPECT_EQ(invsync::sync::MAX_START_GROUPS, session.groups.size());
    EXPECT_EQ(invsync::sync::MAX_START_INDICES, session.indices.size());
}

TEST(FullSessionValidatorTest, VectorEntriesAliasingOneObjectAre400)
{
    using invsync::test::AliasedVector;

    // D25: every vector the validator walks, each holding ONE object referenced many times. The
    // FlatBuffers Verifier accepts all of them; the reachable-bytes budget must not. The Start lists
    // stay within D26's caps so it is the budget, not the caps, that refuses them.
    const std::string kibibyte(1024, 'x');
    const std::string groupName(invsync::sync::MAX_START_GROUP_NAME_BYTES, 'g');
    const std::tuple<AliasedVector, std::size_t, std::string, const char*> cases[] {
        {AliasedVector::Values, 1000, R"({"a":")" + kibibyte + R"("})", "values"},
        {AliasedVector::Contexts, 1000, R"({"a":")" + kibibyte + R"("})", "contexts"},
        {AliasedVector::CleanItems, 1000, "wazuh-states-inventory-packages", "clean items"},
        {AliasedVector::Groups, invsync::sync::MAX_START_GROUPS, groupName, "groups"},
        {AliasedVector::Indices, invsync::sync::MAX_START_INDICES, "wazuh-states-inventory-packages", "indices"},
    };
    for (const auto& [target, copies, payload, name] : cases)
    {
        const auto body = invsync::test::buildAliasedSession(SessionSpec {}, target, copies, payload);
        const auto result = validateFullSession(body, "001", CLUSTER);
        const auto& failure = failureOf(result);
        EXPECT_EQ(400, failure.status) << name;
        EXPECT_NE(std::string::npos, failure.reason.find("more data than it carries")) << name;
    }
}

TEST(FullSessionValidatorTest, AnAliasedVectorOfOneEntryIsJustAnHonestMessage)
{
    // The budget refuses sharing by its effect, not by its shape: a single reference is an
    // ordinary message, so the builder used above is not what is being rejected.
    using invsync::test::AliasedVector;
    const auto body = invsync::test::buildAliasedSession(SessionSpec {}, AliasedVector::Values, 1, R"({"a":1})");
    EXPECT_TRUE(std::holds_alternative<ValidatedSession>(validateFullSession(body, "001", CLUSTER)));
}

TEST(FullSessionValidatorTest, ManyDistinctSmallObjectsStayWithinTheBudget)
{
    // The budget's charges are LOWER bounds of what each object occupies, so a message that shares
    // nothing always fits its own size -- however many objects it has and however small they are,
    // including empty strings and absent data.
    std::vector<invsync::test::ValueSpec> values(5000);
    for (std::size_t i = 0; i < values.size(); ++i)
    {
        values[i].id = std::to_string(i);
        values[i].data = i % 2 == 0 ? std::string {} : std::string {"{}"};
        values[i].operation =
            i % 2 == 0 ? invsync::schema::fb::Operation_Delete : invsync::schema::fb::Operation_Upsert;
    }
    std::vector<invsync::test::ContextSpec> contexts(5000);
    for (std::size_t i = 0; i < contexts.size(); ++i)
    {
        contexts[i].id = std::to_string(i);
        contexts[i].data.clear();
    }
    const auto sync = invsync::test::buildSyncDataSession(SessionSpec {}, values, contexts);
    EXPECT_TRUE(std::holds_alternative<ValidatedSession>(validateFullSession(sync, "001", CLUSTER)));

    const std::vector<std::string> indices(5000, "wazuh-states-inventory-packages");
    const auto cleans = invsync::test::buildCleansSession(SessionSpec {}, indices);
    EXPECT_TRUE(std::holds_alternative<ValidatedSession>(validateFullSession(cleans, "001", CLUSTER)));
}
