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

#include "schema/syncSchema.hpp"

#include <flatbuffers/flatbuffers.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

/*
 * Locks the FINAL wire contract agreed with the agent team (the shared
 * shared_modules/utils/flatbuffers/schemas/inventorySync.fbs since the legacy schema retired).
 *
 * The enum-discriminant tests are not busywork: an innocent-looking reordering of the schema (or a
 * divergence introduced while merging upstream changes) would silently produce buffers the agent
 * misreads. Pinning the numeric values makes such a drift a test failure instead of a fleet-wide
 * protocol bug.
 */

namespace fb = invsync::schema::fb;

namespace
{

    /// Builds a minimal-but-representative Start table. Metadata strings the tests do not assert on
    /// stay null on purpose: every field of Start is optional at the FlatBuffers level.
    flatbuffers::Offset<fb::Start>
    makeStart(flatbuffers::FlatBufferBuilder& builder, fb::Mode mode, fb::Option option = fb::Option_Sync)
    {
        std::vector<flatbuffers::Offset<flatbuffers::String>> indexVector {
            builder.CreateString("wazuh-states-inventory-packages")};
        return fb::CreateStartDirect(builder,
                                     "syscollector",
                                     mode,
                                     &indexVector,
                                     option,
                                     nullptr, // architecture
                                     nullptr, // hostname
                                     nullptr, // osname
                                     nullptr, // osplatform
                                     nullptr, // ostype
                                     nullptr, // osversion
                                     nullptr, // agentversion
                                     nullptr, // agentname
                                     "001",
                                     nullptr, // groups
                                     3,       // global_version
                                     "cluster01");
    }

    /// Finishes the buffer and returns the verified root, failing the test on a verifier rejection.
    const fb::Message* finishAndVerify(flatbuffers::FlatBufferBuilder& builder,
                                       flatbuffers::Offset<fb::Message> message)
    {
        builder.Finish(message);
        flatbuffers::Verifier verifier(builder.GetBufferPointer(), builder.GetSize());
        EXPECT_TRUE(fb::VerifyMessageBuffer(verifier));
        return fb::GetMessage(builder.GetBufferPointer());
    }

} // namespace

TEST(SchemaContractTest, ModeDiscriminantsMatchTheAgreedContract)
{
    EXPECT_EQ(0, static_cast<int>(fb::Mode_ModuleDelta));
    EXPECT_EQ(1, static_cast<int>(fb::Mode_ModuleCheck));
    EXPECT_EQ(2, static_cast<int>(fb::Mode_MetadataDelta));
    EXPECT_EQ(3, static_cast<int>(fb::Mode_MetadataCheck));
    EXPECT_EQ(4, static_cast<int>(fb::Mode_GroupDelta));
    EXPECT_EQ(5, static_cast<int>(fb::Mode_GroupCheck));
    // There is deliberately NO ModuleFull: a full resync is Cleans + ModuleDelta, two requests.
    EXPECT_EQ(fb::Mode_GroupCheck, fb::Mode_MAX);
}

TEST(SchemaContractTest, OperationAndOptionDiscriminantsMatchTheAgreedContract)
{
    EXPECT_EQ(0, static_cast<int>(fb::Operation_Upsert));
    EXPECT_EQ(1, static_cast<int>(fb::Operation_Delete));
    EXPECT_EQ(0, static_cast<int>(fb::Option_Sync));
    EXPECT_EQ(1, static_cast<int>(fb::Option_VDFirst));
    EXPECT_EQ(2, static_cast<int>(fb::Option_VDSync));
}

TEST(SchemaContractTest, SessionPayloadMembersMatchTheAgreedContract)
{
    EXPECT_EQ(0, static_cast<int>(fb::SessionPayload_NONE));
    EXPECT_EQ(1, static_cast<int>(fb::SessionPayload_SyncData));
    EXPECT_EQ(2, static_cast<int>(fb::SessionPayload_Cleans));
    // ChecksumModule is a DIRECT union member: "exactly one checksum per request" is imposed by the
    // schema itself, not by a validator rule.
    EXPECT_EQ(3, static_cast<int>(fb::SessionPayload_ChecksumModule));
    EXPECT_EQ(fb::SessionPayload_ChecksumModule, fb::SessionPayload_MAX);
}

TEST(SchemaContractTest, MessageTypeKeepsTheLegacyMembersAndAddsFullSession)
{
    // The legacy direct members keep their slots; FullSession is the only
    // member this server accepts.
    EXPECT_EQ(1, static_cast<int>(fb::MessageType_DataValue));
    EXPECT_EQ(2, static_cast<int>(fb::MessageType_DataClean));
    EXPECT_EQ(3, static_cast<int>(fb::MessageType_ChecksumModule));
    EXPECT_EQ(4, static_cast<int>(fb::MessageType_Start));
    EXPECT_EQ(5, static_cast<int>(fb::MessageType_DataContext));
    EXPECT_EQ(6, static_cast<int>(fb::MessageType_FullSession));
    EXPECT_EQ(fb::MessageType_FullSession, fb::MessageType_MAX);
}

TEST(SchemaRoundtripTest, FullSessionWithSyncDataRoundTrips)
{
    flatbuffers::FlatBufferBuilder builder;

    const std::vector<int8_t> documentBytes {'{', '"', 'k', '"', ':', '1', '}'};
    std::vector<flatbuffers::Offset<fb::DataValue>> values {fb::CreateDataValueDirect(
        builder, fb::Operation_Upsert, "id-1", "wazuh-states-inventory-packages", 7, &documentBytes)};
    std::vector<flatbuffers::Offset<fb::DataContext>> contexts {
        fb::CreateDataContextDirect(builder, "ctx-1", "wazuh-states-vulnerabilities", &documentBytes)};
    const auto syncData = fb::CreateSyncDataDirect(builder, &values, &contexts);

    const auto fullSession = fb::CreateFullSession(builder,
                                                   makeStart(builder, fb::Mode_ModuleDelta, fb::Option_VDFirst),
                                                   fb::SessionPayload_SyncData,
                                                   syncData.Union());
    const auto* parsed =
        finishAndVerify(builder, fb::CreateMessage(builder, fb::MessageType_FullSession, fullSession.Union()));

    ASSERT_EQ(fb::MessageType_FullSession, parsed->content_type());
    const auto* session = parsed->content_as_FullSession();
    ASSERT_NE(nullptr, session);

    const auto* start = session->start();
    ASSERT_NE(nullptr, start);
    // flatc escapes the reserved word `module` to `module_` in the generated accessor.
    EXPECT_EQ("syscollector", start->module_()->str());
    EXPECT_EQ(fb::Mode_ModuleDelta, start->mode());
    EXPECT_EQ(fb::Option_VDFirst, start->option());
    EXPECT_EQ("001", start->agentid()->str());
    EXPECT_EQ(3U, start->global_version());
    EXPECT_EQ("cluster01", start->cluster_name()->str());
    ASSERT_EQ(1U, start->index()->size());
    EXPECT_EQ("wazuh-states-inventory-packages", start->index()->Get(0)->str());

    ASSERT_EQ(fb::SessionPayload_SyncData, session->payload_type());
    const auto* payload = session->payload_as_SyncData();
    ASSERT_NE(nullptr, payload);
    ASSERT_EQ(1U, payload->values()->size());
    const auto* value = payload->values()->Get(0);
    EXPECT_EQ(fb::Operation_Upsert, value->operation());
    EXPECT_EQ("id-1", value->id()->str());
    EXPECT_EQ(7U, value->version());
    ASSERT_NE(nullptr, value->data());
    EXPECT_EQ(documentBytes.size(), value->data()->size());
    ASSERT_EQ(1U, payload->contexts()->size());
    EXPECT_EQ("ctx-1", payload->contexts()->Get(0)->id()->str());
}

TEST(SchemaRoundtripTest, FullSessionWithCleansRoundTrips)
{
    flatbuffers::FlatBufferBuilder builder;

    std::vector<flatbuffers::Offset<fb::DataClean>> items {
        fb::CreateDataCleanDirect(builder, "wazuh-states-fim-files"),
        fb::CreateDataCleanDirect(builder, "wazuh-states-fim-registry-keys")};
    const auto cleans = fb::CreateCleansDirect(builder, &items);

    const auto fullSession = fb::CreateFullSession(
        builder, makeStart(builder, fb::Mode_ModuleDelta), fb::SessionPayload_Cleans, cleans.Union());
    const auto* parsed =
        finishAndVerify(builder, fb::CreateMessage(builder, fb::MessageType_FullSession, fullSession.Union()));

    const auto* session = parsed->content_as_FullSession();
    ASSERT_NE(nullptr, session);
    ASSERT_EQ(fb::SessionPayload_Cleans, session->payload_type());
    const auto* payload = session->payload_as_Cleans();
    ASSERT_NE(nullptr, payload);
    ASSERT_EQ(2U, payload->items()->size());
    EXPECT_EQ("wazuh-states-fim-files", payload->items()->Get(0)->index()->str());
    EXPECT_EQ("wazuh-states-fim-registry-keys", payload->items()->Get(1)->index()->str());
}

TEST(SchemaRoundtripTest, FullSessionWithAChecksumRoundTrips)
{
    flatbuffers::FlatBufferBuilder builder;

    const auto checksum = fb::CreateChecksumModuleDirect(builder, "wazuh-states-inventory-packages", "a1b2c3d4");
    const auto fullSession = fb::CreateFullSession(
        builder, makeStart(builder, fb::Mode_ModuleCheck), fb::SessionPayload_ChecksumModule, checksum.Union());
    const auto* parsed =
        finishAndVerify(builder, fb::CreateMessage(builder, fb::MessageType_FullSession, fullSession.Union()));

    const auto* session = parsed->content_as_FullSession();
    ASSERT_NE(nullptr, session);
    ASSERT_EQ(fb::SessionPayload_ChecksumModule, session->payload_type());
    const auto* payload = session->payload_as_ChecksumModule();
    ASSERT_NE(nullptr, payload);
    EXPECT_EQ("wazuh-states-inventory-packages", payload->index()->str());
    EXPECT_EQ("a1b2c3d4", payload->checksum()->str());
}

TEST(SchemaRoundtripTest, MetadataSessionWithoutPayloadRoundTrips)
{
    // Metadata*/Group* sessions travel with payload NONE: everything they say is in Start.
    flatbuffers::FlatBufferBuilder builder;

    const auto fullSession = fb::CreateFullSession(builder, makeStart(builder, fb::Mode_MetadataDelta));
    const auto* parsed =
        finishAndVerify(builder, fb::CreateMessage(builder, fb::MessageType_FullSession, fullSession.Union()));

    const auto* session = parsed->content_as_FullSession();
    ASSERT_NE(nullptr, session);
    EXPECT_EQ(fb::SessionPayload_NONE, session->payload_type());
    EXPECT_EQ(nullptr, session->payload());
    EXPECT_EQ(fb::Mode_MetadataDelta, session->start()->mode());
}

TEST(SchemaRoundtripTest, ALegacyDirectMemberIsStillExpressible)
{
    // The server rejects these with 400, but the schema must keep carrying them.
    flatbuffers::FlatBufferBuilder builder;

    const auto start = makeStart(builder, fb::Mode_ModuleDelta);
    const auto* parsed = finishAndVerify(builder, fb::CreateMessage(builder, fb::MessageType_Start, start.Union()));

    ASSERT_EQ(fb::MessageType_Start, parsed->content_type());
    ASSERT_NE(nullptr, parsed->content_as_Start());
    EXPECT_EQ("syscollector", parsed->content_as_Start()->module_()->str());
}
