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

#ifndef _INVSYNC_TEST_SESSION_BUILDER_HPP
#define _INVSYNC_TEST_SESSION_BUILDER_HPP

#include "schema/syncSchema.hpp"

#include <flatbuffers/flatbuffers.h>

#include <cstdint>
#include <string>
#include <vector>

namespace invsync::test
{

    namespace fb = invsync::schema::fb;

    /// Start-table knobs shared by every builder below; the defaults form a session the validator
    /// accepts for agent "1" in cluster "test-cluster" (what the module tests configure).
    struct SessionSpec
    {
        std::string moduleName {"syscollector"};
        fb::Mode mode {fb::Mode_ModuleDelta};
        fb::Option option {fb::Option_Sync};
        std::string agentId {"1"};
        std::string agentName {"agent-one"};
        std::string agentVersion {"v5.0.0"};
        std::string architecture {"x86_64"};
        std::string hostname {"host-one"};
        std::string osname {"Ubuntu"};
        std::string osplatform {"ubuntu"};
        std::string ostype {"linux"};
        std::string osversion {"22.04"};
        std::vector<std::string> groups {"default"};
        std::vector<std::string> indices {"wazuh-states-inventory-packages"};
        std::uint64_t globalVersion {3};
        std::string clusterName {"test-cluster"};
        /// Start.feed_offset. Only meaningful for VD sessions (option VDFirst/VDSync); see
        /// fullSessionValidator.hpp's ValidatedSession::feedOffset.
        std::uint64_t feedOffset {0};
    };

    /// One DataValue of a SyncData payload.
    struct ValueSpec
    {
        fb::Operation operation {fb::Operation_Upsert};
        std::string id {"doc-1"};
        std::string index {"wazuh-states-inventory-packages"};
        std::string data {R"({"package":{"name":"vim"}})"};
        std::uint64_t version {0};
        /// -1 keeps `operation` as-is; any other value is written RAW into the field, letting a
        /// test forge an out-of-enum discriminant (the validator must answer 400).
        int rawOperation {-1};
    };

    struct ContextSpec
    {
        std::string id {"ctx-1"};
        std::string index {"wazuh-states-vulnerabilities"};
        std::string data {R"({"os":{"name":"Ubuntu"}})"};
    };

    inline flatbuffers::Offset<fb::Start> buildStart(flatbuffers::FlatBufferBuilder& builder, const SessionSpec& spec)
    {
        std::vector<flatbuffers::Offset<flatbuffers::String>> indexVector;
        indexVector.reserve(spec.indices.size());
        for (const auto& index : spec.indices)
        {
            indexVector.push_back(builder.CreateString(index));
        }
        std::vector<flatbuffers::Offset<flatbuffers::String>> groupVector;
        groupVector.reserve(spec.groups.size());
        for (const auto& group : spec.groups)
        {
            groupVector.push_back(builder.CreateString(group));
        }

        return fb::CreateStartDirect(builder,
                                     spec.moduleName.empty() ? nullptr : spec.moduleName.c_str(),
                                     spec.mode,
                                     indexVector.empty() ? nullptr : &indexVector,
                                     spec.option,
                                     spec.architecture.c_str(),
                                     spec.hostname.c_str(),
                                     spec.osname.c_str(),
                                     spec.osplatform.c_str(),
                                     spec.ostype.c_str(),
                                     spec.osversion.c_str(),
                                     spec.agentVersion.c_str(),
                                     spec.agentName.c_str(),
                                     spec.agentId.empty() ? nullptr : spec.agentId.c_str(),
                                     groupVector.empty() ? nullptr : &groupVector,
                                     spec.globalVersion,
                                     spec.clusterName.empty() ? nullptr : spec.clusterName.c_str(),
                                     spec.feedOffset);
    }

    inline std::string finishSession(flatbuffers::FlatBufferBuilder& builder,
                                     flatbuffers::Offset<fb::Start> start,
                                     fb::SessionPayload payloadType,
                                     flatbuffers::Offset<void> payload)
    {
        const auto fullSession = fb::CreateFullSession(builder, start, payloadType, payload);
        builder.Finish(fb::CreateMessage(builder, fb::MessageType_FullSession, fullSession.Union()));
        return {reinterpret_cast<const char*>(builder.GetBufferPointer()), builder.GetSize()};
    }

    /// Message{FullSession{start, SyncData{values, contexts}}} as raw wire bytes.
    inline std::string buildSyncDataSession(const SessionSpec& spec,
                                            const std::vector<ValueSpec>& values,
                                            const std::vector<ContextSpec>& contexts = {})
    {
        flatbuffers::FlatBufferBuilder builder;

        std::vector<flatbuffers::Offset<fb::DataValue>> valueOffsets;
        valueOffsets.reserve(values.size());
        for (const auto& value : values)
        {
            const std::vector<std::int8_t> bytes {value.data.begin(), value.data.end()};
            const auto operation =
                value.rawOperation >= 0 ? static_cast<fb::Operation>(value.rawOperation) : value.operation;
            valueOffsets.push_back(fb::CreateDataValueDirect(builder,
                                                             operation,
                                                             value.id.empty() ? nullptr : value.id.c_str(),
                                                             value.index.c_str(),
                                                             value.version,
                                                             value.data.empty() ? nullptr : &bytes));
        }

        std::vector<flatbuffers::Offset<fb::DataContext>> contextOffsets;
        contextOffsets.reserve(contexts.size());
        for (const auto& context : contexts)
        {
            const std::vector<std::int8_t> bytes {context.data.begin(), context.data.end()};
            contextOffsets.push_back(
                fb::CreateDataContextDirect(builder, context.id.c_str(), context.index.c_str(), &bytes));
        }

        const auto payload = fb::CreateSyncDataDirect(builder,
                                                      valueOffsets.empty() ? nullptr : &valueOffsets,
                                                      contextOffsets.empty() ? nullptr : &contextOffsets);
        return finishSession(builder, buildStart(builder, spec), fb::SessionPayload_SyncData, payload.Union());
    }

    /// Message{FullSession{start, Cleans{items}}} as raw wire bytes.
    inline std::string buildCleansSession(const SessionSpec& spec, const std::vector<std::string>& indices)
    {
        flatbuffers::FlatBufferBuilder builder;

        std::vector<flatbuffers::Offset<fb::DataClean>> items;
        items.reserve(indices.size());
        for (const auto& index : indices)
        {
            items.push_back(fb::CreateDataCleanDirect(builder, index.c_str()));
        }

        const auto payload = fb::CreateCleansDirect(builder, items.empty() ? nullptr : &items);
        return finishSession(builder, buildStart(builder, spec), fb::SessionPayload_Cleans, payload.Union());
    }

    /// Message{FullSession{start, ChecksumModule}} as raw wire bytes.
    inline std::string
    buildChecksumSession(const SessionSpec& spec, const std::string& index, const std::string& checksum)
    {
        flatbuffers::FlatBufferBuilder builder;
        const auto payload = fb::CreateChecksumModuleDirect(
            builder, index.empty() ? nullptr : index.c_str(), checksum.empty() ? nullptr : checksum.c_str());
        return finishSession(builder, buildStart(builder, spec), fb::SessionPayload_ChecksumModule, payload.Union());
    }

    /// Message{FullSession{start}} with NO payload (the Metadata*/Group* shape).
    inline std::string buildBareSession(const SessionSpec& spec)
    {
        flatbuffers::FlatBufferBuilder builder;
        return finishSession(builder, buildStart(builder, spec), fb::SessionPayload_NONE, 0);
    }

    /// A legacy-style direct member (Message{Start}) -- the server must answer 400.
    inline std::string buildLegacyStartMessage(const SessionSpec& spec)
    {
        flatbuffers::FlatBufferBuilder builder;
        const auto start = buildStart(builder, spec);
        builder.Finish(fb::CreateMessage(builder, fb::MessageType_Start, start.Union()));
        return {reinterpret_cast<const char*>(builder.GetBufferPointer()), builder.GetSize()};
    }

} // namespace invsync::test

#endif // _INVSYNC_TEST_SESSION_BUILDER_HPP
