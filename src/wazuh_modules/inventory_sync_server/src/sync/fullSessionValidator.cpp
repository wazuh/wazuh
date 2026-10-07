/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 4, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sync/fullSessionValidator.hpp"

#include "common/agentId.hpp"
#include "sync/stateIndexAllowlist.hpp"

#include <flatbuffers/flatbuffers.h>

namespace
{
    namespace fb = invsync::schema::fb;

    invsync::sync::ValidationFailure badRequest(std::string reason)
    {
        return {400, std::move(reason)};
    }

    invsync::sync::ValidationFailure forbidden(std::string reason)
    {
        return {403, std::move(reason)};
    }

    std::string_view viewOf(const flatbuffers::String* value)
    {
        return value ? value->string_view() : std::string_view {};
    }

    /// The mode x payload matrix (design doc 02 §2). Any combination outside it is a 400.
    bool modeAcceptsPayload(fb::Mode mode, fb::SessionPayload payload)
    {
        switch (mode)
        {
            // D6: cleans arrive with mode ModuleDelta today (the agent's sync protocol emits them
            // that way), so both payloads are legal and the router below picks by payload.
            case fb::Mode_ModuleDelta:
                return payload == fb::SessionPayload_SyncData || payload == fb::SessionPayload_Cleans;
            case fb::Mode_ModuleCheck: return payload == fb::SessionPayload_ChecksumModule;
            case fb::Mode_MetadataDelta:
            case fb::Mode_MetadataCheck:
            case fb::Mode_GroupDelta:
            case fb::Mode_GroupCheck: return payload == fb::SessionPayload_NONE;
            default: return false;
        }
    }
} // namespace

namespace invsync::sync
{

    ValidationResult validateFullSession(std::string_view body,
                                         std::string_view authenticatedAgentId,
                                         const std::string& managerClusterName)
    {
        // 1. Structural integrity of the whole buffer, before touching any accessor.
        flatbuffers::Verifier verifier(reinterpret_cast<const std::uint8_t*>(body.data()), body.size());
        if (!fb::VerifyMessageBuffer(verifier))
        {
            return badRequest("Body is not a valid inventory sync message");
        }

        // 2. This server accepts exactly one message type.
        const auto* message = fb::GetMessage(body.data());
        if (message->content_type() != fb::MessageType_FullSession)
        {
            return badRequest("Unsupported message type: expected FullSession");
        }
        // The verifier accepts a union whose type is set but whose value is absent, so the
        // discriminator alone does not guarantee a table: null-check every union accessor.
        const auto* session = message->content_as_FullSession();
        if (session == nullptr)
        {
            return badRequest("Message is missing its FullSession table");
        }

        // 3. Shape: a session says nothing without its Start.
        const auto* start = session->start();
        if (start == nullptr)
        {
            return badRequest("FullSession is missing its start table");
        }
        if (viewOf(start->module_()).empty())
        {
            return badRequest("Start is missing the module name");
        }

        // 4. Identity. The header carries the id remoted AUTHENTICATED (bearer token), always in its
        // canonical spelling; the session claims one. An agent id is a string: the claim must be that
        // same text, byte for byte. Comparing numbers instead let "0001" pass for "001" and then index
        // documents under an id no agent has, which the agent's deletion never matches. A claim that
        // is not a canonical id (not digits, out of range, or another spelling such as "0001") is
        // malformed input, 400; a well-formed id other than the authenticated one is spoofing, 403.
        const auto claimedAgentId = viewOf(start->agentid());
        if (!invsync::common::isCanonicalAgentId(claimedAgentId) ||
            !invsync::common::isCanonicalAgentId(authenticatedAgentId))
        {
            return badRequest("Agent id must be a canonical agent id");
        }
        if (claimedAgentId != authenticatedAgentId)
        {
            return forbidden("identity mismatch");
        }

        const auto claimedCluster = viewOf(start->cluster_name());
        if (claimedCluster.empty())
        {
            return badRequest("Start is missing the cluster name");
        }
        if (claimedCluster != managerClusterName)
        {
            return forbidden("identity mismatch");
        }

        // 5. mode x payload matrix.
        const auto mode = start->mode();
        const auto payloadType = session->payload_type();
        if (!modeAcceptsPayload(mode, payloadType))
        {
            return badRequest("Invalid mode/payload combination");
        }

        // 6. Per-payload shape.
        switch (payloadType)
        {
            case fb::SessionPayload_SyncData:
            {
                // D8: a data session must carry at least one DataValue. DataContext items are
                // vulnerability-detection side data and cannot stand alone.
                const auto* payload = session->payload_as_SyncData();
                if (payload == nullptr)
                {
                    return badRequest("FullSession is missing its SyncData table");
                }
                if (payload->values() == nullptr || payload->values()->size() == 0)
                {
                    return badRequest("SyncData must carry at least one value");
                }
                break;
            }
            case fb::SessionPayload_Cleans:
            {
                const auto* payload = session->payload_as_Cleans();
                if (payload == nullptr)
                {
                    return badRequest("FullSession is missing its Cleans table");
                }
                if (payload->items() == nullptr || payload->items()->size() == 0)
                {
                    return badRequest("Cleans must carry at least one item");
                }
                break;
            }
            case fb::SessionPayload_ChecksumModule:
            {
                const auto* payload = session->payload_as_ChecksumModule();
                if (payload == nullptr)
                {
                    return badRequest("FullSession is missing its ChecksumModule table");
                }
                const auto index = viewOf(payload->index());
                if (index.empty() || !isAgentScopedStateIndex(index))
                {
                    return badRequest("ChecksumModule index must be an agent-scoped state index");
                }
                if (viewOf(payload->checksum()).empty())
                {
                    return badRequest("ChecksumModule is missing the checksum");
                }
                break;
            }
            default: break; // NONE, already constrained by the matrix
        }

        // Validated: copy the small Start-derived fields out; the payload stays zero-copy.
        ValidatedSession validated;
        validated.session = session;
        validated.mode = mode;
        validated.option = start->option();
        validated.payloadType = payloadType;
        validated.isVD = start->option() == fb::Option_VDFirst || start->option() == fb::Option_VDSync;
        validated.moduleName = std::string {viewOf(start->module_())};
        // The authenticated id, not the claim: equal by now, but the stored identity must never be
        // one the agent chose.
        validated.agentId = std::string {authenticatedAgentId};
        validated.agentName = std::string {viewOf(start->agentname())};
        validated.agentVersion = std::string {viewOf(start->agentversion())};
        validated.architecture = std::string {viewOf(start->architecture())};
        validated.hostname = std::string {viewOf(start->hostname())};
        validated.osname = std::string {viewOf(start->osname())};
        validated.osplatform = std::string {viewOf(start->osplatform())};
        validated.ostype = std::string {viewOf(start->ostype())};
        validated.osversion = std::string {viewOf(start->osversion())};
        validated.globalVersion = start->global_version();
        validated.feedOffset = start->feed_offset();
        // Effective cluster: the session's (already validated equal to the manager's) with the
        // manager's as fallback -- same expression the legacy `_id` builder used.
        validated.clusterName = claimedCluster.empty() ? managerClusterName : std::string {claimedCluster};

        if (start->groups() != nullptr)
        {
            validated.groups.reserve(start->groups()->size());
            for (const auto* group : *start->groups())
            {
                if (group != nullptr)
                {
                    validated.groups.emplace_back(group->str());
                }
            }
        }
        if (start->index() != nullptr)
        {
            validated.indices.reserve(start->index()->size());
            for (const auto* index : *start->index())
            {
                if (index != nullptr)
                {
                    validated.indices.emplace_back(index->str());
                }
            }
        }

        return validated;
    }

} // namespace invsync::sync
