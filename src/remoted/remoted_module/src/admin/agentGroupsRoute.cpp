/*
 * Wazuh remoted module - Admin route POST /_internal/agents/groups
 * Copyright (C) 2015, Wazuh Inc.
 * September 29, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "agentGroupsRoute.hpp"
#include "control/groupSelector.hpp"
#include "json.hpp"
#include "loggerHelper.h"

#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace remoted::admin
{
    namespace
    {
        constexpr auto ADMIN_LOGTAG {"wazuh-manager-remoted:admin"};

        const LogFn& logFn()
        {
            static const LogFn instance {LogFn {ADMIN_LOGTAG}.compose("agent-groups")};
            return instance;
        }

        struct SetItem
        {
            control::AgentId id {0};
            std::vector<std::string> groups;
        };

        struct Publication
        {
            std::vector<SetItem> sets;
            std::vector<control::AgentId> invalidations;
        };

        // An agent id as the publisher writes it: a JSON unsigned integer naming a real agent. Never
        // a string, a float or a negative, and never 0 -- wazuh-db's agent-groups sync never yields
        // the manager's own row, so a 0 is a publisher bug like any other malformed id.
        bool readAgentId(const nlohmann::json& value, control::AgentId& out)
        {
            if (!value.is_number_unsigned())
            {
                return false;
            }
            const auto raw = value.get<std::uint64_t>();
            if (raw == 0 || raw > std::numeric_limits<control::AgentId>::max())
            {
                return false;
            }
            out = static_cast<control::AgentId>(raw);
            return true;
        }

        // A group name as it can appear in a membership: non-empty, and without the ',' that
        // separates the groups of a multigroup selector (a name with one would name another list).
        bool readGroupName(const nlohmann::json& value, std::string& out)
        {
            if (!value.is_string())
            {
                return false;
            }
            out = value.get<std::string>();
            return !out.empty() && out.find(',') == std::string::npos;
        }

        // The whole body, validated before anything is applied: the first defect is the 400's reason.
        // Non-throwing parse (invsync precedent): a malformed body is ordinary input, not an exception.
        std::optional<Publication> parsePublication(const std::string& body, const char*& reason)
        {
            const auto document = nlohmann::json::parse(body, nullptr, /*allow_exceptions=*/false);
            if (!document.is_object())
            {
                reason = "Body must be a JSON object";
                return std::nullopt;
            }

            const auto set = document.find("set");
            const auto invalidate = document.find("invalidate");
            if (set == document.end() && invalidate == document.end())
            {
                reason = R"(Body must carry "set", "invalidate" or both)";
                return std::nullopt;
            }

            Publication publication;
            if (set != document.end())
            {
                if (!set->is_array())
                {
                    reason = R"("set" must be an array)";
                    return std::nullopt;
                }
                publication.sets.reserve(set->size());
                for (const auto& element : *set)
                {
                    SetItem item;
                    const auto id = element.is_object() ? element.find("id") : element.end();
                    if (!element.is_object() || id == element.end() || !readAgentId(*id, item.id))
                    {
                        reason = R"(Every "set" element must be an object with an "id" from 1 to 4294967295)";
                        return std::nullopt;
                    }
                    const auto groups = element.find("groups");
                    if (groups == element.end() || !groups->is_array())
                    {
                        reason = R"(Every "set" element must carry a "groups" array)";
                        return std::nullopt;
                    }
                    item.groups.reserve(groups->size());
                    for (const auto& group : *groups)
                    {
                        std::string name;
                        if (!readGroupName(group, name))
                        {
                            reason = "Group names must be non-empty strings without ','";
                            return std::nullopt;
                        }
                        item.groups.push_back(std::move(name));
                    }
                    publication.sets.push_back(std::move(item));
                }
            }

            if (invalidate != document.end())
            {
                if (!invalidate->is_array())
                {
                    reason = R"("invalidate" must be an array)";
                    return std::nullopt;
                }
                publication.invalidations.reserve(invalidate->size());
                for (const auto& element : *invalidate)
                {
                    control::AgentId id = 0;
                    if (!readAgentId(element, id))
                    {
                        reason = R"(Every "invalidate" element must be an id from 1 to 4294967295)";
                        return std::nullopt;
                    }
                    publication.invalidations.push_back(id);
                }
            }
            return publication;
        }

        wazuh::uds_http::HttpResponse errorResponse(int status, const char* message)
        {
            return wazuh::uds_http::HttpResponse::json(status,
                                                       nlohmann::json {{"error", message}, {"code", status}}.dump());
        }

        uint64_t wallSec()
        {
            return static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count());
        }
    } // namespace

    wazuh::uds_http::RouteHandler makeAgentGroupsHandler(std::weak_ptr<control::AgentRegistry> registry,
                                                         control::PushMetrics metrics)
    {
        return [registry = std::move(registry),
                metrics = std::move(metrics)](std::shared_ptr<const wazuh::uds_http::HttpRequest> request,
                                              std::shared_ptr<wazuh::uds_http::IHttpResponder> responder)
        {
            // Debug only for refusals: the caller is a local daemon, so a 400 is its bug, not an
            // attack worth a warning -- and remoted.control.registry.push.rejected counts every one.
            const char* reason = "";
            auto publication = parsePublication(request->body, reason);
            if (!publication)
            {
                control::addPush(metrics.rejected);
                LOGFN_DEBUG1(logFn(), "Refused a membership publication: %s.", reason);
                responder->send(errorResponse(400, reason));
                return;
            }

            const auto target = registry.lock();
            if (!target)
            {
                control::addPush(metrics.rejected);
                LOGFN_DEBUG1(logFn(), "Refused a membership publication: the agent registry is gone (stopping).");
                responder->send(errorResponse(503, "registry unavailable"));
                return;
            }

            const uint64_t now = wallSec();
            uint64_t updated = 0;
            uint64_t invalidated = 0;
            uint64_t skipped = 0;
            for (auto& item : publication->sets)
            {
                const auto outcome = target->setGroups(item.id, control::membershipGroups(std::move(item.groups)), now);
                (outcome == control::AgentRegistry::PushOutcome::Updated ? updated : skipped) += 1;
            }
            for (const auto id : publication->invalidations)
            {
                const auto outcome = target->invalidateGroups(id);
                (outcome == control::AgentRegistry::PushOutcome::Invalidated ? invalidated : skipped) += 1;
            }

            control::addPush(metrics.updated, updated);
            control::addPush(metrics.invalidated, invalidated);
            control::addPush(metrics.skipped, skipped);
            LOGFN_DEBUG1(logFn(),
                         "Applied a membership publication: %llu updated, %llu invalidated, %llu skipped.",
                         static_cast<unsigned long long>(updated),
                         static_cast<unsigned long long>(invalidated),
                         static_cast<unsigned long long>(skipped));

            responder->send(wazuh::uds_http::HttpResponse::json(
                200, nlohmann::json {{"updated", updated}, {"invalidated", invalidated}, {"skipped", skipped}}.dump()));
        };
    }
} // namespace remoted::admin
