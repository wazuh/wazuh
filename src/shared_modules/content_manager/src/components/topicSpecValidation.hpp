/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _TOPIC_SPEC_VALIDATION_HPP
#define _TOPIC_SPEC_VALIDATION_HPP

#include "contentTopicSpec.hpp"
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

/**
 * @brief Reject a registration the cycle could not run, naming the field at fault.
 *
 * The struct's shape already rules out unknown keys and mixed strategies; what is left is the values.
 *
 * @param spec The registration.
 * @throws std::invalid_argument naming the first invalid field.
 */
inline void validateTopicSpec(const content_manager::TopicSpec& spec)
{
    const auto fail = [](const std::string& message)
    {
        throw std::invalid_argument {message};
    };
    const auto requireStrings = [&fail](const std::vector<std::string>& values, const std::string& field)
    {
        for (const auto& value : values)
        {
            if (value.empty())
            {
                fail(field + ": entries must be non-empty");
            }
        }
    };
    const auto requirePointer = [&fail](const std::string& pointer, const std::string& field)
    {
        if (pointer.size() < 2 || pointer.front() != '/')
        {
            fail(field + ": '" + pointer + "' is not a JSON pointer to a field");
        }
    };
    const auto requireObject = [&fail](const std::optional<nlohmann::json>& value, const std::string& field)
    {
        if (value.has_value() && !value->is_object())
        {
            fail(field + ": must be an object");
        }
    };

    if (spec.schedule.intervalSeconds.has_value() && *spec.schedule.intervalSeconds == 0)
    {
        fail("schedule.intervalSeconds: must be positive");
    }

    if (spec.source.indices.empty())
    {
        fail("source.indices: at least one index is required");
    }
    requireStrings(spec.source.indices, "source.indices");
    requireObject(spec.source.query, "source.query");
    requireObject(spec.source.sourceFilter, "source.sourceFilter");
    if (spec.source.pageSize == 0)
    {
        fail("source.pageSize: must be positive");
    }
    if (spec.source.slices == 0)
    {
        fail("source.slices: must be positive");
    }
    if (spec.source.pitKeepAlive.empty())
    {
        fail("source.pitKeepAlive: must not be empty");
    }

    if (spec.readiness.has_value())
    {
        // Both defences against consumer documents leaking into the content — the query-side
        // `must_not` on `_index` and the hit-side drop — compare against the `_index` metafield,
        // which reports the concrete backing index. A pattern or a list would never match, so the
        // leak would be silent; this is the only place it is cheap to catch.
        const auto& index = spec.readiness->consumerIndex;
        if (index.empty() || index.find_first_of("*,") != std::string::npos || index.front() == '-')
        {
            fail("readiness.consumerIndex: must be a concrete index name (no wildcard, list or exclusion): '" + index +
                 "'");
        }
        if (spec.readiness->consumerId.empty())
        {
            fail("readiness.consumerId: must not be empty");
        }
        if (spec.readiness->retrySeconds == 0)
        {
            fail("readiness.retrySeconds: must be positive");
        }
    }

    if (const auto* cursor = std::get_if<content_manager::CursorDetection>(&spec.detection))
    {
        if (cursor->field.empty() || cursor->unmappedType.empty())
        {
            fail("detection: a cursor needs a field and its unmapped type");
        }
    }
    else
    {
        const auto& hash = std::get<content_manager::HashDetection>(spec.detection);
        if (const auto* document = std::get_if<content_manager::DocumentProbe>(&hash.probe))
        {
            if (document->id.empty())
            {
                fail("detection.probe.id: must not be empty");
            }
        }
        else if (!std::get<content_manager::QueryProbe>(hash.probe).query.is_object())
        {
            fail("detection.probe.query: must be an object");
        }
        if (hash.tokenPointers.empty())
        {
            fail("detection.tokenPointers: at least one pointer is required");
        }
        for (const auto& pointer : hash.tokenPointers)
        {
            requirePointer(pointer, "detection.tokenPointers");
        }
        for (const auto& [name, pointer] : hash.metadata)
        {
            requirePointer(pointer, "detection.metadata." + name);
        }
    }

    requireStrings(spec.fullLoad.requiredDocumentIds, "fullLoad.requiredDocumentIds");
}

#endif // _TOPIC_SPEC_VALIDATION_HPP
