/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "taskId.hpp"

#include <hashHelper.h>

#include <array>
#include <cstddef>
#include <cstdio>

namespace
{
    constexpr std::array<char, 16> HEX_DIGITS {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    std::string toHex(const unsigned char* bytes, const std::size_t count)
    {
        std::string hex;
        hex.reserve(count * 2);
        for (std::size_t i = 0; i < count; ++i)
        {
            hex.push_back(HEX_DIGITS[bytes[i] >> 4U]);
            hex.push_back(HEX_DIGITS[bytes[i] & 0x0FU]);
        }
        return hex;
    }
} // namespace

namespace task_manager::taskId
{
    std::string sha256Hex(const std::string_view data)
    {
        Utils::HashData hash {Utils::HashType::Sha256};
        hash.update(data.data(), data.size());
        const auto digest {hash.hash()};
        return toHex(digest.data(), digest.size());
    }

    std::string forScheduledRun(const std::string_view scheduleId, const Timestamp scheduledRunAt)
    {
        std::string input {"mt:sched:"};
        input.append(scheduleId);
        input.push_back(':');
        input.append(std::to_string(scheduledRunAt));
        return sha256Hex(input);
    }

    std::string forAgentTask(const std::string_view sourceId,
                             const std::string_view agentId,
                             const std::string_view taskType,
                             const Timestamp createTime)
    {
        std::string input;
        if (!sourceId.empty())
        {
            input.append(sourceId);
            input.push_back(':');
        }
        input.append(agentId);
        input.push_back(':');
        input.append(taskType);
        input.push_back(':');
        input.append(std::to_string(createTime));

        Utils::HashData hash {Utils::HashType::Sha256};
        hash.update(input.data(), input.size());
        const auto digest {hash.hash()};

        // 8-4-4-4-12 over the first 16 bytes. Truncated on purpose -- see the header.
        const auto hex {toHex(digest.data(), 16)};
        std::string id;
        id.reserve(36);
        id.append(hex, 0, 8);
        id.push_back('-');
        id.append(hex, 8, 4);
        id.push_back('-');
        id.append(hex, 12, 4);
        id.push_back('-');
        id.append(hex, 16, 4);
        id.push_back('-');
        id.append(hex, 20, 12);
        return id;
    }
} // namespace task_manager::taskId
