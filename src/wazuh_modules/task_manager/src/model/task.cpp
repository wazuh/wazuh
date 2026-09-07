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

#include "task.hpp"

namespace task_manager
{
    std::string_view toString(const TaskStatus status) noexcept
    {
        switch (status)
        {
            case TaskStatus::Pending: return "pending";
            case TaskStatus::Claimed: return "claimed";
            case TaskStatus::Completed: return "completed";
            case TaskStatus::Failed: return "failed";
            case TaskStatus::DeadLetter: return "dead_letter";
            case TaskStatus::Superseded: return "superseded";
        }
        return "pending";
    }

    std::string_view toString(const Outcome outcome) noexcept
    {
        switch (outcome)
        {
            case Outcome::Ok: return "ok";
            case Outcome::Retryable: return "retryable";
            case Outcome::Timeout: return "timeout";
            case Outcome::Terminal: return "terminal";
            case Outcome::NotReady: return "not_ready";
            case Outcome::Busy: return "busy";
            case Outcome::Incomplete: return "incomplete";
        }
        return "retryable";
    }

    std::string_view toString(const CreateResult result) noexcept
    {
        switch (result)
        {
            case CreateResult::Created: return "created";
            case CreateResult::Coalesced: return "coalesced";
            case CreateResult::Collided: return "collided";
            case CreateResult::QueueFull: return "queue_full";
        }
        return "created";
    }

    std::optional<TaskStatus> taskStatusFromString(const std::string_view text) noexcept
    {
        if (text == "pending")
        {
            return TaskStatus::Pending;
        }
        if (text == "claimed")
        {
            return TaskStatus::Claimed;
        }
        if (text == "completed")
        {
            return TaskStatus::Completed;
        }
        if (text == "failed")
        {
            return TaskStatus::Failed;
        }
        if (text == "dead_letter")
        {
            return TaskStatus::DeadLetter;
        }
        if (text == "superseded")
        {
            return TaskStatus::Superseded;
        }
        return std::nullopt;
    }
} // namespace task_manager
