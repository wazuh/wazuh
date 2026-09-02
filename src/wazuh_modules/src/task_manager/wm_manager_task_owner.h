/*
 * Wazuh Module for Task management: manager task ownership.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * A claimed row names the lane that holds it. Deciding whether that claim is still live is the
 * one piece of this design that can make things worse than what it replaces: reclaim a row whose
 * lane is still working on it and the work runs twice, with the second copy started by the very
 * mechanism meant to prevent that.
 *
 * OWNER is "<pid>:<process start time>:<lane>". The start time is in it because a pid on its own
 * is not an identity: pids are recycled, and a recycled one would let a stranger's process pass
 * as the lane that made the claim.
 */
#ifndef WM_MANAGER_TASK_OWNER_H
#define WM_MANAGER_TASK_OWNER_H

#include "shared.h"
#include "wm_manager_task_registry.h"

/// Longest OWNER string: two integers, a lane name and two separators.
#define WM_MANAGER_TASK_OWNER_LEN 64

/**
 * @brief A parsed OWNER, or this process's own identity.
 */
typedef struct _wm_manager_task_owner {
    pid_t pid;
    unsigned long long start_time; ///< Field 22 of /proc/<pid>/stat, in clock ticks since boot.
    char lane[32];                 ///< Lane name and index, such as "delete-2".
} wm_manager_task_owner;

/**
 * @brief What a claimed row's OWNER says about whether the claim is still live.
 */
typedef enum _wm_manager_task_owner_kind {
    WM_MANAGER_TASK_OWNER_DEAD = 0,   ///< The process is gone, or its pid has been recycled.
    WM_MANAGER_TASK_OWNER_MINE,       ///< A lane of this process instance.
    WM_MANAGER_TASK_OWNER_FOREIGN,    ///< Alive, and not us.
    WM_MANAGER_TASK_OWNER_UNPARSEABLE ///< Not an OWNER this build wrote.
} wm_manager_task_owner_kind;

/**
 * @brief Capture this process's identity, for comparison against the rows it claims.
 *
 * @param[out] self Identity to fill. The lane field is left empty.
 * @return 0 on success, -1 when the process start time could not be read.
 */
int wm_manager_task_owner_self(wm_manager_task_owner *self);

/**
 * @brief Build the OWNER string one lane worker writes onto the rows it claims.
 *
 * @param[out] buffer Destination, at least WM_MANAGER_TASK_OWNER_LEN bytes.
 * @param[in] len Size of the destination.
 * @param[in] self This process's identity.
 * @param[in] lane Lane the worker belongs to.
 * @param[in] index Worker's position within its lane, from zero.
 * @return 0 on success, -1 when the value would not fit.
 */
int wm_manager_task_owner_format(char *buffer,
                                 size_t len,
                                 const wm_manager_task_owner *self,
                                 wm_manager_task_lane lane,
                                 int index);

/**
 * @brief Parse an OWNER string.
 *
 * @param[in] owner String to parse.
 * @param[out] parsed Result, which is untouched on failure.
 * @return true when the string is a well-formed OWNER.
 */
bool wm_manager_task_owner_parse(const char *owner, wm_manager_task_owner *parsed);

/**
 * @brief Read a process's start time, which distinguishes it from a later reuse of its pid.
 *
 * @param[in] pid Process to inspect.
 * @return Start time in clock ticks, or 0 when the process does not exist or cannot be read.
 */
unsigned long long wm_manager_task_process_start_time(pid_t pid);

/**
 * @brief Classify a claimed row's owner against this process.
 *
 * @param[in] owner OWNER string from the row.
 * @param[in] self This process's identity.
 * @return What the owner is.
 */
wm_manager_task_owner_kind wm_manager_task_owner_classify(const char *owner, const wm_manager_task_owner *self);

/**
 * @brief Whether the ownership sweep may return a claimed row to the pending state.
 *
 * The rule has three cases and one term that looks redundant and is not:
 *
 *  - The owning process is gone, or its pid has been recycled. Reclaimed at once, which is
 *    strictly better than a lease timer: after a crash mid-execution the row does not sit
 *    unusable for a timeout that has nothing to do with the failure.
 *
 *  - The owner is a live lane of this process. Reclaimed only when the lane is demonstrably not
 *    working on this row AND the claim is older than the grace period. The grace is not
 *    belt-and-braces: a lane cannot publish the id of the row it is running until the claim has
 *    returned it, so between the claim landing and the publish there is a window in which the
 *    sweep sees a mismatch and reclaims a row that is about to execute.
 *
 *  - The owner is alive and is not us. Never reclaimed. Under a restart with an overlapping old
 *    process, or an operator starting a second modulesd, those lanes may still be mid-call, and
 *    inferring death from "not mine" is what would cause the concurrent execution this design
 *    forbids.
 *
 * @param[in] owner OWNER string from the row.
 * @param[in] claim_time When the row was claimed.
 * @param[in] now Current time.
 * @param[in] claim_grace Seconds a claim by one of our own lanes is left alone regardless.
 * @param[in] self This process's identity.
 * @param[in] lane_inflight_task_id Id the owning lane says it is executing, or NULL for none.
 * @param[in] row_task_id Id of the row being considered.
 * @return true when the row may be reclaimed.
 */
bool wm_manager_task_owner_reclaimable(const char *owner,
                                       long long claim_time,
                                       long long now,
                                       int claim_grace,
                                       const wm_manager_task_owner *self,
                                       const char *lane_inflight_task_id,
                                       const char *row_task_id);

#endif
