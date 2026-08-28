/*
 * Wazuh Module for Task management: manager task ownership.
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WAZUH_UNIT_TESTING
#define STATIC
#else
#define STATIC static
#endif

#include "wmodules.h"
#include "wm_task_manager.h"
#include "wm_manager_task_owner.h"

/// Field number of starttime in /proc/<pid>/stat, counting from one.
#define PROC_STAT_STARTTIME_FIELD 22

/// The state field, which is the first one after the comm field's closing parenthesis.
#define PROC_STAT_STATE_FIELD 3

unsigned long long wm_manager_task_process_start_time(pid_t pid) {
#ifndef WIN32
    char path[PATH_MAX];
    char line[OS_SIZE_2048];
    FILE *stat_file = NULL;
    char *cursor = NULL;
    unsigned long long start_time = 0;
    size_t read = 0;

    if (pid <= 0) {
        return 0;
    }

    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);

    if (stat_file = wfopen(path, "r"), !stat_file) {
        // No such process, which is exactly what the caller wants to know.
        return 0;
    }

    read = fread(line, 1, sizeof(line) - 1, stat_file);
    fclose(stat_file);

    if (read == 0) {
        return 0;
    }

    line[read] = '\0';

    // The comm field is parenthesised and may itself contain spaces and parentheses, so the only
    // safe anchor is the LAST closing parenthesis on the line. Splitting on whitespace from the
    // start would misparse any process whose name contains a space.
    if (cursor = strrchr(line, ')'), !cursor) {
        return 0;
    }

    cursor++;

    // The next token after that parenthesis is the state field, so starttime is this many tokens
    // further along.
    for (int field = PROC_STAT_STATE_FIELD; field <= PROC_STAT_STARTTIME_FIELD; field++) {
        while (*cursor == ' ') {
            cursor++;
        }

        if (*cursor == '\0') {
            return 0;
        }

        if (field == PROC_STAT_STARTTIME_FIELD) {
            start_time = strtoull(cursor, NULL, 10);
            break;
        }

        while (*cursor != ' ' && *cursor != '\0') {
            cursor++;
        }
    }

    return start_time;
#else
    (void)pid;
    return 0;
#endif
}

int wm_manager_task_owner_self(wm_manager_task_owner *self) {
    if (!self) {
        return -1;
    }

    memset(self, 0, sizeof(*self));

    self->pid = getpid();
    self->start_time = wm_manager_task_process_start_time(self->pid);

    if (self->start_time == 0) {
        // Without a start time an OWNER cannot distinguish this process from a later one that
        // inherits its pid, and the sweep would be free to reclaim rows a live lane still holds.
        mterror(WM_TASK_MANAGER_LOGTAG, "Cannot read this process's start time; ownership cannot be tracked.");
        return -1;
    }

    return 0;
}

int wm_manager_task_owner_format(char *buffer,
                                 size_t len,
                                 const wm_manager_task_owner *self,
                                 wm_manager_task_lane lane,
                                 int index) {
    int written = 0;

    if (!buffer || !len || !self || lane >= WM_MANAGER_TASK_LANE_COUNT || index < 0) {
        return -1;
    }

    written = snprintf(buffer, len, "%d:%llu:%s-%d", (int)self->pid, self->start_time,
                       wm_manager_task_lane_name(lane), index);

    // A truncated OWNER would compare unequal to itself on the next sweep, so it is refused
    // rather than written.
    return (written > 0 && (size_t)written < len) ? 0 : -1;
}

bool wm_manager_task_owner_parse(const char *owner, wm_manager_task_owner *parsed) {
    const char *first = NULL;
    const char *second = NULL;
    char *end = NULL;
    long long pid = 0;
    unsigned long long start_time = 0;
    size_t lane_len = 0;

    if (!owner || !parsed) {
        return false;
    }

    if (first = strchr(owner, ':'), !first) {
        return false;
    }

    if (second = strchr(first + 1, ':'), !second) {
        return false;
    }

    pid = strtoll(owner, &end, 10);

    if (end != first || pid <= 0) {
        return false;
    }

    start_time = strtoull(first + 1, &end, 10);

    if (end != second) {
        return false;
    }

    lane_len = strlen(second + 1);

    if (lane_len == 0 || lane_len >= sizeof(parsed->lane)) {
        return false;
    }

    parsed->pid = (pid_t)pid;
    parsed->start_time = start_time;
    strncpy(parsed->lane, second + 1, sizeof(parsed->lane) - 1);
    parsed->lane[sizeof(parsed->lane) - 1] = '\0';

    return true;
}

wm_manager_task_owner_kind wm_manager_task_owner_classify(const char *owner, const wm_manager_task_owner *self) {
    wm_manager_task_owner parsed = {0};

    if (!self || !wm_manager_task_owner_parse(owner, &parsed)) {
        return WM_MANAGER_TASK_OWNER_UNPARSEABLE;
    }

    if (parsed.pid == self->pid && parsed.start_time == self->start_time) {
        return WM_MANAGER_TASK_OWNER_MINE;
    }

    // Reading the start time answers both questions at once: a zero means the process is gone,
    // and a different value means the pid has been reused by something else entirely.
    if (wm_manager_task_process_start_time(parsed.pid) != parsed.start_time) {
        return WM_MANAGER_TASK_OWNER_DEAD;
    }

    return WM_MANAGER_TASK_OWNER_FOREIGN;
}

bool wm_manager_task_owner_reclaimable(const char *owner,
                                       long long claim_time,
                                       long long now,
                                       int claim_grace,
                                       const wm_manager_task_owner *self,
                                       const char *lane_inflight_task_id,
                                       const char *row_task_id) {
    switch (wm_manager_task_owner_classify(owner, self)) {
    case WM_MANAGER_TASK_OWNER_DEAD:
        return true;

    case WM_MANAGER_TASK_OWNER_UNPARSEABLE:
        // A claimed row whose owner this build cannot read would never be reclaimed by any other
        // rule, and would sit unclaimable forever while counting against the row ceiling.
        return true;

    case WM_MANAGER_TASK_OWNER_FOREIGN:
        // Never. Those lanes may still be mid-call.
        return false;

    case WM_MANAGER_TASK_OWNER_MINE:
        // Both terms, and in this order. A lane that says it is running this row is running it,
        // however long it has been; the per-call timeout is what bounds that, not the sweep.
        if (lane_inflight_task_id && row_task_id && strcmp(lane_inflight_task_id, row_task_id) == 0) {
            return false;
        }

        // And the grace, which closes the window between the claim landing and the lane
        // publishing the id it just claimed. Without it the sweep sees "not the row this lane is
        // running" for a row the lane is about to run, and reclaims it.
        return (now - claim_time) > claim_grace;
    }

    return false;
}
