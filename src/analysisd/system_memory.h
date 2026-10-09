/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef SYSTEM_MEMORY_H
#define SYSTEM_MEMORY_H

#include <stdbool.h>
#include <stdint.h>

#define W_PROC_SELF_CGROUP      "/proc/self/cgroup"
#define W_PROC_SELF_MOUNTINFO   "/proc/self/mountinfo"

/**
 * @brief Get the memory that the process can use: the physical memory, or the cgroup memory limit if it is lower.
 *
 * Reads /proc and /sys: call it before the process enters a chroot.
 *
 * @param cgroup_limited Set to true if the cgroup memory limit is lower than the physical memory. May be NULL.
 * @return Memory size in bytes, or 0 if it cannot be determined.
 */
uint64_t w_get_memory_size(bool *cgroup_limited);

/**
 * @brief Get the physical memory of the system.
 * @return Physical memory in bytes, or 0 if it cannot be determined.
 */
uint64_t w_get_physical_memory(void);

/**
 * @brief Get the lowest memory limit of the cgroup of the process and its ancestors.
 *
 * Uses the cgroup v1 memory controller if the process belongs to one, and the cgroup v2 hierarchy otherwise.
 * The mount of the hierarchy is found in the mount information of the process: the cgroup path is translated
 * with the root of the mount, and only the levels inside the mount are checked.
 *
 * @param proc_cgroup File that lists the cgroups of the process, usually /proc/self/cgroup.
 * @param proc_mountinfo Mount information of the process, usually /proc/self/mountinfo.
 * @param fs_root Prefix for the mount points, "" for the real filesystem.
 * @return Memory limit in bytes, or 0 if there is no limit or it cannot be read.
 */
uint64_t w_get_cgroup_memory_limit(const char *proc_cgroup, const char *proc_mountinfo, const char *fs_root);

#endif /* SYSTEM_MEMORY_H */
