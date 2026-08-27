/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace wazuh::ebpf {

/**
 * @brief High-level classification of eBPF events. Each module loads only the
 * hooks of the classes it asks for; there is no cross-module dispatch.
 */
enum class EventClass : uint16_t {
    FILE = 1,
    PROCESS = 2, ///< Not implemented yet (exec hooks pending)
    NETWORK = 3  ///< Not implemented yet (network hooks pending)
};

/**
 * @brief Specific types of file-related events (for FIM).
 */
enum class FileEventType : uint16_t {
    OPEN_CREATE = 1,
    ATTR_CHANGE = 2,
    UNLINK = 3,
    RENAME = 4
};

/**
 * @brief Specific types of process-related events (for Syscollector / IT Hygiene).
 */
enum class ProcessEventType : uint16_t {
    EXEC = 1,
    EXIT = 2
};

/**
 * @brief Specific types of network-related events (for IT Hygiene).
 */
enum class NetworkEventType : uint16_t {
    CONNECT = 1,
    ACCEPT = 2,
    LISTEN = 3
};

/**
 * @brief Correlation keys captured at kernel level for container attribution.
 * cgroup_id plus the namespace inodes are enough to resolve the container.
 */
struct CorrelationKeys {
    uint64_t cgroup_id{0}; ///< bpf_get_current_cgroup_id() - primary container key
    uint32_t mntns_ino{0};
    uint32_t pidns_ino{0};
    uint32_t netns_ino{0};
};

/**
 * @brief Process identity attributes.
 */
struct ProcessIdentity {
    uint32_t pid{0};
    uint32_t tid{0};
    uint32_t ppid{0};
    uint32_t uid{0};
    uint32_t gid{0};
    uint32_t euid{0};
    uint32_t login_uid{0};
    std::string comm;
    std::string parent_comm;
    std::string cwd;
};

/**
 * @brief Normalized file event read from the module's own ring buffer.
 */
struct FileEvent {
    FileEventType type{FileEventType::OPEN_CREATE};
    ProcessIdentity identity;
    CorrelationKeys correlation;
    uint64_t inode{0};
    uint64_t dev{0};
    uint32_t open_flags{0};
    std::string path;
    std::string old_path; ///< Populated only for RENAME events
};

/**
 * @brief Normalized process event (exec hooks pending).
 */
struct ProcessEvent {
    ProcessEventType type{ProcessEventType::EXEC};
    ProcessIdentity identity;
    CorrelationKeys correlation;
    std::string exe_path;
    std::vector<std::string> argv;
    int32_t exit_code{0};
};

/**
 * @brief Normalized network event (network hooks pending).
 */
struct NetworkEvent {
    NetworkEventType type{NetworkEventType::CONNECT};
    ProcessIdentity identity;
    CorrelationKeys correlation;
    uint8_t protocol{0}; ///< IPPROTO_TCP / IPPROTO_UDP
    uint16_t src_port{0};
    uint16_t dst_port{0};
    std::string src_ip;
    std::string dst_ip;
};

using FileEventCallback = std::function<void(const FileEvent&)>;
using ProcessEventCallback = std::function<void(const ProcessEvent&)>;
using NetworkEventCallback = std::function<void(const NetworkEvent&)>;

/**
 * @brief Returns true when @p path starts with any of @p prefixes.
 * An empty prefix list matches nothing: consumers filter on their own
 * configuration, so "no configured paths" means "no events of interest".
 */
inline bool matchesAnyPrefix(std::string_view path, const std::vector<std::string>& prefixes) {
    for (const auto& prefix : prefixes) {
        if (!prefix.empty() && path.compare(0, prefix.size(), prefix) == 0) {
            return true;
        }
    }
    return false;
}

} // namespace wazuh::ebpf
