#pragma once

#include "cgroup_host_mode.h"

#include <cstdint>
#include <string>

namespace wazuh::container_instances
{

    /// Separating two roles that happen to coincide on cgroup v2.
    ///
    /// One number has been playing both parts: the STORE INDEX KEY, which a
    /// record is filed under so a consumer lookup finds it, and the EBPF
    /// CORRELATION KEY, which the kernel stamps into every event. On a unified
    /// hierarchy they are the same cgroup inode, and that identity is the
    /// design's elegance. On a legacy hierarchy they cannot be the same,
    /// because `bpf_get_current_cgroup_id()` collapses to one constant for
    /// every task — so the kernel side carries no usable number at all, and the
    /// correlation key has to come from somewhere else (#37396 ADR-002).
    ///
    /// Unifying the two hierarchies therefore means separating the two roles
    /// and letting the host decide which concrete number fills each.
    enum class KeyKind : std::uint8_t
    {
        cgroupInode, ///< Unified and hybrid: `ev->cgroup_id`, identical value.
        mntNsInode   ///< Legacy: `ev->mnt_ns`, already carried by every event.
    };

    struct HostKey
    {
        KeyKind kind {KeyKind::cgroupInode};
        std::uint64_t value {0};

        [[nodiscard]] bool operator==(const HostKey& other) const
        {
            return kind == other.kind && value == other.value;
        }
    };

    /// Which key this host uses — a HOST CONSTANT, decided once at startup from
    /// the mount layout.
    ///
    /// Never per record and never inferred from an event. Two records in one
    /// store keyed by different kinds are two numbers drawn from unrelated
    /// spaces that happen to share a type, and every comparison between them is
    /// silently meaningless — which is the exact ambiguity this split exists to
    /// remove, reintroduced one layer down.
    ///
    /// Hybrid follows unified because `bpf_get_current_cgroup_id()` returns
    /// unified-hierarchy ids there, which is also how the mode probe classifies
    /// it.
    [[nodiscard]] inline KeyKind keyKindFor(wz_cgroup_mode_t mode)
    {
        return wz_cgroup_mode_has_usable_cgroup_id(mode) ? KeyKind::cgroupInode : KeyKind::mntNsInode;
    }

    /// The wire spelling. Stable across versions: it is published in the
    /// `status` reply so a consumer DISCOVERS which key to send rather than
    /// probing the host itself — two components independently classifying one
    /// host is the defect the shared probe exists to prevent, and the protocol
    /// must not reintroduce it.
    [[nodiscard]] inline const char* keyKindName(KeyKind kind)
    {
        return (kind == KeyKind::mntNsInode) ? "mnt_ns" : "cgroup";
    }

    [[nodiscard]] inline bool keyKindFromName(const std::string& name, KeyKind& out)
    {
        if (name == "cgroup")
        {
            out = KeyKind::cgroupInode;
            return true;
        }
        if (name == "mnt_ns")
        {
            out = KeyKind::mntNsInode;
            return true;
        }
        return false;
    }

} // namespace wazuh::container_instances
