#pragma once

#include "../core/container_record.hpp"

#include <cstdint>
#include <deque>
#include <random>
#include <string>
#include <vector>

namespace wazuh::container_instances
{

    /// Default ring capacity. Generous rather than tuned: append-time filtering
    /// keeps metadata churn out of the ring entirely (see appendsNothing in
    /// MetadataStore), so what lands here is membership and substantive change,
    /// which no realistic host produces thousands of per consumer poll.
    inline constexpr std::size_t LIFECYCLE_RING_CAPACITY = 4096;

    enum class LifecycleKind : std::uint8_t
    {
        /// Became visible through listContainers(). Not "the runtime created
        /// it": a container is published only once it has a usable cgroup, so
        /// this fires when it becomes ATTRIBUTABLE, which is the only moment a
        /// consumer can act on.
        added,

        /// Still visible, and something a consumer might care about differs.
        changed,

        /// No longer visible. Fires at erase — for a running container that is
        /// grace expiry, not the moment it vanished from a snapshot — so it is
        /// safe to treat as authority for deleting that container's rows.
        removed
    };

    /// What differs, so a consumer can re-scan only what it must.
    ///
    /// `metadata` exists to be ignored: Kubernetes annotations churn constantly,
    /// and a label change has no bearing on a container's files or packages. An
    /// event whose only class is metadata is never appended at all.
    enum LifecycleField : unsigned int
    {
        LIFECYCLE_IDENTITY = 1u << 0, ///< name, restart count, state, cgroup inode
        LIFECYCLE_IMAGE = 1u << 1,    ///< image or its digest
        LIFECYCLE_MOUNTS = 1u << 2,   ///< oci mounts
        LIFECYCLE_NETWORK = 1u << 3,  ///< interfaces/addresses
        LIFECYCLE_METADATA = 1u << 4, ///< labels, annotations, owner refs, pod identity
    };

    struct LifecycleEvent
    {
        std::uint64_t seq {0};
        LifecycleKind kind {LifecycleKind::added};
        std::string containerId;

        /// Last known cgroup inode. Carried on `removed` too — and that is the
        /// point: FIM keys its kernel allowlist by inode, so a removal it cannot
        /// map back to an inode is a removal it cannot act on.
        std::uint64_t cgroupId {0};

        /// Bitmask of LifecycleField; meaningful only for `changed`.
        unsigned int changed {0};

        /// Null for `removed`.
        ContainerRecordPtr record;
    };

    /// Where a consumer has read up to. `epoch` pins it to one store lifetime:
    /// sequence numbers restart when the module does, so a cursor without it
    /// would silently appear to be up to date against a fresh journal.
    struct LifecycleCursor
    {
        std::uint64_t epoch {0};
        std::uint64_t seq {0};
    };

    struct LifecycleDelta
    {
        /// The cursor could not be served — wrong epoch, or its position has
        /// already been evicted. `containers` then carries the full current set
        /// so the caller recovers in the same round trip rather than having to
        /// ask again against a set that may have moved on.
        bool resyncRequired {false};

        LifecycleCursor cursor;
        std::vector<LifecycleEvent> events;
        std::vector<ContainerRecordPtr> containers;
    };

    /// Bounded log of transitions of the set listContainers() returns.
    ///
    /// THE INVARIANT, which every caller depends on and which is easy to break:
    /// for cursors s1 < s2 with no eviction between them, applying the events in
    /// (s1, s2] to the set as it was at s1 yields the set as it is at s2. The log
    /// therefore tracks VISIBILITY, not store writes — a record inserted while
    /// still unresolved appends nothing, and the later insert that gives it a
    /// cgroup is what appends `added`.
    ///
    /// Membership is mirrored exactly. Record CONTENTS are not: a metadata-only
    /// change is dropped at append time, so a consumer that followed the journal
    /// alone could hold slightly stale labels. That is deliberate — it is what
    /// stops annotation churn evicting real transitions out of the ring — and it
    /// is why consumers keep a periodic full read as a floor.
    ///
    /// Not thread-safe; MetadataStore owns one and only touches it under its own
    /// write lock.
    class LifecycleJournal
    {
        public:
            explicit LifecycleJournal(std::size_t capacity = LIFECYCLE_RING_CAPACITY)
                : m_capacity(capacity == 0 ? 1 : capacity)
            {
                // Random rather than counted: the point is that a consumer can
                // tell "same store I was reading" from "a different one", and a
                // restart counter would have to be persisted to do that.
                std::random_device device;
                std::uniform_int_distribution<std::uint64_t> distribution;
                std::mt19937_64 generator(device());
                m_epoch = distribution(generator);

                if (m_epoch == 0)
                {
                    m_epoch = 1; // 0 is the "no cursor" sentinel.
                }
            }

            void append(LifecycleEvent event)
            {
                event.seq = m_nextSeq++;
                m_events.push_back(std::move(event));

                while (m_events.size() > m_capacity)
                {
                    m_events.pop_front();
                }
            }

            [[nodiscard]] LifecycleCursor cursor() const
            {
                return LifecycleCursor {m_epoch, m_nextSeq - 1};
            }

            /// Events after `from`, or a resync demand. `currentSet` is consulted
            /// only to fill a resync reply, so the caller passes the live set.
            [[nodiscard]] LifecycleDelta since(const LifecycleCursor& from,
                                               const std::vector<ContainerRecordPtr>& currentSet) const
            {
                LifecycleDelta delta;
                delta.cursor = cursor();

                if (from.epoch != m_epoch || from.seq > delta.cursor.seq || !canServe(from.seq))
                {
                    // A seq AHEAD of ours is not a bogus client to reject: it is
                    // this store having restarted and the epoch check being the
                    // only thing that caught it. Same recovery either way.
                    delta.resyncRequired = true;
                    delta.containers = currentSet;
                    return delta;
                }

                for (const auto& event : m_events)
                {
                    if (event.seq > from.seq)
                    {
                        delta.events.push_back(event);
                    }
                }

                return delta;
            }

            [[nodiscard]] std::uint64_t epoch() const
            {
                return m_epoch;
            }

            [[nodiscard]] std::size_t size() const
            {
                return m_events.size();
            }

        private:
            /// True when everything after `seq` is still in the ring.
            [[nodiscard]] bool canServe(std::uint64_t seq) const
            {
                if (m_events.empty())
                {
                    // Nothing has been appended since `seq` — serviceable only if
                    // the caller is up to date with a journal that never evicted.
                    return seq + 1 == m_nextSeq;
                }
                return seq + 1 >= m_events.front().seq;
            }

            std::size_t m_capacity;
            std::uint64_t m_epoch {0};
            std::uint64_t m_nextSeq {1};
            std::deque<LifecycleEvent> m_events;
    };

    /// Which classes of field differ. Returns 0 when the records are equivalent
    /// for every class this reports on.
    [[nodiscard]] inline unsigned int lifecycleChangeMask(const ContainerRecord& before, const ContainerRecord& after)
    {
        unsigned int mask = 0;

        if (before.containerName != after.containerName || before.restartCount != after.restartCount ||
            before.state != after.state || before.cgroupId != after.cgroupId || before.runtime != after.runtime)
        {
            mask |= LIFECYCLE_IDENTITY;
        }
        if (before.image != after.image || before.imageDigest != after.imageDigest)
        {
            mask |= LIFECYCLE_IMAGE;
        }
        if (before.ociMounts != after.ociMounts)
        {
            mask |= LIFECYCLE_MOUNTS;
        }
        if (before.network != after.network)
        {
            mask |= LIFECYCLE_NETWORK;
        }
        if (before.labels != after.labels || before.annotations != after.annotations ||
            before.ownerRefs != after.ownerRefs || before.podUid != after.podUid || before.podName != after.podName ||
            before.podNamespace != after.podNamespace || before.nodeName != after.nodeName)
        {
            mask |= LIFECYCLE_METADATA;
        }

        return mask;
    }

} // namespace wazuh::container_instances
