#pragma once

#include "../core/cache_entry.hpp"
#include "../core/container_record.hpp"
#include "../core/host_key.hpp"
#include "lifecycle_journal.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

namespace wazuh::container_instances
{

    struct LookupResult
    {
        enum class Status : std::uint8_t
        {
            miss,     ///< Nothing known for this key.
            resolved, ///< `record` is set.
            pending,  ///< Cold cache; caller re-queries later.
            verdict,  ///< `reason` is set; permanent "not a container".
            /// The caller asked in a key space this host does not use. Distinct
            /// from `miss` on purpose: a miss means "go and resolve it", and
            /// resolving a number from the wrong space either never settles or
            /// settles on the wrong container. Nothing here can answer the
            /// question as asked, so the caller is told so instead.
            wrongKeyKind
        };

        Status status {Status::miss};
        ContainerRecordPtr record;
        std::optional<VerdictReason> reason;
    };

    struct StoreStats
    {
        std::size_t resolved {0};
        std::size_t pending {0};
        std::size_t verdicts {0};
        std::optional<TimePoint> lastReconcile;
    };

    /// Concurrent metadata cache. Threading contract:
    ///  - applySnapshot: exactly one caller, the connector thread.
    ///  - upsertPending/upsertVerdict: targeted single-key writes from IPC workers.
    ///  - lookups: any thread, shared-lock, return immutable record copies.
    class IMetadataStore
    {
    public:
        virtual ~IMetadataStore() = default;

        /// Look one container up by the key its host uses.
        ///
        /// Takes a HostKey rather than a bare integer so a caller asking with
        /// the WRONG KIND is refused instead of answered. That is not
        /// hypothetical: the key arrives over IPC from a separate process that
        /// classified the host itself, and a cgroup inode and a mount-namespace
        /// inode are both plausible-looking 64-bit numbers. Compared as bare
        /// integers they simply fail to match, which is reported as "this
        /// container is unknown" — sending the consumer off to re-resolve a
        /// container that is sitting right there.
        ///
        /// The refusal is `Status::wrongKeyKind`, and the distinction from
        /// `miss` is the whole point: returning a plain miss here WAS the
        /// defect, because every caller reads a miss as "unknown, go and
        /// resolve it" and resolving a number from the wrong space either never
        /// settles or settles on an unrelated container.
        [[nodiscard]] virtual LookupResult lookup(HostKey key) const = 0;

        /// Which kind of key this store is filed under, so a consumer can ask
        /// rather than classify the host for itself.
        [[nodiscard]] virtual KeyKind keyKind() const = 0;
        [[nodiscard]] virtual LookupResult lookupByContainerId(const std::string& containerId) const = 0;
        [[nodiscard]] virtual LookupResult lookupByPodContainer(const std::string& podUid,
                                                                const std::string& containerName) const = 0;
        [[nodiscard]] virtual StoreStats stats() const = 0;
        [[nodiscard]] virtual std::vector<ContainerRecordPtr> listContainers() const = 0;

        /// Which containers may report to the manager, a subset of the ids
        /// listContainers() publishes.
        ///
        /// Deliberately a SEPARATE query rather than a field on the record.
        /// recordEquals() compares every field, so an admission flag living on
        /// the record would make each admission shift look like a container
        /// change and journal a `changed` event for a container that did not
        /// change. It is also why listContainers() still returns everything: the
        /// consumers' stale sweeps delete on absence from that list, so dropping
        /// a container from it would delete its rows rather than withhold them.
        [[nodiscard]] virtual std::set<std::string> admittedIds() const = 0;

        /// How many running containers listContainers() is CURRENTLY withholding
        /// because the resolver has not keyed them yet. Zero means the list is the
        /// whole node.
        ///
        /// The consumers' stale sweeps delete on absence from that list, so without
        /// this they cannot tell "this container is gone" from "this container is
        /// not resolved yet" -- and at startup, when the resolver is still walking,
        /// the second reads exactly like the first. Publishing the count lets a
        /// consumer hold its sweep for a cycle instead of deleting a live
        /// container's rows and re-creating them on the next pass.
        [[nodiscard]] virtual std::size_t withheldFromListCount() const = 0;

        /// How many containers may report; <= 0 means unlimited, which is the
        /// shipped default. Pushed by the manager, so it changes at runtime.
        virtual void setSyncLimit(int limit) = 0;

        /// Transitions of the listContainers() set after `from`.
        ///
        /// A caller that cannot be served — different store lifetime, or a
        /// position already evicted from the ring — gets `resyncRequired` with
        /// the full current set attached, so it recovers without a second call
        /// against a set that may have moved on meanwhile.
        [[nodiscard]] virtual LifecycleDelta lifecycleSince(const LifecycleCursor& from) const = 0;

        /// Where the journal currently stands. For a caller that wants to start
        /// following from "now" without replaying history.
        [[nodiscard]] virtual LifecycleCursor lifecycleCursor() const = 0;

        /// Invoked after a batch of mutations has been applied AND the store's
        /// lock released, once per batch that appended anything to the journal.
        ///
        /// After the lock on purpose: an observer's natural first move is to read
        /// the store, which would deadlock under the write lock, and a slow
        /// observer would otherwise stall every reader. Once per batch, not per
        /// event, because the signal is "something changed, come and look" — the
        /// journal is where the detail lives.
        virtual void setOnLifecycleChange(std::function<void(LifecycleCursor)> callback) = 0;

        /// Reconcile ONE source's view: replace that source's resolved set with
        /// `snapshot` (diff is computed within the source, so multiple sources
        /// coexist without evicting each other), sweep pending TTLs, age grace
        /// entries, and run verdict liveness against `liveInodes`.
        virtual void applySnapshot(const SourceId& source,
                                   std::vector<ContainerRecord> snapshot,
                                   const std::unordered_set<std::uint64_t>& liveInodes,
                                   TimePoint now) = 0;

        virtual void upsertPending(std::uint64_t cgroupInode, int attempts, TimePoint now) = 0;
        virtual void upsertVerdict(std::uint64_t cgroupInode, VerdictReason reason) = 0;

        /// Targeted single-record insert from the cold path (on-demand refresh).
        ///
        /// `record.hostKey` is the key the cold path WAS ASKED ABOUT, which is
        /// not necessarily the one this container is filed under: a container
        /// running an init system has several cgroups and the reconcile picks
        /// one of them for the whole container. A container already keyed keeps
        /// that key, and the asked-about one becomes an alias (AliasEntry), so
        /// the query is still answered by it. Re-keying instead made the key
        /// flap between the two, and a changed key is an identity change —
        /// published as `changed`, which has consumers re-walk a container that
        /// never moved.
        virtual void upsertResolved(const SourceId& source, ContainerRecord record) = 0;
    };

} // namespace wazuh::container_instances
