#pragma once

#include "../cache/i_metadata_store.hpp"
#include "../cache/lifecycle_journal.hpp"
#include "../core/cache_entry.hpp"
#include "../core/container_record.hpp"
#include "../core/host_key.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wazuh::container_instances
{

    /// Wire-independent request. `hostKey` is the only mandatory lookup key;
    /// the rest are optional secondary keys for lifecycle/debug use.
    struct QueryRequest
    {
        enum class Op : std::uint8_t
        {
            list,
            resolve,
            status
        };

        int version {0};
        Op op {Op::resolve};
        std::uint64_t hostKey {0};

        /// Which key space `hostKey` is drawn from, as the CLIENT believes it.
        /// Carried rather than assumed because the store refuses a mismatch,
        /// and a refusal is only possible if the claim was stated.
        KeyKind keyKind {KeyKind::cgroupInode};
        std::optional<std::string> containerId;
        std::optional<std::string> podUid;
        std::optional<std::string> containerName;

        /// `list` only: read forward from here instead of returning the whole
        /// set. Absent means a client that does not know about the cursor, or
        /// one deliberately asking for everything — both get today's reply.
        std::optional<LifecycleCursor> since;
    };

    /// Wire-independent response covering the three-outcome contract plus the
    /// status op and the error envelope.
    struct QueryResponse
    {
        enum class Status : std::uint8_t
        {
            resolved,
            pending,
            notContainer,
            ok, ///< status op.
            error
        };

        enum class ErrorCode : std::uint8_t
        {
            badRequest,
            unsupportedVersion,
            internal
        };

        Status status {Status::error};

        /// The protocol version to answer in — echoed from the request, not
        /// fixed at the server's own. A v1 client that is told the reply is v2
        /// rejects it outright, so answering every caller in the newest
        /// version would break exactly the clients the alias window exists to
        /// keep working.
        int version {1};

        /// The key space this server files containers under. Published so a
        /// consumer DISCOVERS it instead of classifying the host for itself —
        /// two components reaching that conclusion independently is the defect
        /// the shared probe exists to prevent, and it must not come back in
        /// through the protocol.
        KeyKind keyKind {KeyKind::cgroupInode};

        ContainerRecordPtr record;                  ///< resolved.
        std::vector<ContainerRecordPtr> containers; ///< list op.
        /// This response IS a `list` reply, so `containers` must be serialised even
        /// when empty. Omitting the key made "no containers on this host"
        /// indistinguishable from "no connector" for every client, because the
        /// client can only report reachability on a key it can find (C28).
        bool listReply {false};
        std::optional<VerdictReason> reason; ///< notContainer.
        int retryAfterMs {0};                ///< pending.
        std::optional<StoreStats> stats;     ///< ok.
        std::string connectorName;           ///< ok.

        /// `list` answered with a cursor. Carries the events, the cursor to
        /// come back with, and — when the cursor could not be served — the full
        /// set in `containers`, so recovery costs no extra round trip against a
        /// set that may have moved on meanwhile.
        std::optional<LifecycleDelta> delta;
        std::optional<ErrorCode> errorCode; ///< error.
        std::string errorMessage;           ///< error.
    };

} // namespace wazuh::container_instances
