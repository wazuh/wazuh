#pragma once

#include "../cache/i_metadata_store.hpp"
#include "../core/cache_entry.hpp"
#include "../core/container_record.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace wazuh::container_instances
{

    /// Wire-independent request. `cgroupId` is the only mandatory lookup key;
    /// the rest are optional secondary keys for lifecycle/debug use.
    struct QueryRequest
    {
        enum class Op : std::uint8_t
        {
            resolve,
            status
        };

        int version {0};
        Op op {Op::resolve};
        std::uint64_t cgroupId {0};
        std::optional<std::string> containerId;
        std::optional<std::string> podUid;
        std::optional<std::string> containerName;
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
        ContainerRecordPtr record;           ///< resolved.
        std::optional<VerdictReason> reason; ///< notContainer.
        int retryAfterMs {0};                ///< pending.
        std::optional<StoreStats> stats;     ///< ok.
        std::string connectorName;           ///< ok.
        std::optional<ErrorCode> errorCode;  ///< error.
        std::string errorMessage;            ///< error.
    };

} // namespace wazuh::container_instances
