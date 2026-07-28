#pragma once

#include <string>

#include <json.hpp>

#include "baseline_rows.hpp"  // ContainerIdentity, ContainerContextPtr

namespace wazuh::container_baseline {

/// @brief Parse Container Instances' "resolve" reply "data" object (see
/// wire_protocol.hpp's recordToJson()) into the shared runtime context. Pod/
/// namespace/node/annotations/owner_refs appear only when runtime == "kubernetes";
/// a Docker-origin container leaves `kubernetes` unset (event_schema.md two-block rule).
[[nodiscard]] ContainerContextPtr ContextFromResolveData(const nlohmann::json& data);

/// @brief Build a ContainerIdentity from a container id and the raw JSON reply of
/// a resolveByCgroupId() call. Returns an identity with a null context when the
/// reply did not resolve (cold cache, module unavailable) — the container_id is
/// always set so rows stay attributable.
[[nodiscard]] ContainerIdentity IdentityFromResolveJson(const std::string& container_id,
                                                        const std::string& reply_json);

} // namespace wazuh::container_baseline
