#pragma once

#include "hardware_scanner.hpp"
#include "interface_scanner.hpp"
#include "container_context.hpp"
#include "network_scanner.hpp"
#include "os_scanner.hpp"
#include "package_scanner.hpp"
#include "process_scanner.hpp"
#include "protocol_scanner.hpp"
#include "rootfs_file_walker.hpp"
#include "service_scanner.hpp"
#include "user_scanner.hpp"

#include <string>
#include <utility>

namespace wazuh::container_baseline {

/// @brief Container identity to stamp onto every row produced for one container
/// (looked up once per container via ContainerConnectorClient, not re-queried
/// per file/process/socket). `context` is null when the container_instances
/// lookup didn't resolve (e.g. cold cache, module unavailable) — rows still
/// get `container_id` so they remain attributable and identifiable.
struct ContainerIdentity
{
    std::string        container_id;
    ContainerContextPtr context;
};

void ApplyIdentity(FileBaselineRow& row, const ContainerIdentity& id);
void ApplyIdentity(ProcessBaselineRow& row, const ContainerIdentity& id);
void ApplyIdentity(PortBaselineRow& row, const ContainerIdentity& id);
void ApplyIdentity(UserBaselineRow& row, const ContainerIdentity& id);
void ApplyIdentity(GroupBaselineRow& row, const ContainerIdentity& id);
void ApplyIdentity(PackageBaselineRow& row, const ContainerIdentity& id);
void ApplyIdentity(OsBaselineRow& row, const ContainerIdentity& id);
void ApplyIdentity(InterfaceBaselineRow& row, const ContainerIdentity& id);
void ApplyIdentity(NetworkAddressBaselineRow& row, const ContainerIdentity& id);
void ApplyIdentity(ProtocolBaselineRow& row, const ContainerIdentity& id);
void ApplyIdentity(ServiceBaselineRow& row, const ContainerIdentity& id);
void ApplyIdentity(HardwareBaselineRow& row, const ContainerIdentity& id);

/// @brief Build the sync-protocol payload for one FIM file baseline row.
///
/// Shape matches FileItem::createJSON()'s "data" object field-for-field
/// (src/syscheckd/src/db/src/dbFileItem.cpp) plus a "container" block (generic
/// runtime context: Docker, containerd, CRI-O, ...) and, only when the
/// container originates from a Kubernetes pod, a sibling "kubernetes" block —
/// see event_schema.md for the two-block rationale.
///
/// @return {id, json} where `id` is the value to pass as asp_persist_diff's
///         diff-id (container_id + path is already unique per row within a
///         baseline run).
std::pair<std::string, std::string> BuildFimFileJson(const FileBaselineRow& row);

/// @brief Build the sync-protocol payload for one process baseline row.
///
/// NOTE: this is a draft ECS-ish shape (process.*, container.*), not a byte-for-
/// byte reproduction of Syscollector::ecsData()'s mapping (that method is
/// private to the Syscollector class and its exact field contract for
/// container-sourced rows is still pending #37203-4's schema decision — see the
/// #37532 spike report). Wire this through the real ecsData() transform once
/// that schema is finalized, instead of relying on this approximation.
std::pair<std::string, std::string> BuildProcessJson(const ProcessBaselineRow& row);

/// @brief Build the sync-protocol payload for one network/port baseline row.
/// Same draft-schema caveat as BuildProcessJson().
std::pair<std::string, std::string> BuildPortJson(const PortBaselineRow& row);

/// @brief Build the sync-protocol payload for one user baseline row (M4).
/// Same draft-schema caveat as BuildProcessJson().
std::pair<std::string, std::string> BuildUserJson(const UserBaselineRow& row);

/// @brief Build the sync-protocol payload for one group baseline row (M4).
std::pair<std::string, std::string> BuildGroupJson(const GroupBaselineRow& row);

/// @brief Build the sync-protocol payload for one package baseline row (M4).
std::pair<std::string, std::string> BuildPackageJson(const PackageBaselineRow& row);

/// @brief Build the sync-protocol payload for the container's OS row.
/// Same draft-schema caveat as BuildProcessJson().
std::pair<std::string, std::string> BuildOsJson(const OsBaselineRow& row);

/// @brief Build the sync-protocol payload for one interface baseline row.
std::pair<std::string, std::string> BuildInterfaceJson(const InterfaceBaselineRow& row);

/// @brief Build the sync-protocol payload for one bound-address baseline row.
std::pair<std::string, std::string> BuildNetworkAddressJson(const NetworkAddressBaselineRow& row);

/// @brief Build the sync-protocol payload for one default-route (protocols) row.
std::pair<std::string, std::string> BuildProtocolJson(const ProtocolBaselineRow& row);

/// @brief Build the sync-protocol payload for one systemd service baseline row.
std::pair<std::string, std::string> BuildServiceJson(const ServiceBaselineRow& row);

/// @brief Build the sync-protocol payload for the container's virtual-hardware row.
std::pair<std::string, std::string> BuildHardwareJson(const HardwareBaselineRow& row);

} // namespace wazuh::container_baseline
