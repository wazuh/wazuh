#pragma once

#include "network_scanner.hpp"
#include "package_scanner.hpp"
#include "process_scanner.hpp"
#include "rootfs_file_walker.hpp"
#include "user_scanner.hpp"

#include <string>
#include <utility>

namespace wazuh::container_baseline {

/// @brief Container identity to stamp onto every row produced for one container
/// (looked up once per container via ContainerConnectorClient, not re-queried
/// per file/process/socket).
struct ContainerIdentity
{
    std::string container_id;
    std::string pod_uid;
    std::string pod_name;
    std::string k8s_namespace;
    std::string container_name;
    std::string image;
};

void ApplyIdentity(FileBaselineRow& row, const ContainerIdentity& id);
void ApplyIdentity(ProcessBaselineRow& row, const ContainerIdentity& id);
void ApplyIdentity(PortBaselineRow& row, const ContainerIdentity& id);
void ApplyIdentity(UserBaselineRow& row, const ContainerIdentity& id);
void ApplyIdentity(GroupBaselineRow& row, const ContainerIdentity& id);
void ApplyIdentity(PackageBaselineRow& row, const ContainerIdentity& id);

/// @brief Build the sync-protocol payload for one FIM file baseline row.
///
/// Shape matches FileItem::createJSON()'s "data" object field-for-field
/// (src/syscheckd/src/db/src/dbFileItem.cpp) plus a "kubernetes" context block
/// using the same field names as fim_handle_k8s_event()'s alert (src/syscheckd/
/// src/file/file.c) — so a row produced here is structurally interchangeable
/// with what the existing host-FIM and K8s-event paths already emit.
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

} // namespace wazuh::container_baseline
