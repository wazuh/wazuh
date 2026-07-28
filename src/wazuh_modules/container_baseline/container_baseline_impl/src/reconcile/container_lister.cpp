#include "reconcile/container_lister.hpp"

#include <utility>

#include <json.hpp>

#include "container_instances_client.hpp"
#include "reconcile/resolve_identity.hpp"

namespace wazuh::container_baseline {

namespace {

/// @brief True when a status() reply shows the Container Instances module is up.
bool ModuleUp(const std::string& status_json)
{
    if (status_json.empty())
    {
        return false;
    }
    const auto j = nlohmann::json::parse(status_json, nullptr, false);
    return !j.is_discarded() && j.is_object() && j.value("status", "") == "ok";
}

} // namespace

ContainerLister::ContainerLister(std::string socket_path, std::chrono::milliseconds timeout)
    : m_socket_path(std::move(socket_path))
    , m_timeout(timeout)
{
}

ContainerListing ContainerLister::list()
{
    wazuh::container_instances_client::ContainerInstancesClient client(m_socket_path, m_timeout);
    ContainerListing out;

    const auto refs = client.listContainers();
    if (refs.empty())
    {
        // An empty list is ambiguous: the client collapses every IPC failure to
        // empty. Probe status() — module up => genuinely container-less (available,
        // so a container that just exited gets its rows deleted); module down =>
        // unavailable, and the reconciler skips its pass (no mass delete).
        out.available = ModuleUp(client.status());
        return out;
    }

    out.available = true;
    out.identities.reserve(refs.size());
    for (const auto& ref : refs)
    {
        const auto lookup = client.resolveByCgroupId(ref.cgroupId, ref.containerId);
        if (lookup.status != wazuh::container_instances_client::LookupStatus::resolved)
        {
            out.identities.push_back(ContainerIdentity {ref.containerId, nullptr});
            continue;
        }
        out.identities.push_back(IdentityFromResolveJson(ref.containerId, lookup.json));
    }
    return out;
}

} // namespace wazuh::container_baseline
