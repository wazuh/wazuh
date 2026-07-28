#include "reconcile/resolve_identity.hpp"

#include "container_context.hpp"

namespace wazuh::container_baseline {

ContainerContextPtr ContextFromResolveData(const nlohmann::json& data)
{
    auto ctx = std::make_shared<ContainerContext>();
    ctx->runtime       = data.value("runtime", "");
    ctx->name          = data.value("container_name", "");
    ctx->image         = data.value("image", "");
    ctx->image_digest  = data.value("image_digest", "");
    ctx->restart_count = data.value("restart_count", 0);

    if (const auto it = data.find("labels"); it != data.end() && it->is_object())
    {
        for (const auto& [key, value] : it->items())
        {
            if (value.is_string()) ctx->labels.emplace(key, value.get<std::string>());
        }
    }
    if (const auto it = data.find("network"); it != data.end() && it->is_array())
    {
        for (const auto& iface : *it)
        {
            NetworkEndpoint entry;
            entry.name = iface.value("name", "");
            entry.ip   = iface.value("ip", "");
            ctx->network.push_back(std::move(entry));
        }
    }
    if (const auto it = data.find("oci_mounts"); it != data.end() && it->is_array())
    {
        for (const auto& mount : *it)
        {
            OciMountEntry entry;
            entry.source      = mount.value("source", "");
            entry.destination = mount.value("destination", "");
            entry.read_only   = mount.value("ro", false);
            ctx->oci_mounts.push_back(std::move(entry));
        }
    }

    if (ctx->runtime == "kubernetes")
    {
        KubernetesContext k8s;
        k8s.pod_uid       = data.value("pod_uid", "");
        k8s.pod_name      = data.value("pod_name", "");
        k8s.k8s_namespace = data.value("namespace", "");
        k8s.node_name     = data.value("node_name", "");

        if (const auto it = data.find("annotations"); it != data.end() && it->is_object())
        {
            for (const auto& [key, value] : it->items())
            {
                if (value.is_string()) k8s.annotations.emplace(key, value.get<std::string>());
            }
        }
        if (const auto it = data.find("owner_refs"); it != data.end() && it->is_array())
        {
            for (const auto& owner : *it)
            {
                OwnerReference ref;
                ref.kind = owner.value("kind", "");
                ref.name = owner.value("name", "");
                ref.uid  = owner.value("uid", "");
                k8s.owner_refs.push_back(std::move(ref));
            }
        }

        ctx->kubernetes = std::move(k8s);
    }

    return ctx;
}

ContainerIdentity IdentityFromResolveJson(const std::string& container_id, const std::string& reply_json)
{
    ContainerIdentity id;
    id.container_id = container_id;

    const auto j = nlohmann::json::parse(reply_json, nullptr, false);
    if (j.is_discarded() || !j.is_object() || j.value("status", "") != "resolved")
    {
        return id;
    }

    const auto dataIt = j.find("data");
    if (dataIt == j.end() || !dataIt->is_object())
    {
        return id;
    }

    id.context = ContextFromResolveData(*dataIt);
    return id;
}

} // namespace wazuh::container_baseline
