#include "baseline_rows.hpp"

#include <json.hpp>

namespace wazuh::container_baseline {

void ApplyIdentity(FileBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id   = id.container_id;
    row.pod_uid        = id.pod_uid;
    row.pod_name       = id.pod_name;
    row.k8s_namespace  = id.k8s_namespace;
    row.container_name = id.container_name;
    row.image          = id.image;
}

void ApplyIdentity(ProcessBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id   = id.container_id;
    row.pod_uid        = id.pod_uid;
    row.pod_name       = id.pod_name;
    row.k8s_namespace  = id.k8s_namespace;
    row.container_name = id.container_name;
    row.image          = id.image;
}

void ApplyIdentity(PortBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id   = id.container_id;
    row.pod_uid        = id.pod_uid;
    row.pod_name       = id.pod_name;
    row.k8s_namespace  = id.k8s_namespace;
    row.container_name = id.container_name;
    row.image          = id.image;
}

void ApplyIdentity(UserBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id   = id.container_id;
    row.pod_uid        = id.pod_uid;
    row.pod_name       = id.pod_name;
    row.k8s_namespace  = id.k8s_namespace;
    row.container_name = id.container_name;
    row.image          = id.image;
}

void ApplyIdentity(GroupBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id   = id.container_id;
    row.pod_uid        = id.pod_uid;
    row.pod_name       = id.pod_name;
    row.k8s_namespace  = id.k8s_namespace;
    row.container_name = id.container_name;
    row.image          = id.image;
}

void ApplyIdentity(PackageBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id   = id.container_id;
    row.pod_uid        = id.pod_uid;
    row.pod_name       = id.pod_name;
    row.k8s_namespace  = id.k8s_namespace;
    row.container_name = id.container_name;
    row.image          = id.image;
}

void ApplyIdentity(OsBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id   = id.container_id;
    row.pod_uid        = id.pod_uid;
    row.pod_name       = id.pod_name;
    row.k8s_namespace  = id.k8s_namespace;
    row.container_name = id.container_name;
    row.image          = id.image;
}

void ApplyIdentity(InterfaceBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id   = id.container_id;
    row.pod_uid        = id.pod_uid;
    row.pod_name       = id.pod_name;
    row.k8s_namespace  = id.k8s_namespace;
    row.container_name = id.container_name;
    row.image          = id.image;
}

void ApplyIdentity(NetworkAddressBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id   = id.container_id;
    row.pod_uid        = id.pod_uid;
    row.pod_name       = id.pod_name;
    row.k8s_namespace  = id.k8s_namespace;
    row.container_name = id.container_name;
    row.image          = id.image;
}

void ApplyIdentity(ProtocolBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id   = id.container_id;
    row.pod_uid        = id.pod_uid;
    row.pod_name       = id.pod_name;
    row.k8s_namespace  = id.k8s_namespace;
    row.container_name = id.container_name;
    row.image          = id.image;
}

void ApplyIdentity(ServiceBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id   = id.container_id;
    row.pod_uid        = id.pod_uid;
    row.pod_name       = id.pod_name;
    row.k8s_namespace  = id.k8s_namespace;
    row.container_name = id.container_name;
    row.image          = id.image;
}

void ApplyIdentity(HardwareBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id   = id.container_id;
    row.pod_uid        = id.pod_uid;
    row.pod_name       = id.pod_name;
    row.k8s_namespace  = id.k8s_namespace;
    row.container_name = id.container_name;
    row.image          = id.image;
}

namespace {

nlohmann::json KubernetesBlock(const std::string& container_id,
                                const std::string& pod_uid,
                                const std::string& pod_name,
                                const std::string& k8s_namespace,
                                const std::string& container_name,
                                const std::string& image)
{
    nlohmann::json k8s;
    if (!k8s_namespace.empty())  k8s["namespace"]       = k8s_namespace;
    if (!pod_name.empty())       k8s["pod_name"]        = pod_name;
    if (!pod_uid.empty())        k8s["pod_uid"]         = pod_uid;
    if (!container_name.empty()) k8s["container_name"]  = container_name;
    if (!container_id.empty())   k8s["container_id"]    = container_id;
    if (!image.empty())          k8s["image"]           = image;
    return k8s;
}

} // namespace

std::pair<std::string, std::string> BuildFimFileJson(const FileBaselineRow& row)
{
    nlohmann::json data;
    data["path"]        = row.path;
    data["device"]      = row.device;
    data["inode"]       = row.inode;
    data["size"]        = row.size;
    data["permissions"] = row.permissions;
    data["uid"]         = row.uid;
    data["gid"]         = row.gid;
    data["owner"]       = row.owner;
    data["group_"]      = row.group;
    data["mtime"]       = row.mtime;
    if (!row.hash_md5.empty())    data["hash_md5"]    = row.hash_md5;
    if (!row.hash_sha1.empty())   data["hash_sha1"]   = row.hash_sha1;
    if (!row.hash_sha256.empty()) data["hash_sha256"] = row.hash_sha256;
    data["is_symlink"] = row.is_symlink;
    data["baseline"]   = true; // marks this row as baseline-sourced, not eBPF-diff-sourced.

    data["kubernetes"] = KubernetesBlock(row.container_id, row.pod_uid, row.pod_name,
                                          row.k8s_namespace, row.container_name, row.image);

    const std::string id = row.container_id + ":" + row.path;
    return {id, data.dump()};
}

std::pair<std::string, std::string> BuildProcessJson(const ProcessBaselineRow& row)
{
    nlohmann::json data;
    nlohmann::json process;
    process["pid"]              = row.pid;
    process["name"]             = row.name;
    process["state"]            = row.state;
    process["parent"]           = {{"pid", row.parent_pid}};
    process["command_line"]     = row.command_line;
    process["args"]             = row.args;
    process["args_count"]       = row.args_count;
    process["start"]            = row.start;
    process["utime"]            = row.utime;
    process["stime"]            = row.stime;
    data["process"]   = process;
    data["baseline"]  = true;
    data["container"] = KubernetesBlock(row.container_id, row.pod_uid, row.pod_name,
                                         row.k8s_namespace, row.container_name, row.image);

    const std::string id = row.container_id + ":" + row.pid;
    return {id, data.dump()};
}

std::pair<std::string, std::string> BuildPortJson(const PortBaselineRow& row)
{
    nlohmann::json data;
    data["network"] = {{"transport", row.network_transport}};
    data["source"]      = {{"ip", row.source_ip},      {"port", row.source_port}};
    data["destination"] = {{"ip", row.destination_ip}, {"port", row.destination_port}};
    data["interface_state"] = row.interface_state;
    data["file_inode"]      = row.file_inode;
    if (row.process_pid != 0) {
        data["process"] = {{"pid", row.process_pid}, {"name", row.process_name}};
    }
    data["baseline"]  = true;
    data["container"] = KubernetesBlock(row.container_id, row.pod_uid, row.pod_name,
                                         row.k8s_namespace, row.container_name, row.image);

    const std::string id = row.container_id + ":" + row.network_transport + ":" +
                            row.source_ip + ":" + std::to_string(row.source_port) + ":" +
                            std::to_string(row.file_inode);
    return {id, data.dump()};
}

std::pair<std::string, std::string> BuildUserJson(const UserBaselineRow& row)
{
    nlohmann::json data;
    nlohmann::json user;
    user["name"]        = row.name;
    user["id"]          = row.uid;
    user["group"]       = {{"id", row.gid}};
    user["description"] = row.description;
    user["home"]        = row.home;
    user["shell"]       = row.shell;
    data["user"]      = user;
    data["baseline"]  = true;
    data["container"] = KubernetesBlock(row.container_id, row.pod_uid, row.pod_name,
                                         row.k8s_namespace, row.container_name, row.image);

    // Keyed by name, not uid: /etc/passwd allows duplicate uids (e.g. root
    // aliases) but a name appears once per file.
    const std::string id = row.container_id + ":user:" + row.name;
    return {id, data.dump()};
}

std::pair<std::string, std::string> BuildGroupJson(const GroupBaselineRow& row)
{
    nlohmann::json data;
    nlohmann::json group;
    group["name"]  = row.name;
    group["id"]    = row.gid;
    group["users"] = row.members;
    data["group"]     = group;
    data["baseline"]  = true;
    data["container"] = KubernetesBlock(row.container_id, row.pod_uid, row.pod_name,
                                         row.k8s_namespace, row.container_name, row.image);

    const std::string id = row.container_id + ":group:" + row.name;
    return {id, data.dump()};
}

std::pair<std::string, std::string> BuildPackageJson(const PackageBaselineRow& row)
{
    nlohmann::json data;
    nlohmann::json package;
    package["name"]         = row.name;
    package["version"]      = row.version;
    package["architecture"] = row.architecture;
    package["description"]  = row.description;
    package["size"]         = row.size;
    package["vendor"]       = row.vendor;
    package["installed"]    = row.install_time;
    package["category"]     = row.category;
    package["source"]       = row.source;
    package["type"]         = row.format;
    data["package"]   = package;
    data["baseline"]  = true;
    data["container"] = KubernetesBlock(row.container_id, row.pod_uid, row.pod_name,
                                         row.k8s_namespace, row.container_name, row.image);

    // name+arch+version identifies a package row; multiarch dpkg installs the
    // same name for several architectures, so arch must be part of the key.
    const std::string id = row.container_id + ":pkg:" + row.format + ":" + row.name + ":" +
                            row.architecture + ":" + row.version;
    return {id, data.dump()};
}

std::pair<std::string, std::string> BuildOsJson(const OsBaselineRow& row)
{
    nlohmann::json data;
    nlohmann::json os;
    os["name"]     = row.name;
    os["full"]     = row.full;
    os["version"]  = row.version;
    os["codename"] = row.codename;
    os["platform"] = row.platform;
    os["family"]   = row.family;
    os["kernel"]   = row.kernel;
    os["type"]     = "linux";
    data["os"]        = os;
    data["baseline"]  = true;
    data["container"] = KubernetesBlock(row.container_id, row.pod_uid, row.pod_name,
                                         row.k8s_namespace, row.container_name, row.image);

    // One OS row per container.
    const std::string id = row.container_id + ":os";
    return {id, data.dump()};
}

std::pair<std::string, std::string> BuildInterfaceJson(const InterfaceBaselineRow& row)
{
    nlohmann::json data;
    nlohmann::json iface;
    iface["name"]  = row.name;
    iface["mac"]   = row.mac;
    iface["mtu"]   = row.mtu;
    iface["state"] = row.state;
    iface["type"]  = row.type;
    data["interface"]  = iface;
    data["statistics"] = {
        {"rx", {{"bytes", row.rx_bytes}, {"packets", row.rx_packets}, {"errors", row.rx_errors}, {"dropped", row.rx_dropped}}},
        {"tx", {{"bytes", row.tx_bytes}, {"packets", row.tx_packets}, {"errors", row.tx_errors}, {"dropped", row.tx_dropped}}},
    };
    data["baseline"]  = true;
    data["container"] = KubernetesBlock(row.container_id, row.pod_uid, row.pod_name,
                                         row.k8s_namespace, row.container_name, row.image);

    const std::string id = row.container_id + ":iface:" + row.name;
    return {id, data.dump()};
}

std::pair<std::string, std::string> BuildNetworkAddressJson(const NetworkAddressBaselineRow& row)
{
    nlohmann::json data;
    nlohmann::json network;
    network["interface"] = row.interface_name;
    network["protocol"]  = row.protocol;
    network["ip"]        = row.address;
    network["netmask"]   = row.netmask;
    if (!row.broadcast.empty()) network["broadcast"] = row.broadcast;
    data["network"]   = network;
    data["baseline"]  = true;
    data["container"] = KubernetesBlock(row.container_id, row.pod_uid, row.pod_name,
                                         row.k8s_namespace, row.container_name, row.image);

    // iface + address is unique within one netns; protocol is implied by the
    // address family but kept out of the key (an address string is unambiguous).
    const std::string id = row.container_id + ":net:" + row.interface_name + ":" + row.address;
    return {id, data.dump()};
}

std::pair<std::string, std::string> BuildProtocolJson(const ProtocolBaselineRow& row)
{
    nlohmann::json data;
    data["interface"] = {{"name", row.interface_name}};
    nlohmann::json network;
    network["type"]   = row.type;
    if (!row.gateway.empty()) network["gateway"] = row.gateway; // typed `ip` — omit when absent.
    network["dhcp"]   = row.dhcp;
    network["metric"] = row.metric;
    data["network"]   = network;
    data["baseline"]  = true;
    data["container"] = KubernetesBlock(row.container_id, row.pod_uid, row.pod_name,
                                         row.k8s_namespace, row.container_name, row.image);

    const std::string id = row.container_id + ":proto:" + row.interface_name + ":" + row.type;
    return {id, data.dump()};
}

std::pair<std::string, std::string> BuildServiceJson(const ServiceBaselineRow& row)
{
    nlohmann::json data;
    nlohmann::json service;
    service["name"]        = row.name;
    service["id"]          = row.name;
    service["description"] = row.description;
    service["state"]       = row.state;
    service["enabled"]     = row.enabled;
    service["type"]        = row.type;
    data["service"]   = service;
    // process.executable / file.path mirror the host row's fragment/source paths;
    // omit when a unit has no ExecStart (target/socket units).
    if (!row.executable.empty()) data["process"] = {{"executable", row.executable}};
    if (!row.file_path.empty())  data["file"]    = {{"path", row.file_path}};
    data["baseline"]  = true;
    data["container"] = KubernetesBlock(row.container_id, row.pod_uid, row.pod_name,
                                         row.k8s_namespace, row.container_name, row.image);

    const std::string id = row.container_id + ":svc:" + row.name;
    return {id, data.dump()};
}

std::pair<std::string, std::string> BuildHardwareJson(const HardwareBaselineRow& row)
{
    nlohmann::json data;
    nlohmann::json host;
    // serial_number is the host row's primary key; for a container's virtual
    // hardware the container_id fills that slot, and the manager splits real vs
    // virtual on the container block below.
    host["serial_number"] = row.container_id;
    host["cpu"]    = {{"name", row.cpu_name}, {"cores", row.cpu_cores},
                      {"speed", static_cast<int64_t>(row.cpu_speed)}};
    host["memory"] = {{"total", row.memory_total}, {"free", row.memory_free}, {"used", row.memory_used}};
    data["host"]      = host;
    data["baseline"]  = true;
    data["container"] = KubernetesBlock(row.container_id, row.pod_uid, row.pod_name,
                                         row.k8s_namespace, row.container_name, row.image);

    const std::string id = row.container_id + ":hw";
    return {id, data.dump()};
}

} // namespace wazuh::container_baseline
