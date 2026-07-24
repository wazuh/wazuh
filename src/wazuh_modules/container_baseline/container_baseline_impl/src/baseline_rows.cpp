#include "baseline_rows.hpp"

#include <json.hpp>

namespace wazuh::container_baseline {

void ApplyIdentity(FileBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id = id.container_id;
    row.container     = id.context;
}

void ApplyIdentity(ProcessBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id = id.container_id;
    row.container     = id.context;
}

void ApplyIdentity(PortBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id = id.container_id;
    row.container     = id.context;
}

void ApplyIdentity(UserBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id = id.container_id;
    row.container     = id.context;
}

void ApplyIdentity(GroupBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id = id.container_id;
    row.container     = id.context;
}

void ApplyIdentity(PackageBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id = id.container_id;
    row.container     = id.context;
}

void ApplyIdentity(OsBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id = id.container_id;
    row.container     = id.context;
}

void ApplyIdentity(InterfaceBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id = id.container_id;
    row.container     = id.context;
}

void ApplyIdentity(NetworkAddressBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id = id.container_id;
    row.container     = id.context;
}

void ApplyIdentity(ProtocolBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id = id.container_id;
    row.container     = id.context;
}

void ApplyIdentity(ServiceBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id = id.container_id;
    row.container     = id.context;
}

void ApplyIdentity(HardwareBaselineRow& row, const ContainerIdentity& id)
{
    row.container_id = id.container_id;
    row.container     = id.context;
}

namespace {

/// Generic runtime context block, always present for a containerized row.
/// Fields default to empty/zero when `ctx` is null (container_instances
/// lookup didn't resolve) so callers still get a well-formed "container"
/// object carrying at least the id.
nlohmann::json ContainerBlock(const std::string& container_id, const ContainerContextPtr& ctx)
{
    nlohmann::json block;
    block["id"]      = container_id;
    block["name"]    = ctx ? ctx->name : std::string {};
    block["runtime"] = ctx ? ctx->runtime : std::string {};

    nlohmann::json image;
    image["name"]   = ctx ? ctx->image : std::string {};
    image["digest"] = ctx ? ctx->image_digest : std::string {};
    block["image"] = std::move(image);

    block["labels"]        = ctx ? ctx->labels : std::map<std::string, std::string> {};
    block["restart_count"] = ctx ? ctx->restart_count : 0;

    auto network = nlohmann::json::array();
    if (ctx) {
        for (const auto& iface : ctx->network) {
            network.push_back({{"name", iface.name}, {"ip", iface.ip}});
        }
    }
    block["network"] = std::move(network);

    auto mounts = nlohmann::json::array();
    if (ctx) {
        for (const auto& mount : ctx->oci_mounts) {
            mounts.push_back(
                {{"source", mount.source}, {"destination", mount.destination}, {"ro", mount.read_only}});
        }
    }
    block["oci_mounts"] = std::move(mounts);

    return block;
}

/// Kubernetes-only enrichment block. Omitted entirely (not an empty object)
/// when the container isn't Kubernetes-origin, per event_schema.md: host and
/// Docker rows must not carry a misleading empty "kubernetes" key.
std::optional<nlohmann::json> KubernetesBlock(const ContainerContextPtr& ctx)
{
    if (!ctx || !ctx->kubernetes) {
        return std::nullopt;
    }
    const auto& k8s = *ctx->kubernetes;

    nlohmann::json block;
    if (!k8s.k8s_namespace.empty()) block["namespace"] = k8s.k8s_namespace;

    nlohmann::json pod;
    if (!k8s.pod_uid.empty())  pod["uid"]  = k8s.pod_uid;
    if (!k8s.pod_name.empty()) pod["name"] = k8s.pod_name;
    if (!pod.empty()) block["pod"] = std::move(pod);

    if (!k8s.node_name.empty()) block["node"] = {{"name", k8s.node_name}};
    if (!k8s.annotations.empty()) block["annotations"] = k8s.annotations;

    if (!k8s.owner_refs.empty()) {
        auto owners = nlohmann::json::array();
        for (const auto& owner : k8s.owner_refs) {
            owners.push_back({{"kind", owner.kind}, {"name", owner.name}, {"uid", owner.uid}});
        }
        block["owner_refs"] = std::move(owners);
    }

    return block;
}

/// Stamps the "container" block, and the "kubernetes" block when present,
/// onto `data`. Shared by every Build*Json() below.
void StampContainerContext(nlohmann::json& data, const std::string& container_id, const ContainerContextPtr& ctx)
{
    data["container"] = ContainerBlock(container_id, ctx);
    if (auto kubernetes = KubernetesBlock(ctx)) {
        data["kubernetes"] = std::move(*kubernetes);
    }
}

/// Emit an all-digit string as a JSON number so it satisfies schema fields typed
/// `long` (pid) or `date` (epoch seconds); the strict validator rejects a numeric
/// value carried as a string. No-op (returns false) for empty/non-numeric input,
/// so the caller can omit the field entirely — strict mode allows missing keys.
bool SetNumericIfDigits(nlohmann::json& obj, const char* key, const std::string& s)
{
    if (s.empty()) return false;
    for (const char c : s) {
        if (c < '0' || c > '9') return false;
    }
    obj[key] = static_cast<int64_t>(std::stoll(s));
    return true;
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

    StampContainerContext(data, row.container_id, row.container);

    const std::string id = row.container_id + ":" + row.path;
    return {id, data.dump()};
}

std::pair<std::string, std::string> BuildProcessJson(const ProcessBaselineRow& row)
{
    nlohmann::json data;
    nlohmann::json process;
    SetNumericIfDigits(process, "pid", row.pid); // schema: process.pid is `long`
    process["name"]         = row.name;
    process["state"]        = row.state;
    process["parent"]       = {{"pid", row.parent_pid}};
    process["command_line"] = row.command_line;
    process["args"]         = row.args;
    process["args_count"]   = row.args_count;
    SetNumericIfDigits(process, "start", row.start); // schema: process.start is `date` (epoch)
    process["utime"]        = row.utime;
    process["stime"]        = row.stime;
    data["process"]  = process;
    data["baseline"] = true;

    StampContainerContext(data, row.container_id, row.container);

    const std::string id = row.container_id + ":" + row.pid;
    return {id, data.dump()};
}

std::pair<std::string, std::string> BuildPortJson(const PortBaselineRow& row)
{
    nlohmann::json data;
    data["network"]        = {{"transport", row.network_transport}};
    data["source"]         = {{"ip", row.source_ip},      {"port", row.source_port}};
    data["destination"]    = {{"ip", row.destination_ip}, {"port", row.destination_port}};
    data["interface"] = {{"state", row.interface_state}};
    data["file"]      = {{"inode", std::to_string(row.file_inode)}}; // schema: file.inode is `keyword`
    if (row.process_pid != 0) {
        data["process"] = {{"pid", row.process_pid}, {"name", row.process_name}};
    }
    data["baseline"] = true;

    StampContainerContext(data, row.container_id, row.container);

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
    user["id"]          = std::to_string(row.uid); // schema: user.id is `keyword`
    user["group"]       = {{"id", row.gid}};        // schema: user.group.id is `unsigned_long`
    user["full_name"]   = row.description;          // schema has no user.description; GECOS -> full_name
    user["home"]        = row.home;
    user["shell"]        = row.shell;
    data["user"]     = user;
    data["baseline"] = true;

    StampContainerContext(data, row.container_id, row.container);

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
    data["group"]    = group;
    data["baseline"] = true;

    StampContainerContext(data, row.container_id, row.container);

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
    // schema: package.installed is `date` — omit when empty, epoch digits -> number,
    // otherwise pass through as an ISO8601 string.
    if (!row.install_time.empty() && !SetNumericIfDigits(package, "installed", row.install_time)) {
        package["installed"] = row.install_time;
    }
    package["category"]     = row.category;
    package["source"]       = row.source;
    package["type"]         = row.format;
    data["package"]  = package;
    data["baseline"] = true;

    StampContainerContext(data, row.container_id, row.container);

    // name+arch+version identifies a package row; multiarch dpkg installs the
    // same name for several architectures, so arch must be part of the key.
    const std::string id = row.container_id + ":pkg:" + row.format + ":" + row.name + ":" +
                            row.architecture + ":" + row.version;
    return {id, data.dump()};
}

std::pair<std::string, std::string> BuildOsJson(const OsBaselineRow& row)
{
    nlohmann::json data;
    // schema: wazuh-states-inventory-system nests the OS under host.os (no top-level
    // "os", and no "family" slot — ID_LIKE is dropped). Kernel release -> host.os.kernel.release.
    nlohmann::json os;
    os["name"]     = row.name;
    os["full"]     = row.full;
    os["version"]  = row.version;
    os["codename"] = row.codename;
    os["platform"] = row.platform;
    os["type"]     = "linux";
    if (!row.kernel.empty()) os["kernel"] = {{"release", row.kernel}};
    data["host"]["os"] = os;
    data["baseline"]   = true;
    StampContainerContext(data, row.container_id, row.container);

    // One OS row per container.
    const std::string id = row.container_id + ":os";
    return {id, data.dump()};
}

std::pair<std::string, std::string> BuildInterfaceJson(const InterfaceBaselineRow& row)
{
    nlohmann::json data;
    nlohmann::json iface;
    iface["name"]  = row.name;
    iface["mtu"]   = row.mtu;
    iface["state"] = row.state;
    iface["type"]  = row.type;
    data["interface"] = iface;

    // schema (wazuh-states-inventory-interfaces): the link-layer address is host.mac
    // (keyword), not interface.mac, and the RX/TX counters live under
    // host.network.ingress/egress — there is no top-level "statistics" object, and
    // the drop counter is named "drops", not "dropped".
    if (!row.mac.empty()) data["host"]["mac"] = row.mac;
    data["host"]["network"]["ingress"] = {{"bytes", row.rx_bytes}, {"packets", row.rx_packets},
                                          {"errors", row.rx_errors}, {"drops", row.rx_dropped}};
    data["host"]["network"]["egress"]  = {{"bytes", row.tx_bytes}, {"packets", row.tx_packets},
                                          {"errors", row.tx_errors}, {"drops", row.tx_dropped}};
    data["baseline"]  = true;
    StampContainerContext(data, row.container_id, row.container);

    const std::string id = row.container_id + ":iface:" + row.name;
    return {id, data.dump()};
}

std::pair<std::string, std::string> BuildNetworkAddressJson(const NetworkAddressBaselineRow& row)
{
    nlohmann::json data;
    // schema (wazuh-states-inventory-networks): the interface name is the top-level
    // interface.name keyword, matching the host network-address row — not
    // network.interface (which the schema does not define).
    data["interface"] = {{"name", row.interface_name}};

    nlohmann::json network;
    network["ip"]      = row.address;
    network["netmask"] = row.netmask;
    if (!row.broadcast.empty()) network["broadcast"] = row.broadcast;
    // schema has no network.protocol: the address family ("ipv4"/"ipv6") is carried
    // in network.type (keyword), the same slot the host row uses.
    if (!row.protocol.empty()) network["type"] = row.protocol;
    data["network"]   = network;
    data["baseline"]  = true;
    StampContainerContext(data, row.container_id, row.container);

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
    // schema: network.dhcp is boolean. The scanner can only ever report "unknown" for
    // a container rootfs (no distro ifcfg files), so omit the field rather than emit a
    // non-boolean string the strict validator would reject (strict mode allows missing).
    network["metric"] = row.metric;
    data["network"]   = network;
    data["baseline"]  = true;
    StampContainerContext(data, row.container_id, row.container);

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
    StampContainerContext(data, row.container_id, row.container);

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
    StampContainerContext(data, row.container_id, row.container);

    const std::string id = row.container_id + ":hw";
    return {id, data.dump()};
}

namespace {

/// Starts every dbsync row with the two container columns shared by all
/// syscollector tables (syscollectorTablesDef.hpp).
nlohmann::json DbsyncRowBase(const std::string& container_id, const std::string& container_json)
{
    nlohmann::json row;
    row["container_id"]   = container_id;
    row["container_json"] = container_json;
    return row;
}

} // namespace

std::string BuildContainerContextJson(const std::string& container_id, const ContainerContextPtr& ctx)
{
    nlohmann::json data;
    data["container"] = ContainerBlock(container_id, ctx);
    if (auto kubernetes = KubernetesBlock(ctx)) {
        data["kubernetes"] = std::move(*kubernetes);
    }
    return data.dump();
}

std::string BuildFimFileDbsyncRow(const FileBaselineRow& row, const std::string& container_json)
{
    auto data = DbsyncRowBase(row.container_id, container_json);
    data["path"]        = row.path;
    data["device"]      = static_cast<int64_t>(row.device);
    data["inode"]       = static_cast<int64_t>(row.inode);
    data["size"]        = static_cast<int64_t>(row.size);
    data["permissions"] = row.permissions;
    data["attributes"]  = "";
    data["uid"]         = row.uid;
    data["gid"]         = row.gid;
    data["owner"]       = row.owner;
    data["group_"]      = row.group;
    data["mtime"]       = row.mtime;
    data["hash_md5"]    = row.hash_md5;
    data["hash_sha1"]   = row.hash_sha1;
    data["hash_sha256"] = row.hash_sha256;
    // checksum column intentionally omitted — caller computes and inserts it.
    return data.dump();
}

std::string BuildProcessDbsyncRow(const ProcessBaselineRow& row, const std::string& container_json)
{
    auto data = DbsyncRowBase(row.container_id, container_json);
    data["pid"]          = row.pid;
    data["name"]         = row.name;
    data["state"]        = row.state;
    data["parent_pid"]   = row.parent_pid;
    data["utime"]        = row.utime;
    data["stime"]        = row.stime;
    data["command_line"] = row.command_line;
    data["args"]         = row.args;
    data["args_count"]   = row.args_count;
    data["start"]        = row.start;
    return data.dump();
}

std::string BuildPortDbsyncRow(const PortBaselineRow& row, const std::string& container_json)
{
    auto data = DbsyncRowBase(row.container_id, container_json);
    data["network_transport"] = row.network_transport;
    data["source_ip"]         = row.source_ip;
    data["source_port"]       = row.source_port;
    data["destination_ip"]    = row.destination_ip;
    data["destination_port"]  = row.destination_port;
    data["file_inode"]        = static_cast<int64_t>(row.file_inode);
    data["interface_state"]   = row.interface_state;
    data["process_pid"]       = row.process_pid;
    data["process_name"]      = row.process_name;
    return data.dump();
}

std::string BuildUserDbsyncRow(const UserBaselineRow& row, const std::string& container_json)
{
    auto data = DbsyncRowBase(row.container_id, container_json);
    data["user_name"]      = row.name;
    data["user_id"]        = row.uid;
    data["user_group_id"]  = row.gid;
    data["user_full_name"] = row.description;
    data["user_home"]      = row.home;
    data["user_shell"]     = row.shell;
    return data.dump();
}

std::string BuildGroupDbsyncRow(const GroupBaselineRow& row, const std::string& container_json)
{
    auto data = DbsyncRowBase(row.container_id, container_json);
    data["group_name"] = row.name;
    data["group_id"]   = row.gid;
    std::string users;
    for (const auto& member : row.members) {
        if (!users.empty()) users += ',';
        users += member;
    }
    data["group_users"] = users;
    return data.dump();
}

std::string BuildPackageDbsyncRow(const PackageBaselineRow& row, const std::string& container_json)
{
    auto data = DbsyncRowBase(row.container_id, container_json);
    data["name"]         = row.name;
    data["version_"]     = row.version;
    data["architecture"] = row.architecture;
    data["description"]  = row.description;
    data["size"]         = row.size;
    data["vendor"]       = row.vendor;
    data["installed"]    = row.install_time;
    data["category"]     = row.category;
    data["source"]       = row.source;
    data["type"]         = row.format;
    data["path"]         = ""; // PK member — must be present, container packages carry no path.
    return data.dump();
}

std::string BuildOsDbsyncRow(const OsBaselineRow& row, const std::string& container_json)
{
    auto data = DbsyncRowBase(row.container_id, container_json);
    data["os_name"]           = row.name;
    data["os_full"]           = row.full;
    data["os_version"]        = row.version;
    data["os_codename"]       = row.codename;
    data["os_platform"]       = row.platform;
    data["os_type"]           = "linux";
    data["os_kernel_release"] = row.kernel;
    return data.dump();
}

std::string BuildInterfaceDbsyncRow(const InterfaceBaselineRow& row, const std::string& container_json)
{
    auto data = DbsyncRowBase(row.container_id, container_json);
    data["interface_name"]  = row.name;
    data["interface_alias"] = ""; // PK member — containers have no alias.
    data["interface_type"]  = row.type;
    data["interface_state"] = row.state;
    data["interface_mtu"]   = row.mtu;
    data["host_mac"]        = row.mac;
    data["host_network_ingress_bytes"]    = static_cast<int64_t>(row.rx_bytes);
    data["host_network_ingress_packages"] = static_cast<int64_t>(row.rx_packets);
    data["host_network_ingress_errors"]   = static_cast<int64_t>(row.rx_errors);
    data["host_network_ingress_drops"]    = static_cast<int64_t>(row.rx_dropped);
    data["host_network_egress_bytes"]     = static_cast<int64_t>(row.tx_bytes);
    data["host_network_egress_packages"]  = static_cast<int64_t>(row.tx_packets);
    data["host_network_egress_errors"]    = static_cast<int64_t>(row.tx_errors);
    data["host_network_egress_drops"]     = static_cast<int64_t>(row.tx_dropped);
    return data.dump();
}

std::string BuildNetworkAddressDbsyncRow(const NetworkAddressBaselineRow& row, const std::string& container_json)
{
    auto data = DbsyncRowBase(row.container_id, container_json);
    data["interface_name"]    = row.interface_name;
    // dbsync_network_address.network_type is INTEGER: 0 = IPv4, 1 = IPv6 (same
    // convention sysinfo uses for host rows).
    data["network_type"]      = (row.protocol == "ipv6") ? 1 : 0;
    data["network_ip"]        = row.address;
    data["network_netmask"]   = row.netmask;
    data["network_broadcast"] = row.broadcast;
    return data.dump();
}

std::string BuildProtocolDbsyncRow(const ProtocolBaselineRow& row, const std::string& container_json)
{
    auto data = DbsyncRowBase(row.container_id, container_json);
    data["interface_name"]  = row.interface_name;
    data["network_type"]    = row.type;
    data["network_gateway"] = row.gateway;
    // network_dhcp omitted: scanner only ever knows "unknown" for a container rootfs.
    data["network_metric"]  = std::to_string(row.metric);
    return data.dump();
}

std::string BuildServiceDbsyncRow(const ServiceBaselineRow& row, const std::string& container_json)
{
    auto data = DbsyncRowBase(row.container_id, container_json);
    data["service_id"]          = row.name;
    data["service_name"]        = row.name;
    data["service_description"] = row.description;
    data["service_state"]       = row.state;
    data["service_enabled"]     = row.enabled;
    data["service_type"]        = row.type;
    data["process_executable"]  = row.executable;
    data["file_path"]           = row.file_path; // PK member.
    return data.dump();
}

std::string BuildHardwareDbsyncRow(const HardwareBaselineRow& row, const std::string& container_json)
{
    auto data = DbsyncRowBase(row.container_id, container_json);
    // serial_number is the table's PK slot; a container's virtual hardware has
    // no board serial, so the container_id fills it (unique per container).
    data["serial_number"] = row.container_id;
    data["cpu_name"]      = row.cpu_name;
    data["cpu_cores"]     = row.cpu_cores;
    data["cpu_speed"]     = row.cpu_speed;
    data["memory_total"]  = row.memory_total;
    data["memory_free"]   = row.memory_free;
    data["memory_used"]   = row.memory_used;
    return data.dump();
}

} // namespace wazuh::container_baseline
