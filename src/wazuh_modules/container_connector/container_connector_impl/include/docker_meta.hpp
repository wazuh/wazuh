#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace wazuh::container_connector {

struct DockerNetworkEndpoint
{
    std::string network_name;
    std::string network_id;
    std::string endpoint_id;
    std::string gateway;
    std::string ip_address;
    int         ip_prefix_len{0};
    std::string mac_address;
};

struct DockerContainerState
{
    std::string status;            ///< "running", "paused", "exited", "created", etc.
    bool        running{false};
    bool        paused{false};
    bool        restarting{false};
    int         exit_code{0};
    int         restart_count{0};
    std::string started_at;
    std::string finished_at;
};

struct DockerContainerInfo
{
    std::string                        container_id;   ///< Full 64-char container ID.
    std::string                        name;           ///< Container name without leading '/'.
    std::string                        image;
    std::string                        image_id;
    DockerContainerState               state;
    std::map<std::string, std::string> labels;
    std::vector<DockerNetworkEndpoint> networks;
    std::string                        network_mode;
    uint64_t                           cgroup_id{0};   ///< 0 => not yet resolved.
};

} // namespace wazuh::container_connector
