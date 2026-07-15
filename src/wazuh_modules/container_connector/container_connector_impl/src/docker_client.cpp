#include "docker_client.hpp"

#include "docker_http_client.hpp"
#include "logging_helper.h"

#include <json.hpp>

#include <optional>
#include <stdexcept>
#include <string>

namespace wazuh::container_connector {

namespace {

constexpr const char* kDefaultDockerSocket = "/var/run/docker.sock";

std::string CleanContainerName(const std::string& raw)
{
    if (!raw.empty() && raw.front() == '/') return raw.substr(1);
    return raw;
}

DockerContainerInfo ParseInspect(const nlohmann::json& doc)
{
    DockerContainerInfo info;

    if (auto v = doc.find("Id");           v != doc.end() && v->is_string()) info.container_id = v->get<std::string>();
    if (auto v = doc.find("Name");         v != doc.end() && v->is_string()) info.name         = CleanContainerName(v->get<std::string>());
    if (auto v = doc.find("Image");        v != doc.end() && v->is_string()) info.image_id     = v->get<std::string>();
    if (auto v = doc.find("RestartCount"); v != doc.end() && v->is_number_integer()) info.state.restart_count = v->get<int>();

    if (auto cfg = doc.find("Config"); cfg != doc.end() && cfg->is_object())
    {
        if (auto v = cfg->find("Image"); v != cfg->end() && v->is_string())
            info.image = v->get<std::string>();
        if (auto lv = cfg->find("Labels"); lv != cfg->end() && lv->is_object())
        {
            for (auto it = lv->begin(); it != lv->end(); ++it)
            {
                if (it.value().is_string())
                    info.labels.emplace(it.key(), it.value().get<std::string>());
            }
        }
    }

    if (auto st = doc.find("State"); st != doc.end() && st->is_object())
    {
        if (auto v = st->find("Status");     v != st->end() && v->is_string())          info.state.status     = v->get<std::string>();
        if (auto v = st->find("Running");    v != st->end() && v->is_boolean())         info.state.running    = v->get<bool>();
        if (auto v = st->find("Paused");     v != st->end() && v->is_boolean())         info.state.paused     = v->get<bool>();
        if (auto v = st->find("Restarting"); v != st->end() && v->is_boolean())         info.state.restarting = v->get<bool>();
        if (auto v = st->find("ExitCode");   v != st->end() && v->is_number_integer())  info.state.exit_code  = v->get<int>();
        if (auto v = st->find("StartedAt");  v != st->end() && v->is_string())          info.state.started_at  = v->get<std::string>();
        if (auto v = st->find("FinishedAt"); v != st->end() && v->is_string())          info.state.finished_at = v->get<std::string>();
    }

    if (auto hc = doc.find("HostConfig"); hc != doc.end() && hc->is_object())
    {
        if (auto v = hc->find("NetworkMode"); v != hc->end() && v->is_string())
            info.network_mode = v->get<std::string>();
    }

    if (auto ns = doc.find("NetworkSettings"); ns != doc.end() && ns->is_object())
    {
        if (auto nets = ns->find("Networks"); nets != ns->end() && nets->is_object())
        {
            for (auto it = nets->begin(); it != nets->end(); ++it)
            {
                if (!it.value().is_object()) continue;
                DockerNetworkEndpoint ep;
                ep.network_name = it.key();
                const auto& net = it.value();
                if (auto v = net.find("NetworkID");   v != net.end() && v->is_string())         ep.network_id    = v->get<std::string>();
                if (auto v = net.find("EndpointID");  v != net.end() && v->is_string())         ep.endpoint_id   = v->get<std::string>();
                if (auto v = net.find("Gateway");     v != net.end() && v->is_string())         ep.gateway       = v->get<std::string>();
                if (auto v = net.find("IPAddress");   v != net.end() && v->is_string())         ep.ip_address    = v->get<std::string>();
                if (auto v = net.find("IPPrefixLen"); v != net.end() && v->is_number_integer()) ep.ip_prefix_len = v->get<int>();
                if (auto v = net.find("MacAddress");  v != net.end() && v->is_string())         ep.mac_address   = v->get<std::string>();
                info.networks.push_back(std::move(ep));
            }
        }
    }

    return info;
}

} // namespace

DockerClient::DockerClient(DockerConfig config, std::shared_ptr<StopController> stop, LogCallback log)
    : config_(std::move(config))
    , stop_(std::move(stop))
    , log_(std::move(log))
{
    const auto& path = config_.socket_path.empty()
                           ? std::string{kDefaultDockerSocket}
                           : config_.socket_path;
    http_ = std::make_unique<DockerHttpClient>(path, log_);
}

DockerClient::~DockerClient() = default;

void DockerClient::Log(int level, const std::string& msg) const
{
    if (log_) log_(level, msg);
}

std::vector<DockerContainerInfo> DockerClient::ListContainers()
{
    if (stop_->IsStopRequested()) return {};

    const auto body = http_->Get("/containers/json");
    auto       doc  = nlohmann::json::parse(body, nullptr, false);
    if (doc.is_discarded() || !doc.is_array())
    {
        throw std::runtime_error{"GET /containers/json: invalid JSON response"};
    }

    std::vector<DockerContainerInfo> results;
    results.reserve(doc.size());

    for (const auto& item : doc)
    {
        if (!item.is_object()) continue;
        std::string id;
        if (auto v = item.find("Id"); v != item.end() && v->is_string()) id = v->get<std::string>();
        if (id.empty()) continue;

        try
        {
            if (stop_->IsStopRequested()) break;
            auto full = InspectContainer(id);
            if (full) results.push_back(std::move(*full));
        }
        catch (const std::exception& ex)
        {
            Log(LOG_WARNING, "Failed to inspect container " + id + ": " + ex.what());
        }
    }

    return results;
}

std::optional<DockerContainerInfo> DockerClient::InspectContainer(const std::string& id)
{
    if (stop_->IsStopRequested()) return std::nullopt;

    std::string body;
    try
    {
        body = http_->Get("/containers/" + id + "/json");
    }
    catch (const std::runtime_error& ex)
    {
        // HTTP 404 means the container no longer exists — treat as absent, not an error.
        if (std::string{ex.what()}.find("HTTP 404") != std::string::npos) return std::nullopt;
        throw;
    }

    auto doc = nlohmann::json::parse(body, nullptr, false);
    if (doc.is_discarded() || !doc.is_object())
    {
        throw std::runtime_error{"GET /containers/" + id + "/json: invalid JSON"};
    }

    auto result = ParseInspect(doc);
    return result;
}

void DockerClient::StreamEvents(const std::function<bool(const std::string&)>& on_line,
                                const std::shared_ptr<StopController>&          stop)
{
    // type=container filters to container lifecycle events only.
    http_->StreamGet("/events?type=container", on_line, stop);
}

} // namespace wazuh::container_connector
