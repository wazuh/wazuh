#include "ipc_server.hpp"

#include "container_meta.hpp"
#include "docker_meta.hpp"
#include "docker_metadata_cache.hpp"
#include "logging_helper.h"
#include "metadata_cache.hpp"

#include <json.hpp>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <utility>

#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace wazuh::container_connector {

namespace {

constexpr size_t kMaxRequestBytes      = 8192;
constexpr int    kClientReadTimeoutMs  = 500;
constexpr int    kAcceptSelectTimeoutS = 1;
constexpr mode_t kSocketMode           = 0660;

void CloseFd(int& fd) noexcept
{
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

nlohmann::json ContainerMetaToJson(const ContainerInPod& c)
{
    nlohmann::json j = {
        {"runtime",       "kubernetes"},
        {"container_id",  c.container_id},
        {"name",          c.name},
        {"image",         c.image},
        {"image_id",      c.image_id},
        {"restart_count", c.restart_count},
        {"cgroup_id",     c.cgroup_id},
    };
    if (c.pod) {
        nlohmann::json pod = {
            {"uid",       c.pod->pod_uid},
            {"name",      c.pod->pod_name},
            {"namespace", c.pod->namespace_},
            {"node_name", c.pod->node_name},
        };
        if (!c.pod->labels.empty())      pod["labels"]      = c.pod->labels;
        if (!c.pod->annotations.empty()) pod["annotations"] = c.pod->annotations;
        if (!c.pod->owner_refs.empty()) {
            nlohmann::json refs = nlohmann::json::array();
            for (const auto& ref : c.pod->owner_refs) {
                refs.push_back({{"kind", ref.kind}, {"name", ref.name}});
            }
            pod["owner_refs"] = std::move(refs);
        }
        j["pod"] = std::move(pod);
    }
    return j;
}

nlohmann::json DockerMetaToJson(const DockerContainerInfo& c)
{
    nlohmann::json j = {
        {"runtime",       "docker"},
        {"container_id",  c.container_id},
        {"name",          c.name},
        {"image",         c.image},
        {"image_id",      c.image_id},
        {"restart_count", c.state.restart_count},
        {"cgroup_id",     c.cgroup_id},
    };

    nlohmann::json docker = {
        {"state",        c.state.status},
        {"running",      c.state.running},
        {"paused",       c.state.paused},
        {"restarting",   c.state.restarting},
        {"exit_code",    c.state.exit_code},
        {"started_at",   c.state.started_at},
        {"finished_at",  c.state.finished_at},
        {"network_mode", c.network_mode},
    };

    if (!c.labels.empty()) docker["labels"] = c.labels;

    if (!c.networks.empty()) {
        nlohmann::json nets = nlohmann::json::array();
        for (const auto& ep : c.networks) {
            nets.push_back({
                {"name",           ep.network_name},
                {"network_id",     ep.network_id},
                {"gateway",        ep.gateway},
                {"ip_address",     ep.ip_address},
                {"ip_prefix_len",  ep.ip_prefix_len},
                {"mac_address",    ep.mac_address},
            });
        }
        docker["networks"] = std::move(nets);
    }

    j["docker"] = std::move(docker);
    return j;
}

} // namespace

IpcServer::IpcServer(std::string                     socket_path,
                     MetadataCache*                  cache,
                     DockerMetadataCache*            docker_cache,
                     std::shared_ptr<StopController> stop,
                     LogCallback                     log)
    : socket_path_(std::move(socket_path))
    , cache_(cache)
    , docker_cache_(docker_cache)
    , stop_(std::move(stop))
    , log_(std::move(log))
{
}

IpcServer::~IpcServer()
{
    Stop();
}

void IpcServer::Log(int level, const std::string& msg) const
{
    if (log_) log_(level, msg);
}

void IpcServer::Start()
{
    if (running_) return;

    // Remove a leftover socket from a previous run (does not fail if absent).
    ::unlink(socket_path_.c_str());

    listen_fd_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_fd_ < 0) {
        throw std::runtime_error{std::string{"IpcServer: socket() failed: "} + std::strerror(errno)};
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socket_path_.size() >= sizeof(addr.sun_path)) {
        CloseFd(listen_fd_);
        throw std::runtime_error{"IpcServer: socket path too long (" + socket_path_ + ")"};
    }
    std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        const auto err = errno;
        CloseFd(listen_fd_);
        throw std::runtime_error{"IpcServer: bind('" + socket_path_ + "') failed: " +
                                 std::strerror(err)};
    }

    // 0660 is the Wazuh convention for queue/sockets/*: owner + group access only.
    if (::chmod(socket_path_.c_str(), kSocketMode) < 0) {
        Log(LOG_WARNING, std::string{"IpcServer: chmod failed: "} + std::strerror(errno));
    }

    if (::listen(listen_fd_, 16) < 0) {
        const auto err = errno;
        CloseFd(listen_fd_);
        ::unlink(socket_path_.c_str());
        throw std::runtime_error{"IpcServer: listen() failed: " + std::string{std::strerror(err)}};
    }

    wakeup_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (wakeup_fd_ < 0) {
        const auto err = errno;
        CloseFd(listen_fd_);
        ::unlink(socket_path_.c_str());
        throw std::runtime_error{"IpcServer: eventfd() failed: " + std::string{std::strerror(err)}};
    }

    running_ = true;
    thread_  = std::thread([this] { AcceptLoop(); });

    Log(LOG_INFO, "IpcServer listening on '" + socket_path_ + "'.");
}

void IpcServer::Stop()
{
    if (!running_) return;

    // 1) Wake the select() in AcceptLoop. eventfd write is async-signal-safe and
    //    cannot block; if it ever fails (EBADF, EAGAIN on a 64-bit counter wrap),
    //    closing listen_fd_ below is sufficient to wake select. Result is
    //    deliberately discarded.
    if (wakeup_fd_ >= 0) {
        const uint64_t v   = 1;
        const ssize_t  ret = ::write(wakeup_fd_, &v, sizeof(v));
        static_cast<void>(ret);
    }
    // 2) Close the listening socket so a select that wasn't blocked yet observes
    //    the close (defence-in-depth against races between wakeup and select).
    CloseFd(listen_fd_);

    if (thread_.joinable()) {
        thread_.join();
    }

    CloseFd(wakeup_fd_);
    ::unlink(socket_path_.c_str());
    running_ = false;
}

void IpcServer::AcceptLoop()
{
    while (!stop_->IsStopRequested() && listen_fd_ >= 0) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(listen_fd_, &rfds);
        FD_SET(wakeup_fd_, &rfds);
        const int maxfd = std::max(listen_fd_, wakeup_fd_);

        timeval tv{kAcceptSelectTimeoutS, 0};
        const int rc = ::select(maxfd + 1, &rfds, nullptr, nullptr, &tv);

        if (rc < 0) {
            if (errno == EINTR) continue;
            // Likely listen_fd was closed by Stop() => EBADF. Exit cleanly.
            break;
        }
        if (rc == 0) continue;  // timeout, re-check stop

        if (FD_ISSET(wakeup_fd_, &rfds)) {
            break;  // Stop requested
        }

        if (FD_ISSET(listen_fd_, &rfds)) {
            const int client = ::accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
            if (client < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                if (errno == EBADF || errno == EINVAL) break;  // socket closed mid-accept
                Log(LOG_WARNING, std::string{"IpcServer accept failed: "} + std::strerror(errno));
                continue;
            }
            try {
                HandleClient(client);
            } catch (const std::exception& ex) {
                Log(LOG_WARNING, std::string{"IpcServer client handler threw: "} + ex.what());
            } catch (...) {
                Log(LOG_WARNING, "IpcServer client handler threw unknown exception.");
            }
            ::close(client);
        }
    }

    Log(LOG_DEBUG, "IpcServer accept loop exiting.");
}

void IpcServer::HandleClient(int client_fd)
{
    // Bounded read: stop at first newline or kMaxRequestBytes, whichever first.
    std::string buf;
    buf.reserve(256);
    while (buf.size() < kMaxRequestBytes) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(client_fd, &rfds);
        timeval tv{0, kClientReadTimeoutMs * 1000};
        const int rc = ::select(client_fd + 1, &rfds, nullptr, nullptr, &tv);
        if (rc <= 0) {
            // Timeout or error — drop client without a response.
            return;
        }
        char chunk[256];
        const ssize_t n = ::read(client_fd, chunk, sizeof(chunk));
        if (n <= 0) break;
        buf.append(chunk, static_cast<size_t>(n));
        if (buf.find('\n') != std::string::npos) break;
    }

    if (const auto nl = buf.find('\n'); nl != std::string::npos) {
        buf.resize(nl);
    }

    const auto    response = ProcessRequest(buf) + "\n";
    // Best-effort write: if the client already disconnected we get EPIPE/ECONNRESET;
    // there is nothing useful to do at this point. Result is deliberately discarded.
    const ssize_t ret      = ::write(client_fd, response.data(), response.size());
    static_cast<void>(ret);
}

std::string IpcServer::ProcessRequest(const std::string& request_line)
{
    auto req = nlohmann::json::parse(request_line, /*cb*/ nullptr, /*throw*/ false);
    if (req.is_discarded() || !req.is_object()) {
        return R"({"ok":false,"error":"invalid json"})";
    }

    const auto op_it = req.find("op");
    if (op_it == req.end() || !op_it->is_string()) {
        return R"({"ok":false,"error":"missing op"})";
    }
    const auto op = op_it->get<std::string>();

    if (op == "size") {
        const size_t k8s_sz    = cache_       ? cache_->Size()        : 0;
        const size_t docker_sz = docker_cache_ ? docker_cache_->Size() : 0;
        nlohmann::json resp = {
            {"ok",          true},
            {"size",        k8s_sz + docker_sz},
            {"k8s_size",    k8s_sz},
            {"docker_size", docker_sz},
        };
        return resp.dump();
    }

    if (op == "lookup_cgroup_id") {
        const auto v = req.find("cgroup_id");
        if (v == req.end() || !v->is_number_integer()) {
            return R"({"ok":false,"error":"missing cgroup_id"})";
        }
        const auto cgroup_id = v->get<uint64_t>();

        if (cache_) {
            if (const auto meta = cache_->LookupByCgroupId(cgroup_id)) {
                nlohmann::json resp = {{"ok", true}, {"meta", ContainerMetaToJson(*meta)}};
                return resp.dump();
            }
        }
        if (docker_cache_) {
            if (const auto meta = docker_cache_->LookupByCgroupId(cgroup_id)) {
                nlohmann::json resp = {{"ok", true}, {"meta", DockerMetaToJson(*meta)}};
                return resp.dump();
            }
        }
        return R"({"ok":false})";
    }

    if (op == "lookup_container_id") {
        const auto v = req.find("id");
        if (v == req.end() || !v->is_string()) {
            return R"({"ok":false,"error":"missing id"})";
        }
        const auto id = v->get<std::string>();

        if (cache_) {
            if (const auto meta = cache_->LookupByContainerId(id)) {
                nlohmann::json resp = {{"ok", true}, {"meta", ContainerMetaToJson(*meta)}};
                return resp.dump();
            }
        }
        if (docker_cache_) {
            if (const auto meta = docker_cache_->LookupByContainerId(id)) {
                nlohmann::json resp = {{"ok", true}, {"meta", DockerMetaToJson(*meta)}};
                return resp.dump();
            }
        }
        return R"({"ok":false})";
    }

    return R"({"ok":false,"error":"unknown op"})";
}

} // namespace wazuh::container_connector
