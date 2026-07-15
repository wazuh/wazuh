#include "container_connector_client.hpp"

#include <json.hpp>

#include <cerrno>
#include <cstring>
#include <utility>

#include <fcntl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace wazuh::container_connector {

namespace {

constexpr size_t kMaxResponseBytes = 1 << 16;  // 64 KiB

class ScopedFd
{
public:
    explicit ScopedFd(int fd = -1) noexcept : fd_(fd) {}
    ~ScopedFd() noexcept { if (fd_ >= 0) ::close(fd_); }
    ScopedFd(const ScopedFd&)            = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;
    int  get()     const noexcept { return fd_; }
    bool valid()   const noexcept { return fd_ >= 0; }
    int  release() noexcept       { int t = fd_; fd_ = -1; return t; }

private:
    int fd_;
};

bool WaitWritable(int fd, std::chrono::milliseconds timeout)
{
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    timeval tv{
        static_cast<time_t>(timeout.count() / 1000),
        static_cast<suseconds_t>((timeout.count() % 1000) * 1000),
    };
    return ::select(fd + 1, nullptr, &wfds, nullptr, &tv) > 0;
}

bool WaitReadable(int fd, std::chrono::milliseconds timeout)
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    timeval tv{
        static_cast<time_t>(timeout.count() / 1000),
        static_cast<suseconds_t>((timeout.count() % 1000) * 1000),
    };
    return ::select(fd + 1, &rfds, nullptr, nullptr, &tv) > 0;
}

} // namespace

ContainerConnectorClient::ContainerConnectorClient(std::string               socket_path,
                                                   std::chrono::milliseconds timeout)
    : socket_path_(std::move(socket_path))
    , timeout_(timeout)
{
}

std::string ContainerConnectorClient::RoundTrip(const std::string& request_line)
{
    ScopedFd fd(::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    if (!fd.valid()) return {};

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socket_path_.size() >= sizeof(addr.sun_path)) return {};
    std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (::connect(fd.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        if (errno != EINPROGRESS) return {};
        if (!WaitWritable(fd.get(), timeout_)) return {};
        int       err     = 0;
        socklen_t err_len = sizeof(err);
        if (::getsockopt(fd.get(), SOL_SOCKET, SO_ERROR, &err, &err_len) < 0 || err != 0) return {};
    }

    // Write request (with newline). The kernel buffers a single small line; we
    // do not bother with partial-write loops at this size.
    const auto wire = request_line + "\n";
    if (!WaitWritable(fd.get(), timeout_)) return {};
    const ssize_t wn = ::write(fd.get(), wire.data(), wire.size());
    if (wn < 0 || static_cast<size_t>(wn) != wire.size()) return {};

    // Read response line.
    std::string out;
    out.reserve(256);
    while (out.size() < kMaxResponseBytes) {
        if (!WaitReadable(fd.get(), timeout_)) return {};
        char buf[1024];
        const ssize_t n = ::read(fd.get(), buf, sizeof(buf));
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
        if (out.find('\n') != std::string::npos) break;
    }
    if (const auto nl = out.find('\n'); nl != std::string::npos) {
        out.resize(nl);
    }
    return out;
}

LookupResult ContainerConnectorClient::Lookup(const std::string& request_line)
{
    LookupResult result;
    const auto   response = RoundTrip(request_line);
    if (response.empty()) {
        return result;  // found == false
    }

    auto j = nlohmann::json::parse(response, nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        return result;
    }
    auto ok_it = j.find("ok");
    if (ok_it == j.end() || !ok_it->is_boolean() || !ok_it->get<bool>()) {
        return result;
    }
    auto meta_it = j.find("meta");
    if (meta_it == j.end() || !meta_it->is_object()) {
        return result;
    }
    result.found     = true;
    result.meta_json = meta_it->dump();
    return result;
}

LookupResult ContainerConnectorClient::LookupByCgroupId(uint64_t cgroup_id)
{
    const nlohmann::json req = {{"op", "lookup_cgroup_id"}, {"cgroup_id", cgroup_id}};
    return Lookup(req.dump());
}

LookupResult ContainerConnectorClient::LookupByContainerId(const std::string& container_id)
{
    const nlohmann::json req = {{"op", "lookup_container_id"}, {"id", container_id}};
    return Lookup(req.dump());
}

long long ContainerConnectorClient::Size()
{
    const auto response = RoundTrip(R"({"op":"size"})");
    if (response.empty()) return -1;
    auto j = nlohmann::json::parse(response, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return -1;
    auto ok_it = j.find("ok");
    if (ok_it == j.end() || !ok_it->is_boolean() || !ok_it->get<bool>()) return -1;
    auto size_it = j.find("size");
    if (size_it == j.end() || !size_it->is_number_integer()) return -1;
    return size_it->get<long long>();
}

} // namespace wazuh::container_connector
