#include "docker_http_client.hpp"

#include "logging_helper.h"

#include <cerrno>
#include <cctype>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace wazuh::container_connector {

namespace {

constexpr int kHeaderReadTimeoutSec = 10;
constexpr int kBodyReadTimeoutSec   = 10;
constexpr int kStreamPollMs         = 100;

// Read HTTP headers up to and including the blank CRLF line (\r\n\r\n).
std::string ReadHeaders(int fd)
{
    std::string buf;
    buf.reserve(512);
    while (true)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        timeval tv{kHeaderReadTimeoutSec, 0};
        if (::select(fd + 1, &rfds, nullptr, nullptr, &tv) <= 0)
        {
            throw std::runtime_error{"timeout or error reading Docker API response headers"};
        }
        char c;
        if (::read(fd, &c, 1) <= 0)
        {
            throw std::runtime_error{"connection closed while reading response headers"};
        }
        buf.push_back(c);
        if (buf.size() >= 4 &&
            buf[buf.size() - 4] == '\r' && buf[buf.size() - 3] == '\n' &&
            buf[buf.size() - 2] == '\r' && buf[buf.size() - 1] == '\n')
        {
            return buf;
        }
    }
}

struct ParsedHeaders
{
    int     status_code{0};
    bool    chunked{false};
    ssize_t content_length{-1};
};

ParsedHeaders ParseHeaders(const std::string& raw)
{
    ParsedHeaders h;
    const auto    first_crlf = raw.find("\r\n");
    if (first_crlf == std::string::npos)
    {
        throw std::runtime_error{"malformed HTTP response: no CRLF after status line"};
    }

    const auto sp1 = raw.find(' ');
    if (sp1 == std::string::npos || sp1 >= first_crlf)
    {
        throw std::runtime_error{"malformed HTTP status line"};
    }
    const auto sp2  = raw.find(' ', sp1 + 1);
    const auto end  = (sp2 != std::string::npos && sp2 < first_crlf) ? sp2 : first_crlf;
    h.status_code   = std::stoi(raw.substr(sp1 + 1, end - sp1 - 1));

    size_t pos = first_crlf + 2;
    while (pos < raw.size())
    {
        const auto next = raw.find("\r\n", pos);
        if (next == std::string::npos || next == pos) break;
        const auto line  = raw.substr(pos, next - pos);
        pos              = next + 2;
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;

        std::string name  = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        const auto  vs    = value.find_first_not_of(' ');
        if (vs != std::string::npos) value = value.substr(vs);
        for (auto& ch : name)  ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        for (auto& ch : value) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));

        if (name == "transfer-encoding" && value.find("chunked") != std::string::npos)
        {
            h.chunked = true;
        }
        if (name == "content-length")
        {
            try { h.content_length = static_cast<ssize_t>(std::stol(value)); }
            catch (...) {}
        }
    }
    return h;
}

// Chunked transfer encoding decoder, byte-at-a-time.
class ChunkedDecoder
{
    enum class State { SIZE_LINE, DATA, CRLF_AFTER_DATA };

    State       state_{State::SIZE_LINE};
    size_t      remaining_{0};
    std::string size_buf_;
    bool        done_{false};

public:
    // Feed one raw byte. If it is decoded body data, sets `out` and returns true.
    // Returns false for chunk-framing bytes.
    bool Feed(char c, char& out) noexcept
    {
        if (done_) return false;
        switch (state_)
        {
        case State::SIZE_LINE:
            if (c == '\r') return false;
            if (c == '\n')
            {
                const auto semi = size_buf_.find(';');
                const auto hex  = (semi != std::string::npos) ? size_buf_.substr(0, semi) : size_buf_;
                try { remaining_ = std::stoul(hex, nullptr, 16); }
                catch (...) { remaining_ = 0; }
                size_buf_.clear();
                if (remaining_ == 0) { done_ = true; return false; }
                state_ = State::DATA;
                return false;
            }
            size_buf_.push_back(c);
            return false;

        case State::DATA:
            out = c;
            if (--remaining_ == 0) state_ = State::CRLF_AFTER_DATA;
            return true;

        case State::CRLF_AFTER_DATA:
            if (c == '\n') state_ = State::SIZE_LINE;
            return false;
        }
        return false;
    }

    bool Done() const noexcept { return done_; }
};

} // namespace

DockerHttpClient::DockerHttpClient(std::string socket_path, LogCallback log)
    : socket_path_(std::move(socket_path))
    , log_(std::move(log))
{
}

void DockerHttpClient::Log(int level, const std::string& msg) const
{
    if (log_) log_(level, msg);
}

int DockerHttpClient::Connect() const
{
    int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
        throw std::runtime_error{"socket(): " + std::string{std::strerror(errno)}};
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (socket_path_.size() >= sizeof(addr.sun_path))
    {
        ::close(fd);
        throw std::runtime_error{"Docker socket path too long: " + socket_path_};
    }
    std::strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        const auto err = errno;
        ::close(fd);
        throw std::runtime_error{"connect('" + socket_path_ + "'): " + std::strerror(err)};
    }
    return fd;
}

void DockerHttpClient::SendRequest(int fd, const std::string& path) const
{
    const std::string req =
        "GET " + path + " HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n"
        "\r\n";

    size_t sent = 0;
    while (sent < req.size())
    {
        const ssize_t n = ::write(fd, req.data() + sent, req.size() - sent);
        if (n < 0) throw std::runtime_error{"write(): " + std::string{std::strerror(errno)}};
        sent += static_cast<size_t>(n);
    }
}

std::string DockerHttpClient::Get(const std::string& path)
{
    int fd = Connect();
    struct Guard { int fd; ~Guard() { if (fd >= 0) ::close(fd); } } guard{fd};

    SendRequest(fd, path);

    const auto headers = ParseHeaders(ReadHeaders(fd));

    if (headers.status_code != 200)
    {
        throw std::runtime_error{"Docker API " + path + " returned HTTP " +
                                 std::to_string(headers.status_code)};
    }

    if (headers.chunked)
    {
        std::string    body;
        ChunkedDecoder dec;
        char           buf[4096];
        while (!dec.Done())
        {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            timeval tv{kBodyReadTimeoutSec, 0};
            if (::select(fd + 1, &rfds, nullptr, nullptr, &tv) <= 0) break;
            const ssize_t n = ::read(fd, buf, sizeof(buf));
            if (n <= 0) break;
            for (ssize_t i = 0; i < n && !dec.Done(); ++i)
            {
                char out;
                if (dec.Feed(buf[i], out)) body.push_back(out);
            }
        }
        return body;
    }

    if (headers.content_length >= 0)
    {
        const auto     total = static_cast<size_t>(headers.content_length);
        std::string    body(total, '\0');
        size_t         read_total = 0;
        while (read_total < total)
        {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            timeval tv{kBodyReadTimeoutSec, 0};
            if (::select(fd + 1, &rfds, nullptr, nullptr, &tv) <= 0) break;
            const ssize_t n = ::read(fd, body.data() + read_total, total - read_total);
            if (n <= 0) break;
            read_total += static_cast<size_t>(n);
        }
        body.resize(read_total);
        return body;
    }

    // Fallback: read until connection close.
    std::string body;
    char        buf[4096];
    ssize_t     n;
    while ((n = ::read(fd, buf, sizeof(buf))) > 0) body.append(buf, static_cast<size_t>(n));
    return body;
}

void DockerHttpClient::StreamGet(const std::string&                              path,
                                 const std::function<bool(const std::string&)>& on_line,
                                 const std::shared_ptr<StopController>&          stop)
{
    int fd = Connect();
    struct Guard { int fd; ~Guard() { if (fd >= 0) ::close(fd); } } guard{fd};

    SendRequest(fd, path);

    const auto headers = ParseHeaders(ReadHeaders(fd));

    if (headers.status_code != 200)
    {
        throw std::runtime_error{"Docker events stream returned HTTP " +
                                 std::to_string(headers.status_code)};
    }

    std::optional<ChunkedDecoder> decoder;
    if (headers.chunked) decoder.emplace();

    std::string line;
    bool        done = false;

    while (!stop->IsStopRequested() && !done)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        timeval tv{0, kStreamPollMs * 1000};
        const int rc = ::select(fd + 1, &rfds, nullptr, nullptr, &tv);
        if (rc < 0)
        {
            if (errno == EINTR) continue;
            break;
        }
        if (rc == 0) continue;

        char    buf[4096];
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n <= 0) break;

        for (ssize_t i = 0; i < n && !done; ++i)
        {
            char c = buf[i];

            if (decoder)
            {
                if (decoder->Done()) { done = true; break; }
                char out;
                if (!decoder->Feed(c, out)) continue;
                c = out;
            }

            if (c == '\n')
            {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (!line.empty())
                {
                    if (!on_line(line)) { done = true; break; }
                    line.clear();
                }
            }
            else
            {
                line.push_back(c);
            }
        }
    }
}

} // namespace wazuh::container_connector
