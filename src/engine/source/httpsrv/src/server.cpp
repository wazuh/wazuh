#include "server.hpp"

#include <sstream>
#include <stdexcept>

#include <cerrno>
#include <cstring>
#include <sys/stat.h>

#include <fmt/format.h>

#include <base/logging.hpp>
#include <base/process.hpp>

namespace httpsrv
{

Server::Server(const std::string& id)
    : m_srv(std::make_shared<httplib::Server>())
    , m_id(id)
    , m_socketPath()
{
    // General exception handler for routes handlers, handlers must not throw exceptions.
    auto excptFnName = fmt::format("Server::Server({})::set_exception_handler", id);
    m_srv->set_exception_handler(
        [id, excptFnName](const auto&, auto& res, std::exception_ptr ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (std::exception& e)
            {
                LOG_ERROR_L(excptFnName.c_str(),
                            fmt::format("Server {} uncaught route handler exception: {}", id, e.what()));
            }
            catch (...)
            {
                LOG_ERROR_L(excptFnName.c_str(), fmt::format("Server {} uncaught route handler unknown exception", id));
            }

            res.status = httplib::StatusCode::InternalServerError_500;
            res.set_content("Internal server error", "text/plain");
        });

    // TODO: Add Metrics
    auto loggerFnName = fmt::format("Server::Server({})::set_logger", id);
    m_srv->set_logger([id, loggerFnName](const auto& /*req*/, const auto& /*res*/)
                      { LOG_TRACE_L(loggerFnName.c_str(), "Server {} request received", id); });
}

void Server::addRoute(Method method,
                      const std::string& route,
                      const std::function<void(const httplib::Request&, httplib::Response&)>& handler)
{
    try
    {
        switch (method)
        {
            case Method::GET: m_srv->Get(route, handler); break;
            case Method::POST: m_srv->Post(route, handler); break;
            case Method::PUT: m_srv->Put(route, handler); break;
            case Method::DELETE: m_srv->Delete(route, handler); break;
            default: throw std::runtime_error("Invalid method");
        }
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Server {} failed to add route: {}", m_id, e.what()));
    }

    LOG_DEBUG("Server {} added route: {} {}", m_id, methodToStr(method), route);
}

bool Server::bindAndListen()
{
    if (m_socketPath.empty())
    {
        LOG_ERROR("Server {} cannot bind and listen: empty socket path", m_id);
        return false;
    }

    if (!m_srv->bind_to_port(m_socketPath.string(), 80))
    {
        LOG_ERROR("Server {} failed to bind to socket {}", m_id, m_socketPath.string());
        return false;
    }

    if (chmod(m_socketPath.c_str(), 0660) != 0)
    {
        LOG_WARNING("Server {} failed to change socket permissions: {} ({})", m_id, std::strerror(errno), errno);
    }
    else
    {
        LOG_TRACE("Server {} changed socket permissions to 660 for {}", m_id, m_socketPath.string());
    }

    LOG_DEBUG("Server {} bound to socket {}", m_id, m_socketPath.string());

    return m_srv->listen_after_bind();
}

void Server::start(const std::filesystem::path& socketPath, bool useThread)
{
    if (socketPath.empty())
    {
        throw std::runtime_error(fmt::format("Cannot start server {}: empty socket path", m_id));
    }

    if (isRunning())
    {
        throw std::runtime_error(fmt::format("Cannot start server {}: already running", m_id));
    }

    if (!std::filesystem::exists(socketPath.parent_path()))
    {
        throw std::runtime_error(fmt::format(
            "Cannot start server {}: parent directory {} does not exist", m_id, socketPath.parent_path().string()));
    }

    m_srv->set_address_family(AF_UNIX);

    if (std::filesystem::exists(socketPath.string()))
    {
        std::filesystem::remove(socketPath);
        LOG_TRACE("Server {} removed existing socket file {}", m_id, socketPath.string());
    }
    m_socketPath = socketPath;

    if (useThread)
    {
        std::atomic<bool> threadFailed {false};

        m_thread = std::thread(
            [this, &threadFailed]()
            {
                base::process::setThreadName("httpsrv");
                if (!bindAndListen())
                {
                    threadFailed = true;
                }
            });

        const auto timeout = std::chrono::steady_clock::now() + std::chrono::seconds(10);

        while (!threadFailed && std::chrono::steady_clock::now() < timeout)
        {
            if (m_srv->is_running())
            {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        if (threadFailed)
        {
            if (m_thread.joinable())
            {
                m_thread.join();
            }
            throw std::runtime_error(fmt::format("Server {} failed to start at {}", m_id, socketPath.string()));
        }

        auto tid = m_thread.get_id();
        std::stringstream ss;
        ss << tid;
        LOG_INFO("Server {} started in thread {} at {}", m_id, ss.str(), socketPath.string());
    }
    else
    {
        LOG_INFO("Starting server {} at {}", m_id, socketPath.string());
        if (!bindAndListen())
        {
            throw std::runtime_error(fmt::format("Server {} failed to start at {}", m_id, socketPath.string()));
        }
    }
}

void Server::stop() noexcept
{
    try
    {
        if (!isRunning())
        {
            return;
        }

        m_srv->stop();

        if (m_thread.joinable())
        {
            m_thread.join();
        }

        if (!m_socketPath.empty())
        {
            std::filesystem::remove(m_socketPath);
            LOG_TRACE("Server {} removed socket file {}", m_id, m_socketPath.string());
            m_socketPath.clear();
        }

        LOG_INFO("Server {} stopped", m_id);
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Server {} error while stopping: {}", m_id, e.what());
    }
}

} // namespace httpsrv
