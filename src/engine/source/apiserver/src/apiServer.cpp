// Copyright (C) 2024 Wazuh Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include <apiserver/apiServer.hpp>
#include <base/json.hpp>
#include <base/logging.hpp>
#include <stdexcept>

using namespace apiserver;

ApiServer::ApiServer()
{
    m_svr.set_logger(
        [](const auto& /*req*/, const auto& /*res*/)
        {
            // TODO: Add metrics here.
        });

    m_svr.set_error_handler(
        [](const auto& /*req*/, auto& res)
        {
            // TODO: Add metrics here.
            json::Json response {};
            response.appendString("Service Unavailable", "/error");
            response.setInt(res.status, "/code");
            res.set_content(response.str(), "application/json");
        });
}

ApiServer::~ApiServer()
{
    stop();
}

void ApiServer::start(const std::filesystem::path& socketPath)
{
    if (socketPath.empty())
    {
        throw std::invalid_argument("Socket path cannot be empty");
    }

    if (m_svr.is_running())
    {
        throw ServerAlreadyRunningException();
    }

    m_svr.set_address_family(AF_UNIX);

    // Create parent directory if it does not exist
    if (socketPath.has_parent_path() && !std::filesystem::exists(socketPath.parent_path()))
    {
        std::filesystem::create_directories(socketPath.parent_path());
    }

    if (std::filesystem::exists(socketPath.string()))
    {
        std::filesystem::remove(socketPath);
    }

    m_thread = std::thread([this, socketPath]() { m_svr.listen(socketPath, true); });

    m_svr.wait_until_ready();
}

void ApiServer::stop()
{
    m_svr.stop();

    if (m_thread.joinable())
    {
        m_thread.join();
    }
}

void ApiServer::addRoute(const Method method,
                         const std::string& route,
                         const std::function<void(const httplib::Request&, httplib::Response&)>& handler)
{
    switch (method)
    {
        case Method::GET: m_svr.Get(route, handler); break;
        case Method::POST: m_svr.Post(route, handler); break;
        case Method::PUT: m_svr.Put(route, handler); break;
        case Method::DELETE: m_svr.Delete(route, handler); break;
        default: LOG_ERROR("Invalid method: {}", static_cast<int>(method)); break;
    }
}

bool ApiServer::isRunning() const
{
    return m_svr.is_running();
}
