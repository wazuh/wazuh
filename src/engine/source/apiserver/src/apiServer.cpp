#include <apiserver/apiServer.hpp>
#include <base/json.hpp>
#include <base/logging.hpp>

using namespace apiserver;

ApiServer::ApiServer()
{
    m_svr.set_logger(
        [](const auto& /*req*/, const auto& /*res*/)
        {
            // TODO: Add metrics here.
        });

    m_svr.set_error_handler(
        [](const auto& req, auto& res)
        {
            // TODO: Add metrics here.
            json::Json response {};
            response.appendString("Invalid request", "/error");
            response.setInt(res.status, "/code");
            res.set_content(response.str(), "application/json");
        });
}

void ApiServer::stop()
{
    if (m_thread.joinable())
    {
        if (m_svr.is_running())
        {
            m_svr.stop();
        }
        m_thread.join();
    }
}

void ApiServer::start(const std::filesystem::path& socketPath)
{

    m_svr.set_address_family(AF_UNIX);

    // Create parent directory if it does not exist
    if (!std::filesystem::exists(socketPath.parent_path()))
    {
        std::filesystem::create_directories(socketPath.parent_path());
    }

    if (std::filesystem::exists(socketPath.string()))
    {
        std::filesystem::remove(socketPath);
    }

    m_thread = std::thread([this, socketPath]() { m_svr.listen(socketPath, true); });
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
