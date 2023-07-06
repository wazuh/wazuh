#ifndef _WDB_WDB_MANAGER_HPP
#define _WDB_WDB_MANAGER_HPP

#include <memory>
#include <string>

#include <sockiface/isockFactory.hpp>
#include <wdb/iwdbManager.hpp>

#include "wdbHandler.hpp"

namespace wazuhdb
{

class WDBManager final : public IWDBManager
{
private:
    std::string m_sockPath;
    std::shared_ptr<sockiface::ISockFactory> m_sockFactory;

public:
    using sockProtocol = sockiface::ISockHandler::Protocol;

    WDBManager(const std::string& sockPath, std::shared_ptr<sockiface::ISockFactory> sockFactory)
        : m_sockPath(sockPath)
        , m_sockFactory(sockFactory)
    {
    }

    ~WDBManager() = default;

    /** @brief Create a WazuhDB connection handler from a path
     *
     * @param sockPath Path to the wdb socket
     */
    std::shared_ptr<IWDBHandler> connection() override
    {
        auto socket = m_sockFactory->getHandler(sockProtocol::STREAM, m_sockPath);
        return std::make_shared<WDBHandler>(socket);
    }
};

} // namespace wazuhdb
#endif // _WDB_WDB_MANAGER_HPP
