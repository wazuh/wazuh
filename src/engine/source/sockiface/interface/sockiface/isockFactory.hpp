#ifndef _SOCKIFACE_ISOCKMANAGER_HPP
#define _SOCKIFACE_ISOCKMANAGER_HPP

#include <memory>
#include <string_view>

#include <sockiface/isockHandler.hpp>

namespace sockiface
{

class ISockFactory
{
public:
    virtual ~ISockFactory() = default;

    /**
     * @brief Returns a socket handler.
     *
     * @param proto protocol type.
     * @param path path to the socket.
     * @param maxMsgSize maximum message size.
     *
     * @return std::shared_ptr<ISockHandler> handler.
     */
    virtual std::shared_ptr<ISockHandler>
    getHandler(ISockHandler::Protocol proto, std::string_view path, uint32_t maxMsgSize) = 0;

    /**
     * @brief Returns a socket handler.
     *
     * @param proto protocol type.
     * @param path path to the socket.
     *
     * @return std::shared_ptr<ISockHandler> handler.
     */
    virtual std::shared_ptr<ISockHandler> getHandler(ISockHandler::Protocol proto, std::string_view path) = 0;
};

} // namespace sockiface

#endif // _SOCKIFACE_ISOCKMANAGER_HPP
