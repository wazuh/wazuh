#ifndef _SOCKIFACE_UNIXSOCKETFACTORY_HPP
#define _SOCKIFACE_UNIXSOCKETFACTORY_HPP

#include <sockiface/isockFactory.hpp>

#include "unixDatagram.hpp"
#include "unixSecureStream.hpp"

namespace sockiface
{
class UnixSocketFactory : public ISockFactory
{
public:
    /**
     * @copydoc ISockFactory::getHandler
     */
    std::shared_ptr<ISockHandler>
    getHandler(ISockHandler::Protocol proto, std::string_view path, uint32_t maxMsgSize) override
    {
        switch (proto)
        {
            case ISockHandler::Protocol::DATAGRAM: return std::make_shared<unixDatagram>(path, maxMsgSize);
            case ISockHandler::Protocol::STREAM: return std::make_shared<unixSecureStream>(path, maxMsgSize);
            default: throw std::runtime_error("Invalid protocol");
        }
    }

    /**
     * @copydoc ISockFactory::getHandler
     */
    std::shared_ptr<ISockHandler> getHandler(ISockHandler::Protocol proto, std::string_view path) override
    {
        switch (proto)
        {
            case ISockHandler::Protocol::DATAGRAM: return std::make_shared<unixDatagram>(path);
            case ISockHandler::Protocol::STREAM: return std::make_shared<unixSecureStream>(path);
            default: throw std::runtime_error("Invalid protocol");
        }
    }
};
} // namespace sockiface

#endif // _SOCKIFACE_UNIXSOCKETFACTORY_HPP
