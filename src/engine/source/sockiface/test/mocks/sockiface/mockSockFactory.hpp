#ifndef _SOCKIFACE_MOCK_SOCK_FACTORY_HPP
#define _SOCKIFACE_MOCK_SOCK_FACTORY_HPP

#include <gmock/gmock.h>

#include <sockiface/isockFactory.hpp>

class MockSockFactory : public sockiface::ISockFactory
{
public:
    MOCK_METHOD(std::shared_ptr<sockiface::ISockHandler>,
                getHandler,
                (sockiface::ISockHandler::Protocol proto, std::string_view path, uint32_t maxMsgSize),
                (override));
    MOCK_METHOD(std::shared_ptr<sockiface::ISockHandler>,
                getHandler,
                (sockiface::ISockHandler::Protocol proto, std::string_view path),
                (override));
};

#endif // _SOCKIFACE_MOCK_SOCK_FACTORY_HPP
