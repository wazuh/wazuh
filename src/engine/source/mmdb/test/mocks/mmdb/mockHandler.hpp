#ifndef _MMDB_MOCK_HANDLER_HPP
#define _MMDB_MOCK_HANDLER_HPP

#include <gmock/gmock.h>

#include <mmdb/ihandler.hpp>

namespace mmdb
{
class MockHandler : public IHandler
{
public:
    MOCK_METHOD(bool, isAvailable, (), (const, override));
    MOCK_METHOD(std::shared_ptr<IResult>, lookup, (const std::string& ip), (const, override));
};
} // namespace mmdb

#endif // _MMDB_MOCK_HANDLER_HPP
