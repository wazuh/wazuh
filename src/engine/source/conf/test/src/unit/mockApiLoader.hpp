#ifndef _CONF_APILOADER_MOCK_HPP
#define _CONF_APILOADER_MOCK_HPP

#include <gmock/gmock.h>

#include <conf/apiLoader.hpp>

namespace conf::mocks
{

class MockApiLoader : public IApiLoader
{
public:
    MOCK_METHOD(json::Json, load, (), (const, override));
};

} // namespace conf::mocks

#endif // _CONF_APILOADER_MOCK_HPP
