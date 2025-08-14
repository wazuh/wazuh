#ifndef _CONF_FILELOADER_MOCK_HPP
#define _CONF_FILELOADER_MOCK_HPP

#include <gmock/gmock.h>

#include <conf/fileLoader.hpp>

namespace conf::mocks
{

class MockFileLoader : public IFileLoader
{
public:
    MOCK_METHOD(OptionMap, load, (), (const, override));
};

} // namespace conf::mocks

#endif // _CONF_FILELOADER_MOCK_HPP
