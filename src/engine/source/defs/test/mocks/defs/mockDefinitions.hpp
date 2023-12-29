#ifndef _DEFS_MOCKS_DEFINITIONS_HPP
#define _DEFS_MOCKS_DEFINITIONS_HPP

#include <gmock/gmock.h>

#include "defs/idefinitions.hpp"

namespace defs::mocks
{
class MockDefinitions : public IDefinitions
{
public:
    MOCK_METHOD(json::Json, get, (std::string_view name), (const));
    MOCK_METHOD(bool, contains, (std::string_view name), (const));
    MOCK_METHOD(std::string, replace, (std::string_view input), (const));
};

class MockDefinitionsBuilder : public IDefinitionsBuilder
{
public:
    MOCK_METHOD(std::shared_ptr<IDefinitions>, build, (const json::Json& value), (const));
};
} // namespace defs::mocks

#endif // _DEFS_MOCKS_DEFINITIONS_HPP
