#ifndef _DUMPER_MOCKDUMPER_HPP
#define _DUMPER_MOCKDUMPER_HPP

#include <gmock/gmock.h>

#include <dumper/idumper.hpp>

namespace dumper::mocks
{
class MockDumper : public IDumper
{
public:
    MOCK_METHOD(void, dump, (const std::string& data), (override));
    MOCK_METHOD(void, dump, (const char* data), (override));
    MOCK_METHOD(void, dump, (std::string_view data), (override));
    MOCK_METHOD(void, activate, (), (override));
    MOCK_METHOD(void, deactivate, (), (override));
    MOCK_METHOD(bool, isActive, (), (const, override));
};
} // namespace dumper::mocks

#endif // _DUMPER_MOCKDUMPER_HPP
