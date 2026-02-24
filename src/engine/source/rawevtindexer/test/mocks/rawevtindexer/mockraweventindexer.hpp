#ifndef _RAWEVENTINDEXER_MOCKRAWEVENTINDEXER_HPP
#define _RAWEVENTINDEXER_MOCKRAWEVENTINDEXER_HPP

#include <gmock/gmock.h>

#include <rawevtindexer/iraweventindexer.hpp>

namespace raweventindexer::mocks
{
class MockRawEventIndexer : public IRawEventIndexer
{
public:
    MOCK_METHOD(void, index, (const std::string& data), (override));
    MOCK_METHOD(void, index, (const char* data), (override));
    MOCK_METHOD(void, index, (std::string_view data), (override));
    MOCK_METHOD(void, enable, (), (override));
    MOCK_METHOD(void, disable, (), (override));
    MOCK_METHOD(bool, isEnabled, (), (const, override));
};
} // namespace raweventindexer::mocks

#endif // _RAWEVENTINDEXER_MOCKRAWEVENTINDEXER_HPP
