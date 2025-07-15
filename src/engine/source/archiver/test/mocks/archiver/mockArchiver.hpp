#ifndef _ARCHIVER_MOCKARCHIVER_HPP
#define _ARCHIVER_MOCKARCHIVER_HPP

#include <gmock/gmock.h>

#include <archiver/iarchiver.hpp>

namespace archiver::mocks
{
class MockArchiver : public IArchiver
{
public:
    MOCK_METHOD(base::OptError, archive, (const std::string& data), (override));
    MOCK_METHOD(void, activate, (), (override));
    MOCK_METHOD(void, deactivate, (), (override));
    MOCK_METHOD(bool, isActive, (), (const, override));
};
} // namespace archiver::mocks

#endif // _ARCHIVER_MOCKARCHIVER_HPP
