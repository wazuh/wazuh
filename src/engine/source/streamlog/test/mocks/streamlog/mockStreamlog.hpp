#ifndef _MOCKS_ISTREAMLOG_HPP
#define _MOCKS_ISTREAMLOG_HPP

#include <gmock/gmock.h>

#include <streamlog/ilogger.hpp>

namespace streamlog::mocks
{
class MockILogManager : public ::streamlog::ILogManager
{
public:
    MOCK_METHOD(std::shared_ptr<::streamlog::WriterEvent>, getWriter, (const std::string& name), (override));
};

class MockWriterEvent : public ::streamlog::WriterEvent
{
public:
   // Mocking the operator()
    MOCK_METHOD(bool, CallOperator, (const std::string& message), ());

   bool operator()(std::string&& message) override
   {
       return CallOperator(message);
   }
};

} // namespace streamlog::mocks

#endif // _MOCKS_ISTREAMLOG_HPP
