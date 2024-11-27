#ifndef _API_TESTER_MOCK_TESTER_HPP
#define _API_TESTER_MOCK_TESTER_HPP

#include <gmock/gmock.h>

#include <router/iapi.hpp>

namespace tester::mocks
{

class MockTesterAPI : public ::router::ITesterAPI
{
public:
    MOCK_METHOD(base::OptError, postTestEntry, (const ::router::test::EntryPost& entry), (override));
    MOCK_METHOD(base::OptError, deleteTestEntry, (const std::string& name), (override));
    MOCK_METHOD(base::RespOrError<::router::test::Entry>, getTestEntry, (const std::string& name), (const, override));
    MOCK_METHOD(base::OptError, reloadTestEntry, (const std::string& name), (override));
    MOCK_METHOD(std::list<::router::test::Entry>, getTestEntries, (), (const, override));
    MOCK_METHOD(std::future<base::RespOrError<::router::test::Output>>,
                ingestTest,
                (base::Event && event, const ::router::test::Options& opt),
                (override));
    MOCK_METHOD(base::OptError,
                ingestTest,
                (base::Event && event,
                 const ::router::test::Options& opt,
                 std::function<void(base::RespOrError<::router::test::Output>&&)> callbackFn),
                (override));
    MOCK_METHOD(base::RespOrError<std::unordered_set<std::string>>,
                getAssets,
                (const std::string& name),
                (const, override));
    MOCK_METHOD(std::size_t, getTestTimeout, (), (const, override));
};

} // namespace tester::mocks

#endif // _API_TESTER_MOCK_TESTER_HPP
