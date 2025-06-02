#ifndef ROUTER_TEST_INTERNAL_MOCKS_TESTER_HPP
#define ROUTER_TEST_INTERNAL_MOCKS_TESTER_HPP

#include <gmock/gmock.h>

#include "itester.hpp"

namespace router
{

class MockTester : public router::ITester
{
public:
    MOCK_METHOD(base::OptError, addEntry, (const test::EntryPost&, bool, bool), (override));
    MOCK_METHOD(base::OptError, removeEntry, (const std::string&), (override));
    MOCK_METHOD(base::OptError, rebuildEntry, (const std::string&), (override));
    MOCK_METHOD(base::OptError, enableEntry, (const std::string&), (override));
    MOCK_METHOD(std::list<test::Entry>, getEntries, (), (const, override));
    MOCK_METHOD(base::RespOrError<test::Entry>, getEntry, (const std::string&), (const, override));
    MOCK_METHOD(base::RespOrError<test::Output>,
                ingestTest,
                (base::Event&&, const ::router::test::Options&),
                (override));
    MOCK_METHOD(base::RespOrError<std::unordered_set<std::string>>, getAssets, (const std::string&), (const, override));
    MOCK_METHOD(bool, updateLastUsed, (const std::string&, uint64_t), (override));
};

} // namespace router

#endif // ROUTER_TEST_INTERNAL_MOCKS_TESTER_HPP
