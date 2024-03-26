#ifndef ROUTER_TEST_INTERNAL_MOCKS_WORKER_HPP
#define ROUTER_TEST_INTERNAL_MOCKS_WORKER_HPP

#include <gmock/gmock.h>

#include "iworker.hpp"
#include "mockTester.hpp"
#include "mockRouter.hpp"

namespace router
{

class MockWorker : public router::IWorker
{

public:
    MOCK_METHOD(void, start, (const EpsLimit&), (override));
    MOCK_METHOD(void, stop, (), (override));
    MOCK_METHOD(const std::shared_ptr<IRouter>&, getRouter, (), (const, override));
    MOCK_METHOD(const std::shared_ptr<ITester>&, getTester, (), (const, override));
};

} // namespace router

#endif // ROUTER_TEST_INTERNAL_MOCKS_WORKER_HPP
