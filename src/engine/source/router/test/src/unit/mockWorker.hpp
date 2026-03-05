#ifndef ROUTER_TEST_INTERNAL_MOCKS_WORKER_HPP
#define ROUTER_TEST_INTERNAL_MOCKS_WORKER_HPP

#include <gmock/gmock.h>

#include "irouter.hpp"
#include "itester.hpp"
#include "iworker.hpp"
#include "mockRouter.hpp"
#include "mockTester.hpp"

namespace router
{

class MockRouterWorker : public router::IWorker<router::IRouter>
{

public:
    MOCK_METHOD(void, start, (), (override));
    MOCK_METHOD(void, stop, (), (override));
    MOCK_METHOD(std::shared_ptr<router::IRouter>, get, (), (const, override));
};

class MockTesterWorker : public router::IWorker<router::ITester>
{
public:
    MOCK_METHOD(void, start, (), (override));
    MOCK_METHOD(void, stop, (), (override));
    MOCK_METHOD(std::shared_ptr<router::ITester>, get, (), (const, override));
};

} // namespace router

#endif // ROUTER_TEST_INTERNAL_MOCKS_WORKER_HPP
