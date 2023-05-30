#ifndef _API_TEST_HANDLERS_HPP
#define _API_TEST_HANDLERS_HPP

#include <api/api.hpp>

namespace api::test::handlers
{

/**
 * @brief Test configuration parameters.
 *
 */
struct Config
{
    int dummy;
};

api::Handler resourceRemove(void);
api::Handler resourceGet(void);
api::Handler resourceList(void);
api::Handler resourceNew(void);

/**
 * @brief Register all handlers for the test API.
 *
 * @param config Test configuration.
 * @param api API instance.
 * @throw std::runtime_error If the command registration fails for any reason and at any
 */
void registerHandlers(const Config& config, std::shared_ptr<api::Api> api);

} // namespace api::test::handlers

#endif // _API_TEST_HANDLERS_HPP
