/**
 * @brief Sandbox implementation
 */
#include <algorithm>
#include "rxcpp/rx.hpp"
#include "sandbox.hpp"


/**
 * @brief Construct a new sandbox::add object
 *
 * @param name
 */
void Sandbox::Sandbox::add(const std::string& name)
{
    Sandbox::Sandbox::environments.push_back(Environment(name));

}

/**
 * @brief Return the number of environments in the sandbox
 *
 * @return int
 */
std::size_t Sandbox::Sandbox::len()
{
    return Sandbox::Sandbox::environments.size();
}

/**
 * @brief Enable an environment so the router is able to
 * send messages to it
 *
 * @param environment_id
 */
void Sandbox::Sandbox::enable(const std::string& environment_id)
{
    std::for_each(begin(environments), end(environments), [&environment_id](Environment& e)
    {
        if( e.is(environment_id) && !e.isEnabled()) {
            e.toggle();
        }
    });

}

/**
 * @brief Disables an already enabled environment. It does nothing if the
 * then environment is already disabled. When an environment is disabled, it
 * will all on-going messages, but will stop receiving new ones.
 *
 * @param environment_id
 */
void Sandbox::Sandbox::disable(const std::string& environment_id)
{
    std::for_each(begin(environments), end(environments), [&environment_id](Environment& e)
    {
        if( e.is(environment_id) && e.isEnabled()) {
            e.toggle();
        }
    });
}