/**
* @section Sandbox
*
* The Sandbox manages the environments which are ready to be enabled, ie.
* receive events from the server. Particularily, it can:
*  - Create a new environment from its Catalog definition by calling the Builder
*  - Route events received to an environment which is able to accept it
*  - Enable an environment so it can accept events
*  - Disable an environment so it can stop accepting events
*
* In case there is no environment enabled, the sandbox router will drop the
* events, freeing all resources associated to them.
*
* An environment is a set of decoders, rules, filters and outputs which are set
* up to work together and a filter to decide which events to accept.
*
* The sandbox has a router which selects the events
*
*/
#include <vector>
#include <string>
#include <rxcpp/rx.hpp>
#include "environment.hpp"

namespace Sandbox {

/**
 * @brief A sandbox routes messages to environments
 * 
 */
class Sandbox
{
private:
    std::vector<Environment> environments;

public:
    void add(const std::string& environment_id);
    void enable(const std::string& environment_id);
    void disable(const std::string& environment_id);
    std::size_t len();
};

}