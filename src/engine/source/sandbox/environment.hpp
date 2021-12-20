/**
* @section "Sandbox Environment"
*
* An sandbox environment to which events can be routed.
*
*/
#include <map>
#include <string>

namespace Sandbox {

/**
 * @brief A sandbox environment
 * 
 */
class Environment
{
private:
    std::string id;
    bool enabled;

public:
    bool toggle();
    bool isEnabled();
    bool is(const std::string& id);

    Environment(const std::string& id)
    : id(id), enabled(false)
    {};
};
}
