/**
 * @brief Sandbox environment implementation
 */
#include "environment.hpp"


/**
 * @brief Changes the current environment status between enabled or disabled
 * 
 * 
 * @return true if status was false
 * @return false if status was true
 */
bool Sandbox::Environment::toggle() {
    return (enabled = ! enabled);
}

/**
 * @brief Returns if the environment is enabled or not
 * 
 * @return true 
 * @return false 
 */
bool Sandbox::Environment::isEnabled() {
    return enabled == true;
}

/**
 * @brief Return if this environment is named s
 * 
 * @param s 
 * @return true 
 * @return false 
 */
bool Sandbox::Environment::is(const std::string& s) {
    return id == s;
}
