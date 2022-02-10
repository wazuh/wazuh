#ifndef _REGISTER_HPP
#define _REGISTER_HPP

#include "registry.hpp"
#include <variant>

// Add all builders includes here
#include "buildCheck.hpp"

namespace builder::internals
{
void registerBuilders()
{
    // Needed to initialize the variant type
    Registry::BuildValue b;
    Registry::BuildType c;

    // Register all builders
    // Condition Value
    b = builders::buildCheckVal;
    c = b;
    Registry::registerBuilder("condition.value", c);

    // Condition
    b = builders::buildCheck;
    c = b;
    Registry::registerBuilder("condition", c);
}
} // namespace builder::internals

#endif // _REGISTER_HPP
