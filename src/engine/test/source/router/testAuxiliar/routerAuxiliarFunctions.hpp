#ifndef _ROUTER_AUX_FUNCTIONS_H
#define _ROUTER_AUX_FUNCTIONS_H

#include "utils/stringUtils.hpp"
#include <registry.hpp>
#include <builder.hpp>


namespace aux
{
    std::shared_ptr<builder::Builder> getFakeBuilder();
}

#endif // _ROUTER_AUX_FUNCTIONS_H
