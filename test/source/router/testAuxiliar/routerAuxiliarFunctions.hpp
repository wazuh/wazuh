#ifndef _ROUTER_AUX_FUNCTIONS_H
#define _ROUTER_AUX_FUNCTIONS_H

#include "utils/stringUtils.hpp"
#include <builder.hpp>
#include <registry.hpp>

namespace aux
{
std::shared_ptr<builder::Builder> getFakeBuilder();

const std::vector<std::string> sampleEventsStr {
    R"(2:10.0.0.1:Test Event - deco_1 )", R"(4:10.0.0.1:Test Event - deco_2 )", R"(8:10.0.0.1:Test Event - deco_3 )"};

} // namespace aux

#endif // _ROUTER_AUX_FUNCTIONS_H
