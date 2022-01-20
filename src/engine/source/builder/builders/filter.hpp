#ifndef _BUILDERS_FILTER_H
#define _BUILDERS_FILTER_H

#include <rxcpp/rx.hpp>
#include <stdexcept>
#include <string>

#include "connectable.hpp"
#include "json.hpp"

#include "builders/check_stage.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds rule connectable
 *
 * @param inputJson
 * @return Connectable
 */
Connectable filterBuilder(const json::Document & inputJson)
{
    std::vector<std::string> parents;
    if (inputJson.exists("/after"))
    {
        for (rapidjson::Value::ConstValueIterator it = inputJson.get(".after")->GetArray().Begin();
             it != inputJson.get(".after")->GetArray().End(); it++)
        {
            parents.push_back(it->GetString());
        }
    }
    auto name = inputJson.get(".name");
    if (!name)
    {
        throw std::invalid_argument("Filter builder must have a name entry.");
    }
    Connectable connectable(name->GetString(), parents);

    // Check stage is mandatory in a rule
    auto checkVal = inputJson.get(".allow");
    if (!checkVal)
    {
        throw std::invalid_argument("Rule builder expects rule definition to have a check section. ");
    }
    auto outputObs = checkStageBuilder(connectable.output(), checkVal);

    // Update connectable and return
    connectable.set(outputObs);

    return connectable;
}

} // namespace builder::internals::builders
#endif // _BUILDERS_FILTER_H
