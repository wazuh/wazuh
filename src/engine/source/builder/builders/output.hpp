#ifndef _BUILDERS_OUTPUT_H
#define _BUILDERS_OUTPUT_H

#include <rxcpp/rx.hpp>
#include <stdexcept>
#include <string>

#include "connectable.hpp"
#include "json.hpp"

#include "builders/check_stage.hpp"
#include "builders/file_output.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds output connectable
 *
 * @param inputJson
 * @return Connectable
 */
Connectable outputBuilder(const json::Document & inputJson)
{
    std::vector<std::string> parents;
    if (inputJson.exists(".parents"))
    {
        for (rapidjson::Value::ConstValueIterator it = inputJson.get(".parents")->GetArray().Begin();
             it != inputJson.get(".parents")->GetArray().End(); it++)
        {
            parents.push_back(it->GetString());
        }
    }

    auto name = inputJson.get(".name");
    if (!name)
    {
        throw std::invalid_argument("Output builder must have a name entry.");
    }
    Connectable connectable(name->GetString(), parents);

    // Check stage is mandatory in output
    auto checkVal = inputJson.get(".check");
    if (!checkVal)
    {
        throw std::invalid_argument("Output builder expects output definition to have a check section. ");
    }
    auto outputObs = checkStageBuilder(connectable.output(), checkVal);

    // Outputs stage is mandatory
    checkVal = inputJson.get(".outputs");
    if (!checkVal)
    {
        throw std::invalid_argument("Output builder expects to have outputs section. ");
    }
    else if (!checkVal->IsArray())
    {
        throw std::invalid_argument("Output builder expects outputs section to be an array, but got " +
                                    checkVal->GetType());
    }

    // Iterate and build every output type
    // TODO: once more outputs are added may be better to define a common class for them
    // Only file output supported
    for (auto out = checkVal->Begin(); out != checkVal->End(); ++out)
    {
        // TODO: Check that every item is an object
        // This check must be delegated to its builder once registry is implemented
        std::string outputName = out->MemberBegin()->name.GetString();
        if (outputName == "file")
        {
            fileOutputBuilder(outputObs, &out->MemberBegin()->value);
        }
        else
        {
            throw std::invalid_argument("Output " + outputName + " not supported");
        }
    }

    // Update connectable and return
    connectable.set(outputObs);

    return connectable;
}

} // namespace builder::internals::builders
#endif // _BUILDERS_OUTPUT_H
