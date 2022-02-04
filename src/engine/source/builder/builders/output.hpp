#ifndef _BUILDERS_OUTPUT_H
#define _BUILDERS_OUTPUT_H

#include <rxcpp/rx.hpp>
#include <stdexcept>
#include <string>

#include "connectable.hpp"
#include "json.hpp"
#include "builders/buildCheck.hpp"
#include "builders/buildOutput.hpp"
#include "builders/stage.hpp"

namespace builder::internals::builders
{
    // The type of the event which will flow through the stream
    using Event_t = json::Document;
    // The type of the observable which will compose the processing graph
    using Obs_t = rxcpp::observable<Event_t>;
    // The type of the connectables whisch will help us connect the assets ina graph
    using Con_t = builder::internals::Connectable<Obs_t>;
    // The type of a connectable operation
    using Op_t = std::function<Obs_t(const Obs_t &)>;
    // The signature of a maker function which will build an asset into a`
    // connectable.

    using Graph_t = graph::Graph<Con_t>;
/**
 * @brief Builds output connectable
 *
 * @param inputJson
 * @return Connectable
 */
Con_t buildOutput(const json::Document & def)
{
    std::vector<std::string> parents;
    const json::Value * name;
    const json::Value * checkVal;
    const json::Value * outputs;

    if (def.exists(".parents"))
    {
        for (auto & i : def.get(".parents")->GetArray())
        {
            parents.push_back(i.GetString());
        }
    }

    try
    {
        name = def.get(".name");
    }
    catch (std::invalid_argument & e)
    {
        std::throw_with_nested(std::invalid_argument("Output builder expects definition to have a .name entry."));
    }

    try
    {
        checkVal = def.get(".check");
    }
    catch (std::invalid_argument & e)
    {
        std::throw_with_nested(std::invalid_argument("Output builder expects definition to have a .allow section."));
    }

    Op_t checkStage = buildStageChain(checkVal, buildCheck);

    try
    {
        outputs = def.get(".outputs");
    }
    catch (std::invalid_argument & e)
    {
        std::throw_with_nested(std::invalid_argument("Output builder expects definition to have a .outputs section."));
    }
    Op_t outputsStage = buildOutputStage(outputs);
    
    return Con_t(name->GetString(), parents,[=](const Obs_t & input) -> Obs_t { return outputsStage(checkStage(input)); });
}

} // namespace builder::internals::builders
#endif // _BUILDERS_OUTPUT_H
