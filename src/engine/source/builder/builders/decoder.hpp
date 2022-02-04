#ifndef _BUILDERS_DECODER_H
#define _BUILDERS_DECODER_H

#include <rxcpp/rx.hpp>
#include <algorithm>
#include <functional>
#include <vector>
#include <stdexcept>

#include "builders/buildCheck.hpp"
#include "builders/buildMap.hpp"
#include "builders/stage.hpp"
#include "connectable.hpp"
#include "json.hpp"

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
 * @brief Builds decoder connectable from the decoder definition.
 *
 * @param def decoder definition
 * @return Con_t 
 */
Con_t buildDecoder(const json::Document & def)
{
    const json::Value * name;
    const json::Value * checkVal;
    std::vector<std::string> parents;

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
        std::throw_with_nested(std::invalid_argument("Decoder builder expects definition to have a .name entry."));
    }

    try
    {
        checkVal = def.get(".check");
    }
    catch (std::invalid_argument & e)
    {
        std::throw_with_nested(std::invalid_argument("Decoder builder expects definition to have a .allow section."));
    }

    Op_t checkStage = buildStageChain(checkVal, buildCheck);

    // Normalize stage is optional
    Op_t mapStage = unit_op;
    try
    {
        auto mapVal = def.get(".normalize");
        mapStage = buildStageChain(mapVal, buildMap);
    }
    catch (std::invalid_argument & a)
    {
        // normalize stage is optional, in case of an error do nothign
        // we must ensure nothing else could happen here
    }

    return Con_t(name->GetString(), parents, [=](const Obs_t & input) -> Obs_t { return mapStage(checkStage(input)); });
};

} // namespace builder::internals::builders

#endif // _BUILDERS_DECODER_H
