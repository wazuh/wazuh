#ifndef _BUILDERS_DECODER_H
#define _BUILDERS_DECODER_H

#include <rxcpp/rx.hpp>
#include <stdexcept>
#include <string>

#include "builders/check_stage.hpp"
#include "builders/normalize_stage.hpp"
#include "connectable.hpp"
#include "json.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds decoder connectable
 *
 * @param inputJson
 * @return Connectable
 */
Connectable decoderBuilder(const json::Document & inputJson)
{
    std::vector<std::string> parents;
    if (inputJson.exists("/parents"))
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
        throw std::invalid_argument("Decoder builder expects decoder to have a name entry.");
    }
    Connectable connectable(name->GetString(), parents);

    // Check stage is mandatory in a decoder
    auto checkVal = inputJson.get(".check");
    if (!checkVal)
    {
        throw std::invalid_argument("Decoder builder expects decoder definition to have a check section. ");
    }
    auto outputObs = checkStageBuilder(connectable.output(), checkVal);

    // Normalize stage is optional
    auto normalizeVal = inputJson.get(".normalize");
    if (normalizeVal)
    {
        outputObs = normalizeStageBuilder(outputObs, normalizeVal);
    }

    // Update connectable and return
    connectable.set(outputObs);

    return connectable;
}

} // namespace builder::internals::builders

#endif // _BUILDERS_DECODER_H
