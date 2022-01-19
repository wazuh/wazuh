#ifndef _BUILDERS_DECODER_H
#define _BUILDERS_DECODER_H

#include <rxcpp/rx.hpp>
#include <stdexcept>
#include <string>

#include "connectable.hpp"
#include "json.hpp"

#include "builders/condition.hpp"
#include "builders/map.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds stage check
 *
 * @param inputObs
 * @param inputJson
 * @return rxcpp::observable<json::Document>
 */
rxcpp::observable<json::Document> decoderCheckBuilder(rxcpp::observable<json::Document> inputObs,
                                                      const json::Value * inputJson)
{
    if (!inputJson->IsArray())
    {
        throw std::invalid_argument("Check builder expects and array, but got " + inputJson->GetType());
    }

    auto outputObs = inputObs;
    for (rapidjson::Value::ConstValueIterator it = inputJson->GetArray().Begin(); it != inputJson->GetArray().End();
         it++)
    {
        const json::Value * valueRef = static_cast<const json::Value *>(it);
        outputObs = conditionBuilder(outputObs, valueRef);
    }

    return outputObs;
}

/**
 * @brief Bluilds stage normalize
 *
 * @param inputObs
 * @param inputJson
 * @return rxcpp::observable<json::Document>
 */
rxcpp::observable<json::Document> decoderNormalizeBuilder(rxcpp::observable<json::Document> inputObs,
                                                          const json::Value * inputJson)
{
    if (!inputJson->IsArray())
    {
        throw std::invalid_argument("Check builder expects and array, but got " + inputJson->GetType());
    }

    auto outputObs = inputObs;
    for (rapidjson::Value::ConstValueIterator it = inputJson->GetArray().Begin(); it != inputJson->GetArray().End();
         it++)
    {
        const json::Value * valueRef = static_cast<const json::Value *>(it);
        outputObs = mapBuilder(outputObs, valueRef);
    }

    return outputObs;
}

/**
 * @brief Builds decoder connectable
 *
 * @param inputJson
 * @return Connectable
 */
Connectable decoderBuilder(const json::Document & inputJson)
{
    std::vector<std::string> parents;
    // Needed because check function is ambigous, need to look for constructors to be explicited
    std::string tmpStr{".parents"};
    if (inputJson.check(tmpStr))
    {
        for (rapidjson::Value::ConstValueIterator it = inputJson.get(".parents")->GetArray().Begin();
             it != inputJson.get(".parents")->GetArray().End(); it++)
        {
            parents.push_back(it->GetString());
        }
    }
    Connectable connectable(inputJson.get(".name")->GetString(), parents);

    // Build check
    auto outputObs = decoderCheckBuilder(connectable.output(), inputJson.get(".check"));

    // Build normalize
    outputObs = decoderNormalizeBuilder(outputObs, inputJson.get(".normalize"));

    // Update connectable and return
    connectable.set(outputObs);

    return connectable;
}

} // namespace builder::internals::builders

#endif // _BUILDERS_DECODER_H
