#ifndef _BUILDERS_NORMALIZE_STAGE_H
#define _BUILDERS_NORMALIZE_STAGE_H

#include <rxcpp/rx.hpp>
#include <stdexcept>
#include <string>

#include "connectable.hpp"
#include "json.hpp"

#include "builders/map.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds stage normalize
 *
 * @param inputObs
 * @param inputJson
 * @return rxcpp::observable<json::Document>
 */
rxcpp::observable<json::Document> normalizeStageBuilder(rxcpp::observable<json::Document> inputObs,
                                                        const json::Value * inputJson)
{
    if (!inputJson->IsArray())
    {
        throw std::invalid_argument("Normalize stage builder expects and array, but got " + inputJson->GetType());
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

} // namespace builder::internals::builders

#endif // _BUILDERS_NORMALIZE_STAGE_H
