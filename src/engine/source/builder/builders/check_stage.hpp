#ifndef _BUILDERS_CHECK_STAGE_H
#define _BUILDERS_CHECK_STAGE_H

#include <rxcpp/rx.hpp>
#include <stdexcept>
#include <string>

#include "connectable.hpp"
#include "json.hpp"

#include "builders/condition.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds stage check
 *
 * @param inputObs
 * @param inputJson
 * @return rxcpp::observable<json::Document>
 */
rxcpp::observable<json::Document> checkStageBuilder(rxcpp::observable<json::Document> inputObs,
                                                    const json::Value * inputJson)
{
    if (!inputJson->IsArray())
    {
        throw std::invalid_argument("Check stage builder expects and array, but got " + inputJson->GetType());
    }

    auto outputObs = inputObs;
    for (rapidjson::Value::ConstValueIterator it = inputJson->GetArray().Begin(); it != inputJson->GetArray().End();
         it++)
    {
        outputObs = conditionBuilder(outputObs, it);
    }

    return outputObs;
}

} // namespace builder::internals::builders

#endif // _BUILDERS_CHECK_STAGE_H
