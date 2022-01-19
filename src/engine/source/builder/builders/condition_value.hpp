#ifndef _BUILDERS_CONDITION_VALUE_H
#define _BUILDERS_CONDITION_VALUE_H

#include <rxcpp/rx.hpp>
#include <string>

#include "json.hpp"

namespace builder::internals::builders
{
/**
 * @brief Builds condtion value operation
 *
 * @param input_observable
 * @param input_json
 * @return rxcpp::observable<json::Document>
 */
rxcpp::observable<json::Document> conditionValueBuilder(const rxcpp::observable<json::Document> & input_observable,
                                                        const json::Value * input_json)
{
    auto valDoc = json::Document(*input_json);

    auto output_observable = input_observable.filter([valDoc](json::Document e) { return e.check(valDoc); });
    return output_observable;
}

} // namespace builder::internals::builders

#endif // _BUILDERS_CONDITION_VALUE_H
