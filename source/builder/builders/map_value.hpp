#ifndef _BUILDERS_MAP_VALUE_H
#define _BUILDERS_MAP_VALUE_H

#include <rxcpp/rx.hpp>
#include <string>

#include "json.hpp"

namespace builder::internals::builders
{
/**
 * @brief Builds map value operation
 *
 * @param input_observable
 * @param input_json
 * @return rxcpp::observable<json::Document>
 */
rxcpp::observable<json::Document> mapValueBuilder(const rxcpp::observable<json::Document> & input_observable,
                                                  const json::Value * input_json)
{
    auto valDoc = json::Document(*input_json);
    auto output_observable = input_observable.map(
        [valDoc](json::Document e)
        {
            e.set(valDoc);
            return e;
        });
    return output_observable;
}

} // namespace builder::internals::builders

#endif // _BUILDERS_MAP_VALUE_H
