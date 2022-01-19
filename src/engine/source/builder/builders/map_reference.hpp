#ifndef _BUILDERS_MAP_REFERENCE_H
#define _BUILDERS_MAP_REFERENCE_H

#include <rxcpp/rx.hpp>
#include <string>

#include "json.hpp"

namespace builder::internals::builders
{
/**
 * @brief Builds map reference operation
 *
 * @param input_observable
 * @param input_json
 * @return rxcpp::observable<json::Document>
 */
rxcpp::observable<json::Document> mapReferenceBuilder(const rxcpp::observable<json::Document> & input_observable,
                                                      const json::Value * input_json)
{
    auto valDoc = json::Document(*input_json);
    auto output_observable = input_observable.map(
        [valDoc](json::Document e)
        {
            e.setReference(valDoc);
            return e;
        });
    return output_observable;
}

} // namespace builder::internals::builders

#endif // _BUILDERS_MAP_REFERENCE_H
