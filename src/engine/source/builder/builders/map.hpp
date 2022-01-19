#ifndef _BUILDERS_MAP_H
#define _BUILDERS_MAP_H

#include <rxcpp/rx.hpp>
#include <stdexcept>
#include <string>

#include "json.hpp"
#include "syntax.hpp"

#include "builders/map_value.hpp"

namespace builder::internals::builders
{
/**
 * @brief Builds map operations
 *
 * @param input_observable
 * @param input_json
 * @return rxcpp::observable<json::Document>
 */
rxcpp::observable<json::Document> mapBuilder(const rxcpp::observable<json::Document> & input_observable,
                                             const json::Value * input_json)
{
    // Check that input is as expected and throw exception otherwise
    if (!input_json->IsObject())
    {
        throw std::invalid_argument("map build expects json with an object, but got " + input_json->GetType());
    }

    if (input_json->GetObject().MemberCount() != 1)
    {
        throw std::invalid_argument("map build expects json with only one key, but got" +
                                    input_json->GetObject().MemberCount());
    }

    const json::Value * value = &input_json->MemberBegin()->value;

    rxcpp::observable<json::Document> output_observable;

    // Deduce builder from value anchors, only if it is string
    if (value->IsString())
    {
        std::string str_value = value->GetString();
        // Reference
        if (str_value.compare(0, syntax::REFERENCE_ANCHOR.size(), syntax::REFERENCE_ANCHOR) == 0)
        {

            /* TODO */
        }
        // Helper
        else if (str_value.compare(0, syntax::HELPER_ANCHOR.size(), syntax::HELPER_ANCHOR) == 0)
        {
            /* TODO */
        }
        // Value (string)
        else
        {
            output_observable = mapValueBuilder(input_observable, input_json);
        }
    }
    // Array
    else if (value->IsArray())
    {
        /* TODO */
        // Value
    }
    // Object
    else if (value->IsObject())
    {
        /* TODO */
    }
    // Value
    else
    {
        output_observable = mapValueBuilder(input_observable, input_json);
    }

    return output_observable;
}

} // namespace builder::internals::builders

#endif // _BUILDERS_MAP_H
