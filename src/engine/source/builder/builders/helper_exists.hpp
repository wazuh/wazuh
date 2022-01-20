#ifndef _BUILDERS_HELPER_EXISTS_H
#define _BUILDERS_HELPER_EXISTS_H

#include <rxcpp/rx.hpp>
#include <string>

#include "json.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds helper exists operation
 *
 * @param input_observable
 * @param input_json
 * @return rxcpp::observable<json::Document>
 */
rxcpp::observable<json::Document> helperExistsBuilder(const rxcpp::observable<json::Document> & input_observable,
                                                      const json::Value * input_json)
{
    std::string field = "/";
    field += input_json->MemberBegin()->name.GetString();

    auto output_observable = input_observable.filter([field](json::Document e) { return e.exists(field); });
    return output_observable;
}

/**
 * @brief Builds helper not exists operation
 *
 * @param input_observable
 * @param input_json
 * @return rxcpp::observable<json::Document>
 */
rxcpp::observable<json::Document> helperNotExistsBuilder(const rxcpp::observable<json::Document> & input_observable,
                                                         const json::Value * input_json)
{
    std::string field = "/";
    field += input_json->MemberBegin()->name.GetString();

    auto output_observable = input_observable.filter([field](json::Document e) { return !e.exists(field); });
    return output_observable;
}

} // namespace builder::internals::builders

#endif // _BUILDERS_HELPER_EXISTS_H
