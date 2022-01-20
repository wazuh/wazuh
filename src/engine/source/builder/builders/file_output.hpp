#ifndef _BUILDERS_FILE_OUTPUT_H
#define _BUILDERS_FILE_OUTPUT_H

#include <rxcpp/rx.hpp>
#include <stdexcept>
#include <string>

#include "connectable.hpp"
#include "json.hpp"

#include "outputs/file_output.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds file output
 *
 * @param inputObs
 * @param inputJson
 * @return rxcpp::observable<json::Document>
 */
outputs::FileOutput<json::Document> fileOutputBuilder(const json::Value * inputJson)
{
    if (!inputJson->IsObject())
    {
        throw std::invalid_argument("File output builder expects and object, but got " + inputJson->GetType());
    }

    if (inputJson->GetObject().MemberCount() != 1)
    {
        throw std::invalid_argument("File output builder expects and object with one entry, but got " +
                                    inputJson->GetObject().MemberCount());
    }

    if (!inputJson->GetObject().HasMember("path"))
    {
        throw std::invalid_argument("File output builder expects path attribute");
    }

    return outputs::FileOutput<json::Document>{inputJson->GetObject().FindMember("path")->value.GetString()};
}

} // namespace builder::internals::builders

#endif // _BUILDERS_FILE_OUTPUT_H
