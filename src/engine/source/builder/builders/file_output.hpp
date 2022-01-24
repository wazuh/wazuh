#ifndef _BUILDERS_FILE_OUTPUT_H
#define _BUILDERS_FILE_OUTPUT_H

#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <rxcpp/rx.hpp>
#include <stdexcept>
#include <string>

#include "connectable.hpp"
#include "json.hpp"
#include "outputs/file_output.hpp"

namespace builder::internals::builders
{
using namespace builder::internals::outputs;
/**
 * @brief Builds file output
 *
 * @param inputObs
 * @param inputJson
 * @return rxcpp::observable<json::Document>
 */
void fileOutputBuilder(const rxcpp::observable<json::Document> & inputObs, const json::Value * inputJson)
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
    std::string path = inputJson->GetObject().FindMember("path")->value.GetString();
    std::shared_ptr<outputs::FileOutput> filePtr = std::make_shared<outputs::FileOutput>(path);
    inputObs.subscribe([filePtr](json::Document e) { filePtr->write(e); }, []() {});
}

} // namespace builder::internals::builders

#endif // _BUILDERS_FILE_OUTPUT_H
