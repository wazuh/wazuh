#include "opBuilderFileOutput.hpp"

#include <any>
#include <memory>
#include <stdexcept>
#include <string>

#include <fmt/format.h>
#include <logging/logging.hpp>

#include "baseTypes.hpp"
#include "expression.hpp"
#include "outputs/file.hpp"
#include <json/json.hpp>

namespace builder::internals::builders
{

base::Expression opBuilderFileOutput(const std::any& definition)
{
    json::Json jsonDefinition;

    // Get json and check is as expected
    try
    {
        jsonDefinition = std::any_cast<json::Json>(definition);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format(
            "Engine file output builder: Definition could not be converted to json: {}",
            e.what()));
    }
    const std::string fileOutputName {jsonDefinition.getString("/name").value_or("")};
    if (!jsonDefinition.isObject())
    {
        throw std::runtime_error(
            fmt::format("Engine file output builder: Output \"{}\" has an invalid json "
                        "definition type, expected [object] but got [{}].",
                        fileOutputName,
                        jsonDefinition.typeName()));
    }
    if (jsonDefinition.size() != 1)
    {
        throw std::runtime_error(
            fmt::format("Engine file output builder: Output \"{}\" has an invalid json "
                        "definition size: expected [1] but got [{}].",
                        fileOutputName,
                        jsonDefinition.size()));
    }

    auto outputObj = jsonDefinition.getObject().value();

    auto pathPos = std::find_if(outputObj.begin(), outputObj.end(), [](auto& tuple)
        {
            return std::get<0>(tuple) == "path";
        });
    if (outputObj.end() == pathPos)
    {
        throw std::runtime_error(fmt::format(
            "Engine file output builder: Output \"{}\" has no attribute \"path\".",
            fileOutputName));
    }
    if (!std::get<1>(*pathPos).isString())
    {
        throw std::runtime_error(
            fmt::format("Engine file output builder: Output \"{}\" has an invalid "
                        "attribute path, expected type [string] but got [{}].",
                        fileOutputName,
                        std::get<1>(*pathPos).typeName()));
    }

    auto path = std::get<1>(*pathPos).getString().value();

    auto filePtr = std::make_shared<outputs::FileOutput>(path);
    auto name = fmt::format("output.file[{}]", path);
    const auto successTrace = fmt::format("[{}] -> Success", name);
    const auto failureTrace = fmt::format("[{}] -> Failure: ", name);

    return base::Term<base::EngineOp>::create(
        name,
        [filePtr, successTrace, failureTrace](
            base::Event event) -> base::result::Result<base::Event>
        {
            try
            {
                filePtr->write(event);
                return base::result::makeSuccess(std::move(event), successTrace);
            }
            catch (const std::exception& e)
            {
                return base::result::makeFailure(std::move(event),
                                                 failureTrace + e.what());
            }
        });
}

} // namespace builder::internals::builders
