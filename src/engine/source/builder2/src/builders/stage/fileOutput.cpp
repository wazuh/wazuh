#include "fileOutput.hpp"

#include <memory>
#include <stdexcept>

#include "builders/utils.hpp"

namespace builder::builders
{

base::Expression fileOutputBuilder(const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    if (!definition.isObject())
    {
        throw std::runtime_error(fmt::format(
            "Stage '{}' expects an object but got '{}'", syntax::asset::FILE_OUTPUT_KEY, definition.typeName()));
    }

    if (definition.size() != 1)
    {
        throw std::runtime_error(fmt::format("Stage '{}' expects an object with one key but got '{}'",
                                             syntax::asset::FILE_OUTPUT_KEY,
                                             definition.size()));
    }

    auto outputObj = definition.getObject().value();

    const auto& [key, value] = *outputObj.begin();
    if (key != syntax::asset::FILE_OUTPUT_PATH_KEY)
    {
        throw std::runtime_error(fmt::format("Stage '{}' expects an object with key '{}' but got '{}'",
                                             syntax::asset::FILE_OUTPUT_KEY,
                                             syntax::asset::FILE_OUTPUT_PATH_KEY,
                                             key));
    }

    if (!value.isString())
    {
        throw std::runtime_error(fmt::format("Stage '{}' expects an object with key '{}' to be a string but got '{}'",
                                             syntax::asset::FILE_OUTPUT_KEY,
                                             syntax::asset::FILE_OUTPUT_PATH_KEY,
                                             value.typeName()));
    }

    auto path = value.getString().value();
    auto filePtr = std::make_shared<detail::FileOutput>(path);
    auto name = fmt::format("write.output({})", path);
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace = fmt::format("{} -> Could not write event to output", name);

    return base::Term<base::EngineOp>::create(name,
                                              [filePtr, successTrace, failureTrace, runState = buildCtx->runState()](
                                                  base::Event event) -> base::result::Result<base::Event>
                                              {
                                                  try
                                                  {
                                                      filePtr->write(event);
                                                      RETURN_SUCCESS(runState, event, successTrace);
                                                  }
                                                  catch (const std::exception& e)
                                                  {
                                                      RETURN_FAILURE(runState, event, failureTrace);
                                                  }
                                              });
}

} // namespace builder::builders
