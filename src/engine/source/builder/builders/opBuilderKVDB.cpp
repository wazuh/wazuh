#include "opBuilderKVDB.hpp"

#include <string>
#include <variant>

#include <fmt/format.h>

#include <json/json.hpp>
#include <utils/stringUtils.hpp>

#include "baseHelper.hpp"
#include "baseTypes.hpp"
#include "syntax.hpp"

#include <kvdb/iKVDBHandler.hpp>

namespace builder::internals::builders
{

using builder::internals::syntax::REFERENCE_ANCHOR;
using namespace helper::base;

base::Expression KVDBGet(const std::string& targetField,
                         const std::string& rawName,
                         const std::vector<std::string>& rawParameters,
                         std::shared_ptr<defs::IDefinitions> definitions,
                         bool merge,
                         std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope)
{
    // Identify references and build JSON pointer paths
    const auto parameters {processParameters(rawName, rawParameters, definitions)};

    // Assert expected number of parameters
    checkParametersSize(rawName, parameters, 2);
    checkParameterType(rawName, parameters[0], Parameter::Type::VALUE);

    // Format name for the tracer
    const auto name = formatHelperName(rawName, targetField, parameters);

    // Extract parameters
    const auto dbName = parameters[0].m_value;
    const auto key = parameters[1];

    // Trace messages
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace1 = fmt::format("[{}] -> Failure: reference '{}' not found", name, key.m_value);
    const std::string failureTrace2 =
        fmt::format("[{}] -> Failure: key '{}' could not be found on database '{}'", name, key.m_value, dbName);
    const std::string failureTrace3 = fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField);
    const std::string failureTrace4 = fmt::format("[{}] -> Failure: fields type mismatch when merging", name);
    const std::string failureTrace5 = fmt::format("[{}] -> Failure: malformed JSON for key '{}'", name, key.m_value);

    auto resultHandler = kvdbScope->getKVDBHandler(dbName);

    if (std::holds_alternative<base::Error>(resultHandler))
    {
        throw std::runtime_error(fmt::format("Engine KVDB builder: {}.", std::get<base::Error>(resultHandler).message));
    }

    // Return Expression
    return base::Term<base::EngineOp>::create(
        name,
        [=, 
        targetField = std::move(targetField),
        kvdbHandler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler))
        ]
        (base::Event event)
        {
            // Get DB key
            std::string resolvedKey;
            if (Parameter::Type::REFERENCE == key.m_type)
            {
                const auto value = event->getString(key.m_value);
                if (value)
                {
                    resolvedKey = value.value();
                }
                else
                {
                    return base::result::makeFailure(event, failureTrace1);
                }
            }
            else
            {
                resolvedKey = key.m_value;
            }

            auto resultValue = kvdbHandler->get(resolvedKey);

            if (std::holds_alternative<base::Error>(resultValue))
            {
                return base::result::makeFailure(event, failureTrace2);
            }
            try
            {
                json::Json value {std::get<std::string>(resultValue).c_str()};
                if (merge)
                {
                    // Failure cases on merge
                    if (!event->exists(targetField))
                    {
                        return base::result::makeFailure(event, failureTrace3);
                    }
                    else if (event->type(targetField) != value.type() || (!value.isObject() && !value.isArray()))
                    {
                        return base::result::makeFailure(event, failureTrace4);
                    }
                    event->merge(json::NOT_RECURSIVE, value, targetField);
                }
                else
                {
                    event->set(targetField, value);
                }
            }
            catch (const std::runtime_error& e)
            {
                return base::result::makeFailure(event, failureTrace5);
            }

            return base::result::makeSuccess(event, successTrace);
        });
}

// <field>: +kvdb_get/<DB>/<ref_key>
HelperBuilder getOpBuilderKVDBGet(std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope)
{
    return [kvdbScope](const std::string& targetField,
                                    const std::string& rawName,
                                    const std::vector<std::string>& rawParameters,
                                    std::shared_ptr<defs::IDefinitions> definitions)
    {
        return KVDBGet(targetField, rawName, rawParameters, definitions, false, kvdbScope);
    };
}

// <field>: +kvdb_get_merge/<DB>/<ref_key>
HelperBuilder getOpBuilderKVDBGetMerge(std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope)
{
    return [kvdbScope](const std::string& targetField,
                                    const std::string& rawName,
                                    const std::vector<std::string>& rawParameters,
                                    std::shared_ptr<defs::IDefinitions> definitions)
    {
        return KVDBGet(targetField, rawName, rawParameters, definitions, true, kvdbScope);
    };
}

// TODO: documentation and tests of this method are missing
base::Expression existanceCheck(const std::string& targetField,
                                const std::string& rawName,
                                const std::vector<std::string>& rawParameters,
                                std::shared_ptr<defs::IDefinitions> definitions,
                                bool checkExist,
                                std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope)
{

    const auto parameters = processParameters(rawName, rawParameters, definitions);
    checkParametersSize(rawName, parameters, 1);
    checkParameterType(rawName, parameters[0], Parameter::Type::VALUE);
    const auto name = formatHelperName(targetField, rawName, parameters);

    const auto dbName = parameters[0].m_value;
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace {
        fmt::format("[{}] -> Failure: Target field '{}' does not exist or it is not a string", name, targetField)};

    auto resultHandler = kvdbScope->getKVDBHandler(dbName);

    if (std::holds_alternative<base::Error>(resultHandler))
    {
        throw std::runtime_error(fmt::format("Engine KVDB builder: {}.", std::get<base::Error>(resultHandler).message));
    }

    return base::Term<base::EngineOp>::create(
        name,
        [=, 
        targetField = std::move(targetField),
        kvdbHandler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler))
        ]
        (base::Event event)
        {
            bool found = false;
            try // TODO We are only using try for JSON::get. Is correct to
                // wrap everything?
            {
                const auto value = event->getString(targetField);
                if (value.has_value())
                {
                    auto result = kvdbHandler->contains(value.value());
                    if (std::holds_alternative<base::Error>(result))
                    {
                        return base::result::makeFailure(event, failureTrace + ": " + std::get<base::Error>(result).message);
                    }
                    else
                    {
                        found = std::get<bool>(result);
                    }
                }
            }
            catch (std::exception& e)
            {
                return base::result::makeFailure(event, failureTrace + ": " + e.what());
            }

            // TODO: is this condition right? shouldn't this condition be: "!checkExist ||
            // (checkExist && found)" as if "checkExist" is "false" and "found" is "true"
            // then "truth" is false and the result is a
            bool truth = checkExist ? found : !found;
            if (truth)
            {
                return base::result::makeSuccess(event, successTrace);
            }
            else
            {
                return base::result::makeFailure(event, failureTrace);
            }
        });
}

// TODO: tests for this method are missing
// <field>: +kvdb_match/<DB>
HelperBuilder getOpBuilderKVDBMatch(std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope)
{
    return [kvdbScope](const std::string& targetField,
                         const std::string& rawName,
                         const std::vector<std::string>& rawParameters,
                         std::shared_ptr<defs::IDefinitions> definitions)
    {
        return existanceCheck(targetField, rawName, rawParameters, definitions, true, kvdbScope);
    };
}

// TODO: tests for this method are missing
// <field>: +kvdb_not_match/<DB>
HelperBuilder getOpBuilderKVDBNotMatch(std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope)
{
    return [kvdbScope](const std::string& targetField,
                         const std::string& rawName,
                         const std::vector<std::string>& rawParameters,
                         std::shared_ptr<defs::IDefinitions> definitions)
    {
        return existanceCheck(targetField, rawName, rawParameters, definitions, false, kvdbScope);
    };
}

base::Expression KVDBSet(const std::string& targetField,
                         const std::string& rawName,
                         const std::vector<std::string>& rawParameters,
                         std::shared_ptr<defs::IDefinitions> definitions,
                         std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope)
{

    const auto parameters = processParameters(rawName, rawParameters, definitions);

    checkParametersSize(rawName, parameters, 3);
    checkParameterType(rawName, parameters[0], Parameter::Type::VALUE);

    const auto name = formatHelperName(targetField, rawName, parameters);

    auto dbName = parameters[0].m_value;
    const auto key = parameters[1];
    const auto value = parameters[2];

    // Trace messages
    const std::string successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace {fmt::format("[{}] -> Failure: ", name)};
    const std::string failureTrace1 {fmt::format("[{}] -> Failure: reference '{}' not found", name, dbName)};
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: reference '{}' not found", name, key.m_value)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: reference '{}' not found", name, value.m_value)};
    const std::string failureTrace4 {fmt::format("[{}] -> ", name) + "Failure: Database '{}' could not be loaded: {}"};

    auto resultHandler = kvdbScope->getKVDBHandler(dbName);

    if (std::holds_alternative<base::Error>(resultHandler))
    {
        throw std::runtime_error(fmt::format("Engine KVDB builder: {}.", std::get<base::Error>(resultHandler).message));
    }

    // Return Expression
    return base::Term<base::EngineOp>::create(
        name,
        [=, 
        targetField = std::move(targetField),
        kvdbHandler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler))
        ]
        (base::Event event)
        {
            event->setBool(false, targetField);

            // Get key name
            std::string resolvedKey;
            if (Parameter::Type::REFERENCE == key.m_type)
            {
                const auto retval = event->getString(key.m_value);
                if (retval)
                {
                    resolvedKey = retval.value();
                }
                else
                {
                    return base::result::makeFailure(event, failureTrace2);
                }
            }
            else
            {
                resolvedKey = key.m_value;
            }

            // Get value
            std::string resolvedStrValue {value.m_value};
            json::Json resolvedJsonValue {};
            bool isValueRef {false};
            if (Parameter::Type::REFERENCE == value.m_type)
            {
                const auto refExists = event->exists(value.m_value);
                if (refExists)
                {
                    const auto retvalObject = event->getJson(value.m_value);

                    if (retvalObject)
                    {
                        resolvedJsonValue = retvalObject.value();
                        resolvedStrValue = resolvedJsonValue.str();
                        isValueRef = true;
                    }
                    else
                    {
                        // This should never happen, as the field existance was previously checked
                        return base::result::makeFailure(event, failureTrace3);
                    }
                }
                else
                {
                    return base::result::makeFailure(event, failureTrace3);
                }
            }

            std::variant<bool, base::Error> result;

            if (isValueRef)
            {
                result = kvdbHandler->set(resolvedKey, resolvedJsonValue);
            }
            else
            {
                result = kvdbHandler->set(resolvedKey, resolvedStrValue);
            }

            if (std::holds_alternative<base::Error>(result))
            {
                return base::result::makeFailure(
                    event,
                    failureTrace
                        + fmt::format("Failure: Key '{}' and value '{}' could not be written to database '{}': {}",
                                      resolvedKey,
                                      resolvedStrValue,
                                      dbName,
                                      std::get<base::Error>(result).message));
            }

            event->setBool(true, targetField);

            return base::result::makeSuccess(event, successTrace);
        });
}

// TODO: some tests for this method are missing
// <field>: +kvdb_set/<db>/<field>/<value>
HelperBuilder getOpBuilderKVDBSet(std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope)
{
    return [kvdbScope](const std::string& targetField,
                         const std::string& rawName,
                         const std::vector<std::string>& rawParameters,
                         std::shared_ptr<defs::IDefinitions> definitions)
    {
        return KVDBSet(targetField, rawName, rawParameters, definitions, kvdbScope);
    };
}

base::Expression KVDBDelete(const std::string& targetField,
                            const std::string& rawName,
                            const std::vector<std::string>& rawParameters,
                            std::shared_ptr<defs::IDefinitions> definitions,
                            std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope)
{

    const auto parameters = processParameters(rawName, rawParameters, definitions);
    checkParametersSize(rawName, parameters, 2);
    const auto name = formatHelperName(targetField, rawName, parameters);

    const auto dbName = parameters[0].m_value;
    const auto key = parameters[1];

    // Trace messages
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace1 = fmt::format("[{}] -> Failure: reference '{}' not found", name, key.m_value);
    const std::string failureTrace2 =
        fmt::format("[{}] -> Failure: key '{}' could not be found on database '{}'", name, key.m_value, dbName);
    const std::string failureTrace3 = fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField);
    const std::string failureTrace5 = fmt::format("[{}] -> Failure: malformed JSON for key '{}'", name, key.m_value);

    auto resultHandler = kvdbScope->getKVDBHandler(dbName);

    if (std::holds_alternative<base::Error>(resultHandler))
    {
        throw std::runtime_error(fmt::format("Engine KVDB builder: {}.", std::get<base::Error>(resultHandler).message));
    }

    // Return Expression
    return base::Term<base::EngineOp>::create(name,
            [=, 
            targetField = std::move(targetField),
            kvdbHandler = std::move(std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler))
            ]
            (base::Event event)
            {
                event->setBool(false, targetField);

                std::string resolvedKey;
                if (Parameter::Type::REFERENCE == key.m_type)
                {
                    const auto value = event->getString(key.m_value);
                    if (value)
                    {
                        resolvedKey = value.value();
                    }
                    else
                    {
                        return base::result::makeFailure(event, failureTrace1);
                    }
                }
                else
                {
                    resolvedKey = key.m_value;
                }

                auto resultValue = kvdbHandler->remove(resolvedKey);

                if (std::holds_alternative<base::Error>(resultValue))
                {
                    auto error = std::get<base::Error>(resultValue);
                    return base::result::makeFailure(event, failureTrace2);
                }

                event->setBool(true, targetField);

                return base::result::makeSuccess(event, successTrace);
            });
}

// TODO: some tests for this method are missing
// <field>: +kvdb_delete/<db>
HelperBuilder getOpBuilderKVDBDelete(std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope)
{
    return [kvdbScope](const std::string& targetField,
                         const std::string& rawName,
                         const std::vector<std::string>& rawParameters,
                         std::shared_ptr<defs::IDefinitions> definitions)
    {
        return KVDBDelete(targetField, rawName, rawParameters, definitions, kvdbScope);
    };
}

} // namespace builder::internals::builders
