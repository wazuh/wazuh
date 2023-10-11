#include "opBuilderKVDB.hpp"

#include <string>
#include <variant>

#include <fmt/format.h>

#include <json/json.hpp>
#include <kvdb/iKVDBHandler.hpp>
#include <utils/stringUtils.hpp>

#include "baseHelper.hpp"
#include "baseTypes.hpp"
#include "syntax.hpp"

namespace builder::internals::builders
{

using builder::internals::syntax::REFERENCE_ANCHOR;
using namespace helper::base;
using namespace kvdbManager;

base::Expression KVDBGet(std::shared_ptr<IKVDBManager> kvdbManager,
                         const std::string& kvdbScopeName,
                         const std::string& targetField,
                         const std::string& rawName,
                         const std::vector<std::string>& rawParameters,
                         std::shared_ptr<defs::IDefinitions> definitions,
                         const bool doMerge)
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
    const auto& key = parameters[1];

    // Trace messages
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace1 = fmt::format("[{}] -> Failure: reference '{}' not found", name, key.m_value);
    const std::string failureTrace2 =
        fmt::format("[{}] -> Failure: key '{}' could not be found on database '{}'", name, key.m_value, dbName);
    const std::string failureTrace3 = fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField);
    const std::string failureTrace4 = fmt::format("[{}] -> Failure: fields type mismatch when merging", name);
    const std::string failureTrace5 = fmt::format("[{}] -> Failure: malformed JSON for key '{}'", name, key.m_value);

    auto resultHandler = kvdbManager->getKVDBHandler(dbName, kvdbScopeName);

    if (std::holds_alternative<base::Error>(resultHandler))
    {
        throw std::runtime_error(fmt::format("Engine KVDB builder: {}.", std::get<base::Error>(resultHandler).message));
    }

    // Return Expression
    return base::Term<base::EngineOp>::create(
        name,
        [=,
         targetField = targetField,
         kvdbHandler = std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler)](base::Event event)
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
                if (doMerge)
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
HelperBuilder getOpBuilderKVDBGet(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const std::string& targetField,
                                        const std::string& rawName,
                                        const std::vector<std::string>& rawParameters,
                                        std::shared_ptr<defs::IDefinitions> definitions)
    {
        return KVDBGet(kvdbManager, kvdbScopeName, targetField, rawName, rawParameters, definitions, false);
    };
}

// <field>: +kvdb_get_merge/<DB>/<ref_key>
HelperBuilder getOpBuilderKVDBGetMerge(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const std::string& targetField,
                                        const std::string& rawName,
                                        const std::vector<std::string>& rawParameters,
                                        std::shared_ptr<defs::IDefinitions> definitions)
    {
        return KVDBGet(kvdbManager, kvdbScopeName, targetField, rawName, rawParameters, definitions, true);
    };
}

// TODO: documentation and tests of this method are missing
base::Expression existanceCheck(std::shared_ptr<IKVDBManager> kvdbManager,
                                const std::string& kvdbScopeName,
                                const std::string& targetField,
                                const std::string& rawName,
                                const std::vector<std::string>& rawParameters,
                                std::shared_ptr<defs::IDefinitions> definitions,
                                const bool shouldMatch)
{

    const auto parameters = processParameters(rawName, rawParameters, definitions);
    checkParametersSize(rawName, parameters, 1);
    checkParameterType(rawName, parameters[0], Parameter::Type::VALUE);
    const auto name = formatHelperName(targetField, rawName, parameters);

    const auto dbName = parameters[0].m_value;
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace {
        fmt::format("[{}] -> Failure: Target field '{}' does not exist or it is not a string", name, targetField)};

    auto resultHandler = kvdbManager->getKVDBHandler(dbName, kvdbScopeName);

    if (std::holds_alternative<base::Error>(resultHandler))
    {
        throw std::runtime_error(fmt::format("Engine KVDB builder: {}.", std::get<base::Error>(resultHandler).message));
    }

    return base::Term<base::EngineOp>::create(
        name,
        [=,
         targetField = targetField,
         kvdbHandler = std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler)](base::Event event)
        {
            bool found = false;
            std::optional<std::string> value;

            try
            {
                value = event->getString(targetField);
            }
            catch (std::exception& e)
            {
                return base::result::makeFailure(event, failureTrace + ": " + e.what());
            }

            if (value.has_value())
            {
                auto result = kvdbHandler->contains(value.value());
                if (std::holds_alternative<base::Error>(result))
                {
                    return base::result::makeFailure(event,
                                                     failureTrace + ": " + std::get<base::Error>(result).message);
                }

                found = std::get<bool>(result);
            }

            if ((shouldMatch && found) || (!shouldMatch && !found))
            {
                return base::result::makeSuccess(event, successTrace);
            }

            return base::result::makeFailure(event, failureTrace);
        });
}

// TODO: tests for this method are missing
// <field>: +kvdb_match/<DB>
HelperBuilder getOpBuilderKVDBMatch(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const std::string& targetField,
                                        const std::string& rawName,
                                        const std::vector<std::string>& rawParameters,
                                        std::shared_ptr<defs::IDefinitions> definitions)
    {
        return existanceCheck(kvdbManager, kvdbScopeName, targetField, rawName, rawParameters, definitions, true);
    };
}

// TODO: tests for this method are missing
// <field>: +kvdb_not_match/<DB>
HelperBuilder getOpBuilderKVDBNotMatch(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const std::string& targetField,
                                        const std::string& rawName,
                                        const std::vector<std::string>& rawParameters,
                                        std::shared_ptr<defs::IDefinitions> definitions)
    {
        return existanceCheck(kvdbManager, kvdbScopeName, targetField, rawName, rawParameters, definitions, false);
    };
}

base::Expression KVDBSet(std::shared_ptr<IKVDBManager> kvdbManager,
                         const std::string& kvdbScopeName,
                         const std::string& targetField,
                         const std::string& rawName,
                         const std::vector<std::string>& rawParameters,
                         std::shared_ptr<defs::IDefinitions> definitions)
{

    const auto parameters = processParameters(rawName, rawParameters, definitions);

    checkParametersSize(rawName, parameters, 3);
    checkParameterType(rawName, parameters[0], Parameter::Type::VALUE);

    const auto name = formatHelperName(targetField, rawName, parameters);

    auto dbName = parameters[0].m_value;
    const auto& key = parameters[1];
    const auto& value = parameters[2];

    // Trace messages
    const std::string successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace {fmt::format("[{}] -> Failure: ", name)};
    const std::string failureTrace1 {fmt::format("[{}] -> Failure: reference '{}' not found", name, dbName)};
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: reference '{}' not found", name, key.m_value)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: reference '{}' not found", name, value.m_value)};
    const std::string failureTrace4 {fmt::format("[{}] -> ", name) + "Failure: Database '{}' could not be loaded: {}"};

    auto resultHandler = kvdbManager->getKVDBHandler(dbName, kvdbScopeName);

    if (std::holds_alternative<base::Error>(resultHandler))
    {
        throw std::runtime_error(fmt::format("Engine KVDB builder: {}.", std::get<base::Error>(resultHandler).message));
    }

    // Return Expression
    return base::Term<base::EngineOp>::create(
        name,
        [=,
         targetField = targetField,
         kvdbHandler = std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler)](base::Event event)
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
                    auto retvalObject = event->getJson(value.m_value);

                    if (retvalObject)
                    {
                        resolvedJsonValue = std::move(retvalObject.value());
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

            std::optional<base::Error> kvdbSetError;

            kvdbSetError = isValueRef ? kvdbHandler->set(resolvedKey, resolvedJsonValue)
                                      : kvdbHandler->set(resolvedKey, resolvedStrValue);

            if (kvdbSetError)
            {
                return base::result::makeFailure(
                    event,
                    failureTrace
                        + fmt::format("Failure: Key '{}' and value '{}' could not be written to database '{}': {}",
                                      resolvedKey,
                                      resolvedStrValue,
                                      dbName,
                                      kvdbSetError.value().message));
            }

            event->setBool(true, targetField);

            return base::result::makeSuccess(event, successTrace);
        });
}

// TODO: some tests for this method are missing
// <field>: +kvdb_set/<db>/<field>/<value>
HelperBuilder getOpBuilderKVDBSet(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const std::string& targetField,
                                        const std::string& rawName,
                                        const std::vector<std::string>& rawParameters,
                                        std::shared_ptr<defs::IDefinitions> definitions)
    {
        return KVDBSet(kvdbManager, kvdbScopeName, targetField, rawName, rawParameters, definitions);
    };
}

base::Expression KVDBDelete(std::shared_ptr<IKVDBManager> kvdbManager,
                            const std::string& kvdbScopeName,
                            const std::string& targetField,
                            const std::string& rawName,
                            const std::vector<std::string>& rawParameters,
                            std::shared_ptr<defs::IDefinitions> definitions)
{

    const auto parameters = processParameters(rawName, rawParameters, definitions);
    checkParametersSize(rawName, parameters, 2);
    const auto name = formatHelperName(targetField, rawName, parameters);

    const auto& dbName = parameters[0].m_value;
    const auto& key = parameters[1];

    // Trace messages
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace1 = fmt::format("[{}] -> Failure: reference '{}' not found", name, key.m_value);
    const std::string failureTrace2 =
        fmt::format("[{}] -> Failure: key '{}' could not be found on database '{}'", name, key.m_value, dbName);

    auto resultHandler = kvdbManager->getKVDBHandler(dbName, kvdbScopeName);

    if (std::holds_alternative<base::Error>(resultHandler))
    {
        throw std::runtime_error(
            fmt::format("Database is not available for usage: {}.", std::get<base::Error>(resultHandler).message));
    }

    // Return Expression
    return base::Term<base::EngineOp>::create(
        name,
        [=,
         targetField = targetField,
         kvdbHandler = std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler)](base::Event event)
        {
            std::string resolvedKey;
            if (Parameter::Type::REFERENCE == key.m_type)
            {
                const auto value = event->getString(key.m_value);
                if (value.has_value())
                {
                    resolvedKey = value.value();
                }
                else
                {
                    event->setBool(false, targetField);
                    return base::result::makeFailure(event, failureTrace1);
                }
            }
            else
            {
                resolvedKey = key.m_value;
            }

            const auto resultValue = kvdbHandler->remove(resolvedKey);

            if (resultValue)
            {
                event->setBool(false, targetField);
                return base::result::makeFailure(event, failureTrace2);
            }

            event->setBool(true, targetField);

            return base::result::makeSuccess(event, successTrace);
        });
}

// TODO: some tests for this method are missing
// <field>: +kvdb_delete/<db>
HelperBuilder getOpBuilderKVDBDelete(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const std::string& targetField,
                                        const std::string& rawName,
                                        const std::vector<std::string>& rawParameters,
                                        std::shared_ptr<defs::IDefinitions> definitions)
    {
        return KVDBDelete(kvdbManager, kvdbScopeName, targetField, rawName, rawParameters, definitions);
    };
}

// <field>: kvdb_get_array(<db>, <key_array>)
HelperBuilder getOpBuilderKVDBGetArray(std::shared_ptr<IKVDBManager> kvdbManager,
                                       const std::string& kvdbScopeName,
                                       std::shared_ptr<schemf::ISchema> schema)
{
    return [kvdbManager, kvdbScopeName, schema](const std::string& targetField,
                                                const std::string& rawName,
                                                const std::vector<std::string>& rawParameters,
                                                std::shared_ptr<defs::IDefinitions> definitions)
    {
        auto parameters = processParameters(rawName, rawParameters, definitions);
        checkParametersSize(rawName, parameters, 2);
        const auto name = formatHelperName(targetField, rawName, parameters);

        const auto& dbName = parameters[0].m_value;

        if (Parameter::Type::VALUE != parameters[0].m_type)
        {
            throw std::runtime_error(fmt::format("Engine KVDB builder: {}.", "DB Name must be a value"));
        }

        if (Parameter::Type::REFERENCE != parameters[1].m_type)
        {
            throw std::runtime_error(fmt::format("Engine KVDB builder: {}.", "Key array must be a reference"));
        }

        auto arrayRef = parameters[1].m_value;

        // Check target field is an array
        if (schema->hasField(targetField) && schema->getType(targetField) != json::Json::Type::Array)
        {
            throw std::runtime_error(fmt::format("Engine KVDB builder: {}.", "Target field must be an array"));
        }

        // Check array reference is an array
        if (schema->hasField(arrayRef) && schema->getType(arrayRef) != json::Json::Type::Array)
        {
            throw std::runtime_error(fmt::format("Engine KVDB builder: {}.", "Array reference must be an array"));
        }

        // Get KVDB handler
        auto resultHandler = kvdbManager->getKVDBHandler(dbName, kvdbScopeName);
        if (std::holds_alternative<base::Error>(resultHandler))
        {
            throw std::runtime_error(
                fmt::format("Engine KVDB builder: {}.", std::get<base::Error>(resultHandler).message));
        }

        // Trace messages
        auto referenceNotFound = fmt::format("Reference '{}' not found or not array", arrayRef);
        auto emptyArray = fmt::format("Empty array in reference '{}'", arrayRef);
        auto notKeyStr = fmt::format("Found non-string key in reference '{}'", arrayRef);
        auto heterogeneousTypes = fmt::format("Heterogeneous types when obtaining values from database '{}'", dbName);
        auto malformedJson = fmt::format("Malformed JSON found in database '{}'", dbName);
        auto keyNotMatched = fmt::format("Key not found in DB '{}'", dbName);

        auto successTrace = fmt::format("[{}] -> Success", name);

        // Return Expression
        return base::Term<base::EngineOp>::create(
            name,
            [=, kvdbHandler = std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler)](
                const base::Event& event)
            {
                // Resolve array of keys reference
                auto keys = event->getArray(arrayRef);
                if (!keys)
                {
                    return base::result::makeFailure(event, referenceNotFound);
                }
                if (keys.value().empty())
                {
                    return base::result::makeFailure(event, emptyArray);
                }

                // Get values from KVDB
                bool first = true;
                json::Json::Type type;
                std::vector<json::Json> values;
                for (auto& jKey : keys.value())
                {
                    if (!jKey.isString())
                    {
                        return base::result::makeFailure(event, notKeyStr);
                    }

                    auto resultValue = kvdbHandler->get(jKey.getString().value());
                    if (!base::isError(resultValue))
                    {
                        json::Json jValue;
                        try
                        {
                            jValue = json::Json {std::get<std::string>(resultValue).c_str()};
                        }
                        catch (...)
                        {
                            return base::result::makeFailure(event, malformedJson);
                        }

                        if (first)
                        {
                            type = jValue.type();
                            first = false;
                        }

                        if (jValue.type() != type)
                        {
                            return base::result::makeFailure(event, heterogeneousTypes);
                        }

                        values.emplace_back(std::move(jValue));
                    }
                    else
                    {
                        return base::result::makeFailure(event, keyNotMatched);
                    }
                }

                // Append values to target field
                for (auto& value : values)
                {
                    event->appendJson(value, targetField);
                }

                return base::result::makeSuccess(event, successTrace);
            });
    };
}

namespace
{
// TODO Change this to use an vector instead of a map
std::function<std::optional<json::Json>(uint64_t pos)> getFnSearchMap(const json::Json& jMap)
{
    const std::string throwTrace {"Engine KBDB Decode bit mask: "};

    std::vector<std::optional<json::Json>> buildedMap(std::numeric_limits<uint64_t>::digits);
    // Fill the map with empty values
    std::fill(buildedMap.begin(), buildedMap.end(), std::nullopt);
    {
        if (!jMap.isObject())
        {
            throw std::runtime_error(throwTrace + "Expected object as map.");
        }

        auto jMapObj = jMap.getObject().value();
        json::Json::Type mapValueType {};
        bool isTypeSet = false;

        if (jMapObj.empty())
        {
            throw std::runtime_error(throwTrace + "Malformed map (Empty map provided)");
        }

        for (auto& [key, value] : jMapObj)
        {
            uint64_t index = 0;
            // Validate key
            if (key.empty())
            {
                throw std::runtime_error(throwTrace + "Malformed map (Empty key on map provided)");
            }
            if (key[0] == '-')
            {
                throw std::runtime_error(throwTrace + "Malformed map (Negative number as key on map provided)");
            }

            try
            {
                index = std::stoul(key);
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(throwTrace + "Malformed map (Expected number as key on map provided)");
            }
            if (index >= std::numeric_limits<uint64_t>::digits)
            {
                throw std::runtime_error(fmt::format(throwTrace + "Malformed map (Key out of range {}-{}: {})",
                                                     0,
                                                     std::numeric_limits<uint64_t>::digits,
                                                     index));
            }

            // Validate value
            if (!isTypeSet)
            {
                mapValueType = value.type();
                isTypeSet = true;
            }
            else if (mapValueType != value.type())
            {
                throw std::runtime_error(throwTrace + "Malformed map (Heterogeneous types on map)");
            }

            buildedMap[index] = std::move(value);
        }
    }

    // Function that get the value from the builded map, returns nullopt if not found
    return [buildedMap](const uint64_t pos) -> std::optional<json::Json>
    {
        if (pos < buildedMap.size())
        {
            return buildedMap[pos];
        }
        return std::nullopt;
    };
}
} // namespace

base::Expression OpBuilderHelperKVDBDecodeBitmask(const std::string& targetField,
                                                  const std::string& rawName,
                                                  const std::vector<std::string>& rawParameters,
                                                  std::shared_ptr<defs::IDefinitions> definitions,
                                                  std::shared_ptr<IKVDBManager> kvdbManager,
                                                  const std::string& kvdbScopeName,
                                                  std::shared_ptr<schemf::ISchema> schema)
{
    // Identify references and build JSON pointer paths
    const auto parameters = helper::base::processParameters(rawName, rawParameters, definitions, false);
    const auto name = helper::base::formatHelperName(rawName, targetField, parameters);

    // Tracing
    const std::string throwTrace {"Engine KBDB Decode bit mask: "};
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace1 {fmt::format("[{}] -> Failure: Expected hexa number as mask", name)};
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: Reference to mask not found", name)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: value of mask out of range", name)};
    const std::string failureTrace4 {fmt::format("[{}] -> Failure: no value found for the mask", name)};

    // Verify parameters size and types
    helper::base::checkParametersSize(rawName, parameters, 3);
    helper::base::checkParameterType(rawName, parameters[0], helper::base::Parameter::Type::VALUE);
    helper::base::checkParameterType(rawName, parameters[1], helper::base::Parameter::Type::VALUE);
    helper::base::checkParameterType(rawName, parameters[2], helper::base::Parameter::Type::REFERENCE);

    // Extract parameters
    const auto& dbName = parameters[0].m_value;
    const auto& keyMap = parameters[1].m_value;
    const auto& maskRef = parameters[2].m_value;

    // Verify the schema fields
    if (schema->hasField(targetField) && schema->getType(targetField) != json::Json::Type::Array)
    {
        throw std::runtime_error(throwTrace + "failed schema validation: Target field must be an array.");
    }
    if (schema->hasField(maskRef) && schema->getType(maskRef) != json::Json::Type::String)
    {
        throw std::runtime_error(throwTrace + "failed schema validation: Mask reference must be a string.");
    }

    // Get the json map from KVDB
    json::Json jMap {};
    {
        auto resultHandler = kvdbManager->getKVDBHandler(dbName, kvdbScopeName);
        if (std::holds_alternative<base::Error>(resultHandler))
        {
            throw std::runtime_error(fmt::format(throwTrace + "{}.", std::get<base::Error>(resultHandler).message));
        }
        auto kvdbHandler = std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler);

        auto resultValue = kvdbHandler->get(keyMap);
        if (std::holds_alternative<base::Error>(resultValue))
        {
            throw std::runtime_error(fmt::format(throwTrace + "{}.", std::get<base::Error>(resultValue).message));
        }
        try
        {
            jMap = json::Json {std::get<std::string>(resultValue).c_str()};
        }
        catch (...)
        {
            throw std::runtime_error(throwTrace + "Malformed JSON found in database.");
        }
    }

    // Get the function to search in the map
    auto getValueFn = getFnSearchMap(jMap);

    // Get the function to get the value from the event
    auto getMaskFn = [maskRef, failureTrace1, failureTrace2, failureTrace3](
                         const base::Event& event) -> std::variant<uint64_t, std::string>
    {
        // If is a string, get the mask as hexa in range 0-0xFFFFFFFFFFFFFFFF
        const auto maskStr = event->getString(maskRef);
        if (maskStr.has_value())
        {
            try
            {
                auto rMask = std::stoul(maskStr.value(), nullptr, 16);
                if (rMask <= std::numeric_limits<uint64_t>::max())
                {
                    return static_cast<uint64_t>(rMask);
                }
                return failureTrace3;
            }
            catch (const std::exception&)
            {
                return failureTrace1;
            }
        }
        return failureTrace2;
    };

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [targetField, getValueFn, getMaskFn, successTrace, failureTrace4](
            const base::Event& event) -> base::result::Result<base::Event>
        {
            // Get mask in hexa
            uint64_t mask {};
            {
                auto resultMask = getMaskFn(event);
                if (std::holds_alternative<std::string>(resultMask))
                {
                    return base::result::makeFailure(event, std::move(std::get<std::string>(resultMask)));
                }
                mask = std::get<uint64_t>(resultMask);
            }

            // iterate over the bits of the mask
            bool isResultEmpty {true};
            for (uint64_t bitPos = 0; bitPos < std::numeric_limits<uint64_t>::digits; bitPos++)
            {
                auto flag = 0x1 << bitPos;
                if (flag & mask)
                {
                    auto value = getValueFn(bitPos);

                    if (value.has_value())
                    {
                        isResultEmpty = false;
                        event->appendJson(*value, targetField);
                    }
                }
            }
            if (isResultEmpty)
            {
                return base::result::makeFailure(event, failureTrace4);
            }

            return base::result::makeSuccess(event, successTrace);
        });
}

HelperBuilder getOpBuilderHelperKVDBDecodeBitmask(std::shared_ptr<IKVDBManager> kvdbManager,
                                                  const std::string& kvdbScopeName,
                                                  std::shared_ptr<schemf::ISchema> schema)
{
    return [kvdbManager, kvdbScopeName, schema](const std::string& targetField,
                                                const std::string& rawName,
                                                const std::vector<std::string>& rawParameters,
                                                std::shared_ptr<defs::IDefinitions> definitions)
    {
        return OpBuilderHelperKVDBDecodeBitmask(
            targetField, rawName, rawParameters, definitions, kvdbManager, kvdbScopeName, schema);
    };
}

} // namespace builder::internals::builders
