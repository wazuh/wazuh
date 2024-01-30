#include "builders/opmap/kvdb.hpp"

#include <string>
#include <variant>

#include <fmt/format.h>

#include <json/json.hpp>
#include <kvdb/ikvdbhandler.hpp>
#include <utils/stringUtils.hpp>

#include "syntax.hpp"

namespace builder::builders
{
using namespace kvdbManager;

TransformOp KVDBGet(std::shared_ptr<IKVDBManager> kvdbManager,
                    const std::string& kvdbScopeName,
                    const Reference& targetField,
                    const std::vector<OpArg>& opArgs,
                    const std::shared_ptr<const IBuildCtx>& buildCtx,
                    const bool doMerge)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 2);
    // First argument is kvdb name
    utils::assertValue(opArgs, 0);
    if (!std::static_pointer_cast<Value>(opArgs[0])->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected db name 'string' as first argument but got '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().str()));
    }
    auto dbName = std::static_pointer_cast<const Value>(opArgs[0])->value().getString().value();

    // Second argument is key
    auto key = opArgs[1];
    if (key->isValue())
    {
        if (!std::static_pointer_cast<Value>(key)->value().isString())
        {
            throw std::runtime_error(fmt::format("Expected key 'string' as second argument but got '{}'",
                                                 std::static_pointer_cast<Value>(key)->value().str()));
        }
    }
    else
    {
        const auto& ref = *std::static_pointer_cast<const Reference>(key);
        if (buildCtx->schema().hasField(ref.dotPath()))
        {
            auto jType = buildCtx->validator().getJsonType(buildCtx->schema().getType(ref.dotPath()));
            if (jType != json::Json::Type::String)
            {
                throw std::runtime_error(fmt::format("Expected reference field of 'string' type but got '{}'",
                                                     json::Json::typeToStr(jType)));
            }
        }
    }

    // Get KVDB handler
    auto resultHandler = kvdbManager->getKVDBHandler(dbName, kvdbScopeName);

    if (std::holds_alternative<base::Error>(resultHandler))
    {
        throw std::runtime_error(fmt::format("Engine KVDB builder: {}.", std::get<base::Error>(resultHandler).message));
    }

    // Format name for the tracer
    const auto name = buildCtx->context().opName;

    // Trace messages
    const auto successTrace {fmt::format("{} -> Success", name)};

    const auto failureTrace1 = fmt::format("{} -> Target field '{}' not found", name, targetField.dotPath());
    const auto failureTrace2 = [=]()
    {
        if (key->isReference())
        {
            return fmt::format(
                "{} -> Reference for key '{}' not found", name, std::static_pointer_cast<Reference>(key)->dotPath());
        }

        return std::string("");
    }();
    const auto failureTrace3 = [=]()
    {
        if (key->isReference())
        {
            return fmt::format("{} -> Reference for key '{}' is not a string",
                               name,
                               std::static_pointer_cast<Reference>(key)->dotPath());
        }

        return std::string("");
    }();
    const auto failureTrace4 = fmt::format("{} -> Key not found in DB", name);
    const auto failureTrace5 = fmt::format("{} -> Type mismatch between target field and value when merging", name);
    const auto failureTrace6 = fmt::format("{} -> Malformed JSON for value in DB", name);

    // Return Op
    return [=,
            runState = buildCtx->runState(),
            targetField = targetField.jsonPath(),
            kvdbHandler = std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler)](
               base::Event event) -> TransformResult
    {
        // Get DB key
        std::string resolvedKey;
        if (key->isReference())
        {
            const auto& keyRef = *std::static_pointer_cast<Reference>(key);
            if (!event->exists(keyRef.jsonPath()))
            {
                RETURN_FAILURE(runState, event, failureTrace2)
            }

            const auto value = event->getString(keyRef.jsonPath());
            if (!value)
            {
                RETURN_FAILURE(runState, event, failureTrace3)
            }

            resolvedKey = value.value();
        }
        else
        {
            resolvedKey = std::static_pointer_cast<const Value>(key)->value().getString().value();
        }

        // Get value from KVDB
        auto resultValue = kvdbHandler->get(resolvedKey);

        if (base::isError(resultValue))
        {
            RETURN_FAILURE(runState, event, failureTrace4)
        }

        try
        {
            json::Json value {base::getResponse<std::string>(resultValue).c_str()};
            if (doMerge)
            {
                if (!event->exists(targetField))
                {
                    RETURN_FAILURE(runState, event, failureTrace1)
                }

                if (event->type(targetField) != value.type() || (!value.isObject() && !value.isArray()))
                {
                    RETURN_FAILURE(runState, event, failureTrace5)
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
            RETURN_FAILURE(runState, event, failureTrace6)
        }

        RETURN_SUCCESS(runState, event, successTrace)
    };
}

// <field>: +kvdb_get/<DB>/<ref_key>
TransformBuilder getOpBuilderKVDBGet(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const Reference& targetField,
                                        const std::vector<OpArg>& opArgs,
                                        const std::shared_ptr<const IBuildCtx>& buildCtx)
    {
        return KVDBGet(kvdbManager, kvdbScopeName, targetField, opArgs, buildCtx, false);
    };
}

// <field>: +kvdb_get_merge/<DB>/<ref_key>
TransformBuilder getOpBuilderKVDBGetMerge(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const Reference& targetField,
                                        const std::vector<OpArg>& opArgs,
                                        const std::shared_ptr<const IBuildCtx>& buildCtx)
    {
        return KVDBGet(kvdbManager, kvdbScopeName, targetField, opArgs, buildCtx, true);
    };
}

FilterOp existanceCheck(std::shared_ptr<IKVDBManager> kvdbManager,
                        const std::string& kvdbScopeName,
                        const Reference& targetField,
                        const std::vector<OpArg>& opArgs,
                        const std::shared_ptr<const IBuildCtx>& buildCtx,
                        const bool shouldMatch)
{
    if (!kvdbManager)
    {
        throw std::runtime_error("Got null KVDB manager");
    }

    // Assert expected number of parameters
    utils::assertSize(opArgs, 1);

    // First argument is kvdb name
    utils::assertValue(opArgs, 0);
    if (!std::static_pointer_cast<Value>(opArgs[0])->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected db name 'string' as first argument but got '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().str()));
    }

    auto dbName = std::static_pointer_cast<const Value>(opArgs[0])->value().getString().value();
    auto resultHandler = kvdbManager->getKVDBHandler(dbName, kvdbScopeName);
    if (base::isError(resultHandler))
    {
        throw std::runtime_error(fmt::format("Error getting KVDB handler: {}", base::getError(resultHandler).message));
    }

    // Trace messages
    const auto name = buildCtx->context().opName;
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace1 = fmt::format("{} -> Target field '{}' not found", name, targetField.dotPath());
    const auto failureTrace2 = fmt::format("{} -> Target field '{}' is not a string", name, targetField.dotPath());
    const auto failureTrace3 = fmt::format("{} -> Error quering db: ", name);
    const auto failureTraceMatch = fmt::format("{} -> Key not found in DB", name);
    const auto failureTraceNotMatch = fmt::format("{} -> Key found in DB", name);

    return [=,
            runState = buildCtx->runState(),
            targetField = targetField.jsonPath(),
            kvdbHandler = std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler)](
               base::ConstEvent event) -> FilterResult
    {
        if (!event->exists(targetField))
        {
            RETURN_FAILURE(runState, false, failureTrace1)
        }

        auto key = event->getString(targetField);
        if (!key.has_value())
        {
            RETURN_FAILURE(runState, false, failureTrace2)
        }

        auto value = kvdbHandler->contains(key.value());
        if (base::isError(value))
        {
            RETURN_FAILURE(runState, false, failureTrace3 + std::get<base::Error>(value).message)
        }

        auto found = base::getResponse<bool>(value);
        if (shouldMatch)
        {
            if (!found)
            {
                RETURN_FAILURE(runState, false, failureTraceMatch)
            }
        }
        else
        {
            if (found)
            {
                RETURN_FAILURE(runState, false, failureTraceNotMatch)
            }
        }

        RETURN_SUCCESS(runState, true, successTrace)
    };
}

// <field>: +kvdb_match/<DB>
FilterBuilder getOpBuilderKVDBMatch(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const Reference& targetField,
                                        const std::vector<OpArg>& opArgs,
                                        const std::shared_ptr<const IBuildCtx>& buildCtx)
    {
        return existanceCheck(kvdbManager, kvdbScopeName, targetField, opArgs, buildCtx, true);
    };
}

// <field>: +kvdb_not_match/<DB>
FilterBuilder getOpBuilderKVDBNotMatch(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const Reference& targetField,
                                        const std::vector<OpArg>& opArgs,
                                        const std::shared_ptr<const IBuildCtx>& buildCtx)
    {
        return existanceCheck(kvdbManager, kvdbScopeName, targetField, opArgs, buildCtx, false);
    };
}

TransformOp KVDBSet(std::shared_ptr<IKVDBManager> kvdbManager,
                    const std::string& kvdbScopeName,
                    const Reference& targetField,

                    const std::vector<OpArg>& opArgs,
                    const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 3);

    // First argument is kvdb name
    utils::assertValue(opArgs, 0);
    if (!std::static_pointer_cast<Value>(opArgs[0])->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected db name 'string' as first argument but got '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().str()));
    }

    auto dbName = std::static_pointer_cast<const Value>(opArgs[0])->value().getString().value();
    auto key = opArgs[1];
    auto value = opArgs[2];

    if (key->isValue() && !std::static_pointer_cast<Value>(key)->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected key 'string' as second argument but got '{}'",
                                             std::static_pointer_cast<Value>(key)->value().str()));
    }
    if (value->isValue() && !std::static_pointer_cast<Value>(value)->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected value 'string' as third argument but got '{}'",
                                             std::static_pointer_cast<Value>(value)->value().str()));
    }

    const auto name = buildCtx->context().opName;

    // Trace messages
    const std::string successTrace {fmt::format("{} -> Success", name)};

    const std::string failureTrace {fmt::format("{} -> Failure: ", name)};
    const std::string failureTrace2 {fmt::format("{} -> Failure: key field reference not found", name)};
    const std::string failureTrace3 {fmt::format("{} -> Failure: value field reference not found", name)};
    const std::string failureTrace4 {fmt::format("{} -> ", name) + "Failure: Database '{}' could not be loaded: {}"};

    auto resultHandler = kvdbManager->getKVDBHandler(dbName, kvdbScopeName);

    if (std::holds_alternative<base::Error>(resultHandler))
    {
        throw std::runtime_error(fmt::format("Engine KVDB builder: {}.", std::get<base::Error>(resultHandler).message));
    }

    // Return Op
    return [=,
            targetField = targetField.jsonPath(),
            kvdbHandler = std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler)](
               base::Event event) -> TransformResult
    {
        event->setBool(false, targetField);

        // Get key name
        std::string resolvedKey;
        if (key->isReference())
        {
            const auto keyRef = std::static_pointer_cast<const Reference>(key)->jsonPath();
            const auto retval = event->getString(keyRef);
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
            resolvedKey = std::static_pointer_cast<const Value>(key)->value().getString().value();
        }

        // Get value
        std::string resolvedStrValue;
        json::Json resolvedJsonValue {};
        bool isValueRef {false};
        if (value->isReference())
        {
            const auto valueRef = std::static_pointer_cast<const Reference>(value)->jsonPath();
            const auto refExists = event->exists(valueRef);
            if (refExists)
            {
                auto retvalObject = event->getJson(valueRef);

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
        else
        {
            resolvedStrValue = std::static_pointer_cast<const Value>(value)->value().getString().value();
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
    };
}

// TODO: some tests for this method are missing
// <field>: +kvdb_set/<db>/<field>/<value>
TransformBuilder getOpBuilderKVDBSet(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const Reference& targetField,
                                        const std::vector<OpArg>& opArgs,
                                        const std::shared_ptr<const IBuildCtx>& buildCtx)
    {
        return KVDBSet(kvdbManager, kvdbScopeName, targetField, opArgs, buildCtx);
    };
}

TransformOp KVDBDelete(std::shared_ptr<IKVDBManager> kvdbManager,
                       const std::string& kvdbScopeName,
                       const Reference& targetField,
                       const std::vector<OpArg>& opArgs,
                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 2);

    // First argument is kvdb name
    utils::assertValue(opArgs, 0);
    if (!std::static_pointer_cast<Value>(opArgs[0])->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected db name 'string' as first argument but got '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().str()));
    }

    auto dbName = std::static_pointer_cast<const Value>(opArgs[0])->value().getString().value();

    auto key = opArgs[1];
    if (key->isValue() && !std::static_pointer_cast<Value>(key)->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected key 'string' as second argument but got '{}'",
                                             std::static_pointer_cast<Value>(key)->value().str()));
    }

    const auto name = buildCtx->context().opName;

    // Trace messages
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace1 = fmt::format("[{}] -> Failure: filed reference for key '{}' not found", name);
    const std::string failureTrace2 =
        fmt::format("[{}] -> Failure: key could not be found on database '{}'", name, dbName);

    auto resultHandler = kvdbManager->getKVDBHandler(dbName, kvdbScopeName);

    if (std::holds_alternative<base::Error>(resultHandler))
    {
        throw std::runtime_error(
            fmt::format("Database is not available for usage: {}.", std::get<base::Error>(resultHandler).message));
    }

    // Return Op
    return [=,
            targetField = targetField.jsonPath(),
            kvdbHandler = std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler)](
               base::Event event) -> TransformResult
    {
        std::string resolvedKey;
        if (key->isReference())
        {
            const auto keyRef = std::static_pointer_cast<const Reference>(key)->jsonPath();
            const auto value = event->getString(keyRef);
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
            resolvedKey = std::static_pointer_cast<const Value>(key)->value().getString().value();
        }

        const auto resultValue = kvdbHandler->remove(resolvedKey);

        if (resultValue)
        {
            event->setBool(false, targetField);
            return base::result::makeFailure(event, failureTrace2);
        }

        event->setBool(true, targetField);

        return base::result::makeSuccess(event, successTrace);
    };
}

// TODO: some tests for this method are missing
// <field>: +kvdb_delete/<db>
TransformBuilder getOpBuilderKVDBDelete(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const Reference& targetField,
                                        const std::vector<OpArg>& opArgs,
                                        const std::shared_ptr<const IBuildCtx>& buildCtx)
    {
        return KVDBDelete(kvdbManager, kvdbScopeName, targetField, opArgs, buildCtx);
    };
}

// <field>: kvdb_get_array(<db>, <key_array>)
TransformBuilder getOpBuilderKVDBGetArray(std::shared_ptr<IKVDBManager> kvdbManager, const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const Reference& targetField,
                                        const std::vector<OpArg>& opArgs,
                                        const std::shared_ptr<const IBuildCtx>& buildCtx) -> TransformOp
    {
        // Assert expected number of parameters
        utils::assertSize(opArgs, 2);

        // First argument is kvdb name
        utils::assertValue(opArgs, 0);
        if (!std::static_pointer_cast<Value>(opArgs[0])->value().isString())
        {
            throw std::runtime_error(fmt::format("Expected db name 'string' as first argument but got '{}'",
                                                 std::static_pointer_cast<Value>(opArgs[0])->value().str()));
        }
        const auto dbName = std::static_pointer_cast<const Value>(opArgs[0])->value().getString().value();

        // Second argument is a reference to an array of keys
        utils::assertRef(opArgs, 1);
        const auto& keyArrayRef = *std::static_pointer_cast<const Reference>(opArgs[1]);

        const auto name = buildCtx->context().opName;

        // Check array reference is an array
        const auto& schema = buildCtx->schema();
        if (schema.hasField(keyArrayRef.dotPath()) && !schema.isArray(keyArrayRef.dotPath()))
        {
            throw std::runtime_error(fmt::format("Expected array reference as second argument but got type '{}'",
                                                 schemf::typeToStr(schema.getType(keyArrayRef.dotPath()))));
        }

        // Get KVDB handler
        auto resultHandler = kvdbManager->getKVDBHandler(dbName, kvdbScopeName);
        if (std::holds_alternative<base::Error>(resultHandler))
        {
            throw std::runtime_error(
                fmt::format("Engine KVDB builder: {}.", std::get<base::Error>(resultHandler).message));
        }

        // Trace messages
        auto referenceNotFound = fmt::format("Reference '{}' not found or not array", keyArrayRef.dotPath());
        auto emptyArray = fmt::format("Empty array in reference '{}'", keyArrayRef.dotPath());
        auto notKeyStr = fmt::format("Found non-string key in reference '{}'", keyArrayRef.dotPath());
        auto heterogeneousTypes = fmt::format("Heterogeneous types when obtaining values from database '{}'", dbName);
        auto malformedJson = fmt::format("Malformed JSON found in database '{}'", dbName);
        auto keyNotMatched = fmt::format("Key not found in DB '{}'", dbName);

        auto successTrace = fmt::format("{} -> Success", name);

        // Return Op
        return [=,
                targetField = targetField.jsonPath(),
                arrayRef = keyArrayRef.jsonPath(),
                kvdbHandler = std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler)](
                   const base::Event& event) -> TransformResult
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
        };
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

TransformOp OpBuilderHelperKVDBDecodeBitmask(const Reference& targetField,
                                             const std::vector<OpArg>& opArgs,
                                             const std::shared_ptr<const IBuildCtx>& buildCtx,
                                             std::shared_ptr<IKVDBManager> kvdbManager,
                                             const std::string& kvdbScopeName)
{
    // Identify references and build JSON pointer paths
    const auto name = buildCtx->context().opName;

    // Tracing
    const std::string throwTrace {"Engine KBDB Decode bit mask: "};
    const std::string successTrace {fmt::format("{} -> Success", name)};
    const std::string failureTrace1 {fmt::format("{} -> Failure: Expected hexa number as mask", name)};
    const std::string failureTrace2 {fmt::format("{} -> Failure: Reference to mask not found", name)};
    const std::string failureTrace3 {fmt::format("{} -> Failure: value of mask out of range", name)};
    const std::string failureTrace4 {fmt::format("{} -> Failure: no value found for the mask", name)};

    // Verify parameters size and types
    utils::assertSize(opArgs, 3);
    utils::assertValue(opArgs, 0, 1);
    utils::assertRef(opArgs, 2);

    // Extract parameters
    if (!std::static_pointer_cast<Value>(opArgs[0])->value().isString())
    {
        throw std::runtime_error(fmt::format(throwTrace + "Expected db name 'string' as first argument but got '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().str()));
    }
    if (!std::static_pointer_cast<Value>(opArgs[1])->value().isString())
    {
        throw std::runtime_error(fmt::format(throwTrace + "Expected key map 'string' as second argument but got '{}'",
                                             std::static_pointer_cast<Value>(opArgs[1])->value().str()));
    }
    const auto dbName = std::static_pointer_cast<Value>(opArgs[0])->value().getString().value();
    const auto keyMap = std::static_pointer_cast<Value>(opArgs[1])->value().getString().value();
    const auto& maskRef = *std::static_pointer_cast<const Reference>(opArgs[2]);

    // Verify the schema fields
    const auto& schema = buildCtx->schema();
    if (schema.hasField(targetField.dotPath()) && !schema.isArray(targetField.dotPath()))
    {
        throw std::runtime_error(throwTrace + "failed schema validation: Target field must be an array.");
    }
    if (schema.hasField(maskRef.dotPath()) && schema.getType(maskRef.dotPath()) != schemf::Type::KEYWORD
        && schema.getType(maskRef.dotPath()) != schemf::Type::TEXT
        && schema.getType(maskRef.dotPath()) != schemf::Type::IP)
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
    auto getMaskFn = [maskRef = maskRef.jsonPath(), failureTrace1, failureTrace2, failureTrace3](
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

    // Return Op
    return [targetField = targetField.jsonPath(), getValueFn, getMaskFn, successTrace, failureTrace4](
               const base::Event& event) -> TransformResult
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
    };
}

TransformBuilder getOpBuilderHelperKVDBDecodeBitmask(std::shared_ptr<IKVDBManager> kvdbManager,
                                                     const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const Reference& targetField,
                                        const std::vector<OpArg>& opArgs,
                                        const std::shared_ptr<const IBuildCtx>& buildCtx)
    {
        return OpBuilderHelperKVDBDecodeBitmask(targetField, opArgs, buildCtx, kvdbManager, kvdbScopeName);
    };
}

} // namespace builder::builders
