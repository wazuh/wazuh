#include "builders/opmap/kvdb.hpp"

#include <string>
#include <variant>

#include <fmt/format.h>

#include <base/json.hpp>
#include <base/utils/stringUtils.hpp>
#include <kvdb/ikvdbhandler.hpp>

#include "syntax.hpp"

namespace builder::builders
{
using namespace kvdbManager;

TransformOp KVDBGet(std::shared_ptr<IKVDBManager> kvdbManager,
                    const std::string& kvdbScopeName,
                    const Reference& targetField,
                    const std::vector<OpArg>& opArgs,
                    const std::shared_ptr<const IBuildCtx>& buildCtx,
                    const bool doMerge,
                    const bool isRecursive)
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
        if (buildCtx->validator().hasField(ref.dotPath()))
        {
            auto jType = buildCtx->validator().getJsonType(ref.dotPath());
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

    // Validate the target field
    schemf::ValueValidator validator = nullptr;
    if (buildCtx->validator().hasField(targetField.dotPath()))
    {
        if (doMerge
            && (buildCtx->validator().getType(targetField.dotPath()) != schemf::Type::OBJECT
                && !buildCtx->validator().isArray(targetField.dotPath())))
        {
            throw std::runtime_error(
                fmt::format("Expected target field '{}' to be an object or array but got '{}'",
                            targetField.dotPath(),
                            schemf::typeToStr(buildCtx->validator().getType(targetField.dotPath()))));
        }

        auto res = buildCtx->validator().validate(targetField.dotPath(), schemf::runtimeValidation());
        validator = base::getResponse<schemf::ValidationResult>(res).getValidator();
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
    const auto failureTrace7 =
        fmt::format("{} -> Value from DB failed validation for '{}': ", name, targetField.dotPath());

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
            if (validator != nullptr)
            {
                auto res = validator(value);
                if (base::isError(res))
                {
                    RETURN_FAILURE(runState, event, failureTrace7 + res.value().message);
                }
            }
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
                event->merge(isRecursive ? json::RECURSIVE : json::NOT_RECURSIVE, value, targetField);
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

// <field>: +kvdb_get_merge_recursive/<DB>/<ref_key>
TransformBuilder getOpBuilderKVDBGetMergeRecursive(std::shared_ptr<IKVDBManager> kvdbManager,
                                                   const std::string& kvdbScopeName)
{
    return [kvdbManager, kvdbScopeName](const Reference& targetField,
                                        const std::vector<OpArg>& opArgs,
                                        const std::shared_ptr<const IBuildCtx>& buildCtx)
    {
        return KVDBGet(kvdbManager, kvdbScopeName, targetField, opArgs, buildCtx, true, true);
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
        if (buildCtx->validator().hasField(ref.dotPath()))
        {
            auto jType = buildCtx->validator().getJsonType(ref.dotPath());
            if (jType != json::Json::Type::String)
            {
                throw std::runtime_error(fmt::format("Expected reference field of 'string' type but got '{}'",
                                                     json::Json::typeToStr(jType)));
            }
        }
    }

    auto resultHandler = kvdbManager->getKVDBHandler(dbName, kvdbScopeName);
    if (base::isError(resultHandler))
    {
        throw std::runtime_error(fmt::format("Error getting KVDB handler: {}", base::getError(resultHandler).message));
    }

    // Validate target field
    if (buildCtx->validator().hasField(targetField.dotPath()))
    {
        if (buildCtx->validator().getType(targetField.dotPath()) != schemf::Type::BOOLEAN)
        {
            throw std::runtime_error(fmt::format("Expected target field '{}' to be a boolean", targetField.dotPath()));
        }
    }

    // Trace messages
    const auto name = buildCtx->context().opName;
    const auto successTrace = fmt::format("{} -> Success", name);

    const auto failureTrace1 = [&]()
    {
        if (key->isReference())
        {
            return fmt::format(
                "{} -> Reference for key '{}' not found", name, std::static_pointer_cast<Reference>(key)->dotPath());
        }

        return std::string("");
    }();

    const auto failureTrace2 = [&]()
    {
        if (key->isReference())
        {
            return fmt::format("{} -> Reference for key '{}' is not a string",
                               name,
                               std::static_pointer_cast<Reference>(key)->dotPath());
        }

        return std::string("");
    }();

    const auto failureTrace3 = [&]()
    {
        if (value->isReference())
        {
            return fmt::format("{} -> Reference for value '{}' not found",
                               name,
                               std::static_pointer_cast<Reference>(value)->dotPath());
        }

        return std::string("");
    }();

    const auto failureTrace4 = fmt::format("{} -> Could not set value in DB: ", name);

    // Return Op
    return [=,
            runState = buildCtx->runState(),
            targetField = targetField.jsonPath(),
            kvdbHandler = std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler)](
               base::Event event) -> TransformResult
    {
        // Get key name
        std::string resolvedKey;
        if (key->isReference())
        {
            const auto& keyRef = *std::static_pointer_cast<Reference>(key);
            if (!event->exists(keyRef.jsonPath()))
            {
                RETURN_FAILURE(runState, event, failureTrace1);
            }

            const auto value = event->getString(keyRef.jsonPath());
            if (!value)
            {
                RETURN_FAILURE(runState, event, failureTrace2);
            }

            resolvedKey = value.value();
        }
        else
        {
            resolvedKey = std::static_pointer_cast<const Value>(key)->value().getString().value();
        }

        // Get value and perform the set in the DB
        base::OptError error = base::noError();
        if (value->isReference())
        {
            const auto& valueRef = *std::static_pointer_cast<Reference>(value);
            if (!event->exists(valueRef.jsonPath()))
            {
                RETURN_FAILURE(runState, event, failureTrace3);
            }

            const auto value = event->getJson(valueRef.jsonPath());
            error = kvdbHandler->set(resolvedKey, value.value());
        }
        else
        {
            error = kvdbHandler->set(resolvedKey, std::static_pointer_cast<const Value>(value)->value());
        }

        // Set value in KVDB
        if (error)
        {
            RETURN_FAILURE(runState, event, failureTrace4 + error.value().message);
        }

        event->setBool(true, targetField);
        RETURN_SUCCESS(runState, event, successTrace);
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
        if (buildCtx->validator().hasField(ref.dotPath()))
        {
            auto jType = buildCtx->validator().getJsonType(ref.dotPath());
            if (jType != json::Json::Type::String)
            {
                throw std::runtime_error(fmt::format("Expected reference field of 'string' type but got '{}'",
                                                     json::Json::typeToStr(jType)));
            }
        }
    }

    auto resultHandler = kvdbManager->getKVDBHandler(dbName, kvdbScopeName);

    if (std::holds_alternative<base::Error>(resultHandler))
    {
        throw std::runtime_error(
            fmt::format("Database is not available for usage: {}.", std::get<base::Error>(resultHandler).message));
    }

    // Validate target field
    if (buildCtx->validator().hasField(targetField.dotPath()))
    {
        if (buildCtx->validator().getType(targetField.dotPath()) != schemf::Type::BOOLEAN)
        {
            throw std::runtime_error(fmt::format("Expected target field '{}' to be a boolean", targetField.dotPath()));
        }
    }

    // Trace messages
    const auto name = buildCtx->context().opName;
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace1 = [&]()
    {
        if (key->isReference())
        {
            return fmt::format(
                "{} -> Reference for key '{}' not found", name, std::static_pointer_cast<Reference>(key)->dotPath());
        }

        return std::string("");
    }();
    const auto failureTrace2 = [&]()
    {
        if (key->isReference())
        {
            return fmt::format("{} -> Reference for key '{}' is not a string",
                               name,
                               std::static_pointer_cast<Reference>(key)->dotPath());
        }

        return std::string("");
    }();

    const auto failureTrace3 = fmt::format("{} -> Could not remove entry in DB: ", name);

    // Return Op
    return [=,
            runState = buildCtx->runState(),
            targetField = targetField.jsonPath(),
            kvdbHandler = std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler)](
               base::Event event) -> TransformResult
    {
        std::string resolvedKey;
        if (key->isReference())
        {
            const auto& keyRef = *std::static_pointer_cast<Reference>(key);
            if (!event->exists(keyRef.jsonPath()))
            {
                RETURN_FAILURE(runState, event, failureTrace1);
            }

            const auto value = event->getString(keyRef.jsonPath());
            if (!value)
            {
                RETURN_FAILURE(runState, event, failureTrace2);
            }

            resolvedKey = value.value();
        }
        else
        {
            resolvedKey = std::static_pointer_cast<const Value>(key)->value().getString().value();
        }

        auto error = kvdbHandler->remove(resolvedKey);

        if (error)
        {
            RETURN_FAILURE(runState, event, failureTrace3 + error.value().message);
        }

        event->setBool(true, targetField);

        RETURN_SUCCESS(runState, event, successTrace);
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

        // Second argument is key array
        auto keyArray = opArgs[1];

        if (keyArray->isValue())
        {
            if (!std::static_pointer_cast<Value>(keyArray)->value().isArray())
            {
                throw std::runtime_error(fmt::format("Expected key array 'array' as second argument but got '{}'",
                                                     std::static_pointer_cast<Value>(keyArray)->value().str()));
            }

            auto asArray = std::static_pointer_cast<Value>(keyArray)->value().getArray().value();
            for (auto& value : asArray)
            {
                if (!value.isString())
                {
                    throw std::runtime_error(fmt::format("Expected an array of strings but found '{}'",
                                                         json::Json::typeToStr(value.type())));
                }
            }
        }
        else
        {
            const auto& ref = *std::static_pointer_cast<const Reference>(keyArray);
            if (buildCtx->validator().hasField(ref.dotPath()))
            {
                if (!buildCtx->validator().isArray(ref.dotPath()))
                {
                    throw std::runtime_error(fmt::format("Reference field '{}' is not an array", ref.dotPath()));
                }

                auto jType = buildCtx->validator().getJsonType(ref.dotPath());
                if (jType != json::Json::Type::String)
                {
                    throw std::runtime_error(
                        fmt::format("Reference field '{}' is not an array of strings", ref.dotPath()));
                }
            }
        }

        // Get KVDB handler
        auto resultHandler = kvdbManager->getKVDBHandler(dbName, kvdbScopeName);
        if (std::holds_alternative<base::Error>(resultHandler))
        {
            throw std::runtime_error(
                fmt::format("Engine KVDB builder: {}.", std::get<base::Error>(resultHandler).message));
        }

        // Validate target field
        auto valRes = buildCtx->validator().validate(targetField.dotPath(), schemf::isArrayToken());
        if (base::isError(valRes))
        {
            throw std::runtime_error(fmt::format("Error validating target field '{}': {}",
                                                 targetField.dotPath(),
                                                 std::get<base::Error>(valRes).message));
        }
        auto validator = base::getResponse<schemf::ValidationResult>(valRes).getValidator();

        // Trace messages
        const auto name = buildCtx->context().opName;
        const auto successTrace = fmt::format("{} -> Success", name);

        const auto failureTrace1 = [&]()
        {
            if (keyArray->isReference())
            {
                return fmt::format("{} -> Reference for key array '{}' not found",
                                   name,
                                   std::static_pointer_cast<Reference>(keyArray)->dotPath());
            }

            return std::string("");
        }();

        const auto failureTrace2 = [&]()
        {
            if (keyArray->isReference())
            {
                return fmt::format("{} -> Reference for key array '{}' is not an heterogeneous string array",
                                   name,
                                   std::static_pointer_cast<Reference>(keyArray)->dotPath());
            }

            return std::string("");
        }();

        const auto failureTrace3 = fmt::format("{} -> Could not get value from DB: ", name);
        const auto failureTrace4 = fmt::format("{} -> Malformed JSON for value in DB: ", name);
        const auto failureTrace5 = fmt::format("{} -> Array of values from DB is not homogeneous", name);
        const auto failureTrace6 =
            fmt::format("{} -> Final array failed validation for '{}': ", name, targetField.dotPath());

        // Return Op
        return [=,
                runState = buildCtx->runState(),
                targetField = targetField.jsonPath(),
                kvdbHandler = std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler)](
                   base::Event event) -> TransformResult
        {
            // Resolve array of keys
            std::vector<json::Json> keys;
            if (keyArray->isReference())
            {
                const auto& keyArrayRef = *std::static_pointer_cast<Reference>(keyArray);
                if (!event->exists(keyArrayRef.jsonPath()))
                {
                    RETURN_FAILURE(runState, event, failureTrace1);
                }

                const auto value = event->getArray(keyArrayRef.jsonPath());
                if (!value)
                {
                    RETURN_FAILURE(runState, event, failureTrace2);
                }

                for (const auto& key : value.value())
                {
                    if (!key.isString())
                    {
                        RETURN_FAILURE(runState, event, failureTrace2);
                    }

                    keys.emplace_back(key);
                }
            }
            else
            {
                keys = std::static_pointer_cast<const Value>(keyArray)->value().getArray().value();
            }

            // Get values from KVDB
            bool first = true;
            json::Json::Type type;
            std::vector<json::Json> values;
            for (const auto& jKey : keys)
            {
                auto resultValue = kvdbHandler->get(jKey.getString().value());
                if (base::isError(resultValue))
                {
                    RETURN_FAILURE(runState, event, failureTrace3 + std::get<base::Error>(resultValue).message);
                }

                json::Json jValue;
                try
                {
                    jValue = json::Json {std::get<std::string>(resultValue).c_str()};
                }
                catch (const std::runtime_error& e)
                {
                    RETURN_FAILURE(runState, event, failureTrace4 + e.what());
                }

                if (first)
                {
                    type = jValue.type();
                    first = false;
                }
                else if (jValue.type() != type)
                {
                    RETURN_FAILURE(runState, event, failureTrace5);
                }

                values.emplace_back(std::move(jValue));
            }

            // Get target array
            auto targetArray = event->getJson(targetField)
                                   .value_or(
                                       []()
                                       {
                                           json::Json jArray;
                                           jArray.setArray();
                                           return std::move(jArray);
                                       }());

            // Append values to target field
            for (auto& value : values)
            {
                targetArray.appendJson(value);
            }

            // Validate target array
            if (validator != nullptr)
            {
                auto res = validator(targetArray);
                if (base::isError(res))
                {
                    RETURN_FAILURE(runState, event, failureTrace6 + res.value().message);
                }
            }

            event->set(targetField, targetArray);

            RETURN_SUCCESS(runState, event, successTrace);
        };
    };
}

namespace
{
// TODO Change this to use an vector instead of a map
std::function<std::optional<json::Json>(uint64_t pos)> getFnSearchMap(const json::Json& jMap)
{
    std::vector<std::optional<json::Json>> buildedMap(std::numeric_limits<uint64_t>::digits);
    // Fill the map with empty values
    std::fill(buildedMap.begin(), buildedMap.end(), std::nullopt);
    {
        if (!jMap.isObject())
        {
            throw std::runtime_error(
                fmt::format("Expected map 'object' as value from DB but got '{}'", jMap.typeName()));
        }

        auto jMapObj = jMap.getObject().value();
        json::Json::Type mapValueType {};
        bool isTypeSet = false;

        if (jMapObj.empty())
        {
            throw std::runtime_error("Empty map value from DB");
        }

        for (auto& [key, value] : jMapObj)
        {
            uint64_t index = 0;
            // Validate key
            if (key.empty())
            {
                throw std::runtime_error("Found empty key on map value from DB");
            }
            if (key[0] == '-')
            {
                throw std::runtime_error("Found negative key on map value from DB");
            }

            try
            {
                index = std::stoul(key);
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(fmt::format("Could not convert key '{}' to number: {}", key, e.what()));
            }
            if (index >= std::numeric_limits<uint64_t>::digits)
            {
                throw std::runtime_error(fmt::format(
                    "Malformed map Key '{}' out of range {}-{})", key, 0, std::numeric_limits<uint64_t>::digits));
            }

            // Validate value
            if (!isTypeSet)
            {
                mapValueType = value.type();
                isTypeSet = true;
            }
            else if (mapValueType != value.type())
            {
                throw std::runtime_error(fmt::format("Found heterogeneous values on the map value from DB"));
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
    // Verify parameters size and types
    utils::assertSize(opArgs, 3);
    utils::assertValue(opArgs, 0, 1);
    utils::assertRef(opArgs, 2);

    // Extract parameters
    if (!std::static_pointer_cast<Value>(opArgs[0])->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected db name 'string' as first argument but got '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().str()));
    }
    if (!std::static_pointer_cast<Value>(opArgs[1])->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected key map 'string' as second argument but got '{}'",
                                             std::static_pointer_cast<Value>(opArgs[1])->value().str()));
    }
    const auto dbName = std::static_pointer_cast<Value>(opArgs[0])->value().getString().value();
    const auto keyMap = std::static_pointer_cast<Value>(opArgs[1])->value().getString().value();
    const auto& maskRef = *std::static_pointer_cast<const Reference>(opArgs[2]);

    // Verify the schema fields

    if (buildCtx->validator().hasField(targetField.dotPath()))
    {
        if (!buildCtx->validator().isArray(targetField.dotPath()))
        {
            throw std::runtime_error(fmt::format("Expected target field '{}' to be an array", targetField.dotPath()));
        }
        auto jType = buildCtx->validator().getJsonType(targetField.dotPath());
        if (jType != json::Json::Type::String)
        {
            throw std::runtime_error(
                fmt::format("Expected target field '{}' to be an array of strings", targetField.dotPath()));
        }
    }

    if (buildCtx->validator().hasField(maskRef.dotPath()))
    {
        auto jType = buildCtx->validator().getJsonType(maskRef.dotPath());
        if (jType != json::Json::Type::String)
        {
            throw std::runtime_error(fmt::format("Expected mask field '{}' to be a string", maskRef.dotPath()));
        }
    }

    // Get the json map from KVDB
    json::Json jMap {};
    {
        auto resultHandler = kvdbManager->getKVDBHandler(dbName, kvdbScopeName);
        if (std::holds_alternative<base::Error>(resultHandler))
        {
            throw std::runtime_error(
                fmt::format("Could not get KVDB handler: {}.", std::get<base::Error>(resultHandler).message));
        }
        auto kvdbHandler = std::get<std::shared_ptr<kvdbManager::IKVDBHandler>>(resultHandler);

        auto resultValue = kvdbHandler->get(keyMap);
        if (std::holds_alternative<base::Error>(resultValue))
        {
            throw std::runtime_error(
                fmt::format("Could not get map from KVDB: {}.", std::get<base::Error>(resultValue).message));
        }
        try
        {
            jMap = json::Json {std::get<std::string>(resultValue).c_str()};
        }
        catch (const std::runtime_error& e)
        {
            throw std::runtime_error(fmt::format("Malformed JSON value for key '{}' in DB: {}", keyMap, e.what()));
        }
    }

    // Get the function to search in the map
    auto getValueFn = getFnSearchMap(jMap);

    // Tracing
    const auto name = buildCtx->context().opName;
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace1 = fmt::format("{} -> Reference '{}' not found", name, maskRef.dotPath());
    const auto failureTrace2 = fmt::format("{} -> Reference '{}' is not a string", name, maskRef.dotPath());
    const auto failureTrace3 =
        fmt::format("{} -> Reference '{}' is not a valid hexadecimal number", name, maskRef.dotPath());
    const auto failureTrace4 =
        fmt::format("{} -> Reference '{}' values is out of range 0-0xFFFFFFFFFFFFFFFF", name, maskRef.dotPath());

    // Get the function to get the value from the event
    auto getMaskFn = [maskRef = maskRef.jsonPath(), failureTrace1, failureTrace2, failureTrace3, failureTrace4](
                         const base::Event& event) -> base::RespOrError<uint64_t>
    {
        // Check if the mask exists
        if (!event->exists(maskRef))
        {
            return base::Error {failureTrace1};
        }

        // If is a string, get the mask as hexa in range 0-0xFFFFFFFFFFFFFFFF
        const auto maskStr = event->getString(maskRef);
        if (!maskStr.has_value())
        {
            return base::Error {failureTrace2};
        }

        try
        {
            auto rMask = std::stoul(maskStr.value(), nullptr, 16);
            if (rMask <= std::numeric_limits<uint64_t>::max())
            {
                return static_cast<uint64_t>(rMask);
            }
            return base::Error {failureTrace4};
        }
        catch (const std::exception&)
        {
            return base::Error {failureTrace3};
        }
    };

    // Return Op
    return
        [=, runState = buildCtx->runState(), targetField = targetField.jsonPath()](base::Event event) -> TransformResult
    {
        // Get mask in hexa
        uint64_t mask {};
        {
            auto resultMask = getMaskFn(event);
            if (base::isError(resultMask))
            {
                RETURN_FAILURE(runState, event, base::getError(resultMask).message);
            }
            mask = base::getResponse(resultMask);
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
            RETURN_FAILURE(runState, event, failureTrace4);
        }

        RETURN_SUCCESS(runState, event, successTrace);
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
