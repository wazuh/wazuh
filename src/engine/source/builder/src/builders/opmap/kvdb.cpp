#include "builders/opmap/kvdb.hpp"

#include <string>
#include <variant>

#include <fmt/format.h>

#include <base/json.hpp>
#include <base/utils/stringUtils.hpp>
#include <kvdbstore/ikvdbhandler.hpp>

#include "syntax.hpp"

namespace builder::builders
{

namespace
{
inline TransformOp makeTransformNoOp(const std::shared_ptr<const IBuildCtx>& buildCtx, std::string trace)
{
    const auto runState = buildCtx->runState();
    return [runState, trace = std::move(trace)](base::Event event) -> TransformResult
    {
        RETURN_SUCCESS(runState, event, trace)
    };
}

inline FilterOp makeFilterNoOp(const std::shared_ptr<const IBuildCtx>& buildCtx, bool pass, std::string trace)
{
    const auto runState = buildCtx->runState();
    return [runState, pass, trace = std::move(trace)](base::ConstEvent) -> FilterResult
    {
        RETURN_SUCCESS(runState, pass, trace)
    };
}

/**
 * @brief Validates KVDB availability when building from integration/policy context.
 *
 * Throws runtime_error if KVDB is not declared or is disabled in the integration.
 * Does nothing if not in integration context (availableKvdbs is nullopt).
 *
 * @param buildCtx Build context
 * @param dbName Name of the KVDB to validate
 * @throws std::runtime_error if KVDB is not declared or disabled
 */
inline void validateKvdbAvailability(const std::shared_ptr<const IBuildCtx>& buildCtx, const std::string& dbName)
{
    // Only validate when building from integration/policy context.
    // When validating assets individually, availableKvdbs is nullopt.
    if (buildCtx->context().availableKvdbs.has_value())
    {
        const auto [exists, enabled] = buildCtx->isKvdbAvailable(dbName);

        if (!exists)
        {
            throw std::runtime_error(fmt::format("KVDB '{}' is not declared in the integration. "
                                                 "Add it to the integration's KVDB list before using it.",
                                                 dbName));
        }
        if (!enabled)
        {
            throw std::runtime_error(fmt::format("KVDB '{}' is disabled in the integration. "
                                                 "Enable it to use this helper.",
                                                 dbName));
        }
    }
}
} // namespace

using namespace kvdbstore;

TransformOp KVDBGet(std::shared_ptr<IKVDBManager> kvdbManager,
                    const Reference& targetField,
                    const std::vector<OpArg>& opArgs,
                    const std::shared_ptr<const IBuildCtx>& buildCtx,
                    const bool doMerge,
                    const bool isRecursive)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 2);

    // Allowed fields check
    const auto assetType = base::Name(buildCtx->context().assetName).parts().front();
    if (!buildCtx->allowedFields().check(assetType, targetField.dotPath()))
    {
        throw std::runtime_error(fmt::format("Field '{}' is not allowed in '{}'", targetField.dotPath(), assetType));
    }

    // First argument is KVDB name
    utils::assertValue(opArgs, 0);
    if (!std::static_pointer_cast<Value>(opArgs[0])->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected db name 'string' as first argument but got '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().str()));
    }
    auto dbName = std::static_pointer_cast<const Value>(opArgs[0])->value().getString().value();

    // Validate KVDB availability in integration/policy context
    validateKvdbAvailability(buildCtx, dbName);

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

    // Validate the target field
    schemf::ValueValidator targetValueValidator = nullptr;
    if (buildCtx->validator().hasField(targetField.dotPath()))
    {
        auto res = buildCtx->validator().validate(targetField.dotPath(), schemf::runtimeValidation());
        targetValueValidator = base::getResponse<schemf::ValidationResult>(res).getValidator();

        if (doMerge)
        {
            auto type = buildCtx->validator().getType(targetField.dotPath());
            if (type != schemf::Type::OBJECT)
            {
                throw std::runtime_error(fmt::format("Expected target field '{}' to be an object but got '{}'",
                                                     targetField.dotPath(),
                                                     schemf::typeToStr(type)));
            }
        }
    }

    // Format name for the tracer
    const auto name = buildCtx->context().opName;

    if (buildCtx->allowMissingDependencies())
    {
        return makeTransformNoOp(buildCtx,
                                 fmt::format("{} -> Skipped KVDB resolution (allowMissingDependencies)", name));
    }
    // Get KVDB handler
    const auto& nsReader = buildCtx->getStoreNSReader();

    std::shared_ptr<IKVDBHandler> kvdbHandler;
    try
    {
        kvdbHandler = kvdbManager->getKVDBHandler(nsReader, dbName);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Engine KVDB builder: failed to load KVDB '{}': {}", dbName, e.what()));
    }

    // Trace messages
    const auto successTrace {fmt::format("{} -> Success", name)};

    const auto failureTrace1 = fmt::format("{} -> Target field '{}' not found", name, targetField.dotPath());
    const auto failureTrace2 = [&]()
    {
        if (key->isReference())
        {
            return fmt::format(
                "{} -> Reference for key '{}' not found", name, std::static_pointer_cast<Reference>(key)->dotPath());
        }

        return std::string("");
    }();
    const auto failureTrace3 = [&]()
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
    const auto failureTrace8 = fmt::format(
        "{} -> Cannot map subfields of {} because is not allowed for {}", name, targetField.dotPath(), assetType);

    // Precompute values to capture explicitly
    const auto runState = buildCtx->runState();
    const auto targetJsonPath = targetField.jsonPath();
    const auto targetDotPath = targetField.dotPath();
    const auto allowedFieldsPtr = buildCtx->allowedFieldsPtr();

    // Return Op
    return [key,
            assetType,
            targetValueValidator,
            successTrace,
            failureTrace1,
            failureTrace2,
            failureTrace3,
            failureTrace4,
            failureTrace5,
            failureTrace6,
            failureTrace7,
            failureTrace8,
            runState,
            targetJsonPath,
            targetDotPath,
            allowedFieldsPtr,
            kvdbHandler = std::move(kvdbHandler),
            doMerge,
            isRecursive](base::Event event) -> TransformResult
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
        try
        {
            const json::Json& value = kvdbHandler->get(resolvedKey);

            if (targetValueValidator != nullptr)
            {
                auto res = targetValueValidator(value);
                if (base::isError(res))
                {
                    RETURN_FAILURE(runState, event, failureTrace7 + res.value().message)
                }
            }
            if (value.isObject())
            {
                auto fields = value.getFields().value();
                for (const auto& field : fields)
                {
                    if (!allowedFieldsPtr->check(assetType, DotPath::append(targetDotPath, field)))
                    {
                        RETURN_FAILURE(runState, event, failureTrace8)
                    }
                }
            }

            if (doMerge)
            {
                if (!event->exists(targetJsonPath))
                {
                    RETURN_FAILURE(runState, event, failureTrace1)
                }

                if (event->type(targetJsonPath) != value.type() || (!value.isObject() && !value.isArray()))
                {
                    RETURN_FAILURE(runState, event, failureTrace5)
                }

                event->merge(isRecursive ? json::RECURSIVE : json::NOT_RECURSIVE, value, targetJsonPath);
            }
            else
            {
                event->set(targetJsonPath, value);
            }
        }
        catch (const std::out_of_range&)
        {
            RETURN_FAILURE(runState, event, failureTrace4)
        }
        catch (const std::runtime_error& e)
        {
            RETURN_FAILURE(runState, event, failureTrace6 + e.what())
        }

        RETURN_SUCCESS(runState, event, successTrace)
    };
}

// <field>: +kvdb_get/<DB>/<ref_key>
TransformBuilder getOpBuilderKVDBGet(std::shared_ptr<IKVDBManager> kvdbManager)
{
    return [kvdbManager](const Reference& targetField,
                         const std::vector<OpArg>& opArgs,
                         const std::shared_ptr<const IBuildCtx>& buildCtx)
    {
        return KVDBGet(kvdbManager, targetField, opArgs, buildCtx, false);
    };
}

// <field>: +kvdb_get_merge/<DB>/<ref_key>
TransformBuilder getOpBuilderKVDBGetMerge(std::shared_ptr<IKVDBManager> kvdbManager)
{
    return [kvdbManager](const Reference& targetField,
                         const std::vector<OpArg>& opArgs,
                         const std::shared_ptr<const IBuildCtx>& buildCtx)
    {
        return KVDBGet(kvdbManager, targetField, opArgs, buildCtx, true);
    };
}

// <field>: +kvdb_get_merge_recursive/<DB>/<ref_key>
TransformBuilder getOpBuilderKVDBGetMergeRecursive(std::shared_ptr<IKVDBManager> kvdbManager)
{
    return [kvdbManager](const Reference& targetField,
                         const std::vector<OpArg>& opArgs,
                         const std::shared_ptr<const IBuildCtx>& buildCtx)
    {
        return KVDBGet(kvdbManager, targetField, opArgs, buildCtx, true, true);
    };
}

FilterOp existanceCheck(std::shared_ptr<IKVDBManager> kvdbManager,
                        const Reference& targetField,
                        const std::vector<OpArg>& opArgs,
                        const std::shared_ptr<const IBuildCtx>& buildCtx,
                        const bool shouldMatch)
{
    // Assert expected number of parameters
    utils::assertSize(opArgs, 1);

    // First argument is KVDB name
    utils::assertValue(opArgs, 0);
    if (!std::static_pointer_cast<Value>(opArgs[0])->value().isString())
    {
        throw std::runtime_error(fmt::format("Expected db name 'string' as first argument but got '{}'",
                                             std::static_pointer_cast<Value>(opArgs[0])->value().str()));
    }

    auto dbName = std::static_pointer_cast<const Value>(opArgs[0])->value().getString().value();

    // Validate KVDB availability in integration/policy context
    validateKvdbAvailability(buildCtx, dbName);

    const auto name = buildCtx->context().opName;

    if (buildCtx->allowMissingDependencies())
    {
        // Neutral behavior in validation: do not filter anything out.
        return makeFilterNoOp(
            buildCtx, true, fmt::format("{} -> Skipped KVDB resolution (allowMissingDependencies)", name));
    }

    // Get KVDB handler
    const auto& nsReader = buildCtx->getStoreNSReader();

    std::shared_ptr<IKVDBHandler> kvdbHandler;
    try
    {
        kvdbHandler = kvdbManager->getKVDBHandler(nsReader, dbName);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Engine KVDB builder: failed to load KVDB '{}': {}", dbName, e.what()));
    }

    // Trace messages
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace1 = fmt::format("{} -> Target field '{}' not found", name, targetField.dotPath());
    const auto failureTrace2 = fmt::format("{} -> Target field '{}' is not a string", name, targetField.dotPath());
    const auto failureTraceMatch = fmt::format("{} -> Key not found in DB", name);
    const auto failureTraceNotMatch = fmt::format("{} -> Key found in DB", name);

    return [=,
            runState = buildCtx->runState(),
            targetField = targetField.jsonPath(),
            kvdbHandler = std::move(kvdbHandler)](base::ConstEvent event) -> FilterResult
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

        const bool found = kvdbHandler->contains(key.value());
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
FilterBuilder getOpBuilderKVDBMatch(std::shared_ptr<IKVDBManager> kvdbManager)
{
    return [kvdbManager](const Reference& targetField,
                         const std::vector<OpArg>& opArgs,
                         const std::shared_ptr<const IBuildCtx>& buildCtx)
    {
        return existanceCheck(kvdbManager, targetField, opArgs, buildCtx, true);
    };
}

// <field>: +kvdb_not_match/<DB>
FilterBuilder getOpBuilderKVDBNotMatch(std::shared_ptr<IKVDBManager> kvdbManager)
{
    return [kvdbManager](const Reference& targetField,
                         const std::vector<OpArg>& opArgs,
                         const std::shared_ptr<const IBuildCtx>& buildCtx)
    {
        return existanceCheck(kvdbManager, targetField, opArgs, buildCtx, false);
    };
}

// <field>: kvdb_get_array(<db>, <key_array>)
TransformBuilder getOpBuilderKVDBGetArray(std::shared_ptr<IKVDBManager> kvdbManager)
{
    return [kvdbManager](const Reference& targetField,
                         const std::vector<OpArg>& opArgs,
                         const std::shared_ptr<const IBuildCtx>& buildCtx) -> TransformOp
    {
        // Assert expected number of parameters
        utils::assertSize(opArgs, 2);

        // Check allowed fields
        const auto assetType = base::Name(buildCtx->context().assetName).parts().front();
        if (!buildCtx->allowedFields().check(assetType, targetField.dotPath()))
        {
            throw std::runtime_error(
                fmt::format("Field '{}' is not allowed in '{}'", targetField.dotPath(), assetType));
        }

        // First argument is KVDB name
        utils::assertValue(opArgs, 0);
        if (!std::static_pointer_cast<Value>(opArgs[0])->value().isString())
        {
            throw std::runtime_error(fmt::format("Expected db name 'string' as first argument but got '{}'",
                                                 std::static_pointer_cast<Value>(opArgs[0])->value().str()));
        }
        const auto dbName = std::static_pointer_cast<const Value>(opArgs[0])->value().getString().value();

        // Validate KVDB availability in integration/policy context
        validateKvdbAvailability(buildCtx, dbName);

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
                auto jType = buildCtx->validator().getJsonType(ref.dotPath());
                if (jType != json::Json::Type::String)
                {
                    throw std::runtime_error(
                        fmt::format("Reference field '{}' is not an array of strings", ref.dotPath()));
                }
            }
        }

        // Validate target field
        auto valRes = buildCtx->validator().validate(targetField.dotPath(), schemf::elementValidationToken());
        if (base::isError(valRes))
        {
            throw std::runtime_error(fmt::format("Error validating target field '{}': {}",
                                                 targetField.dotPath(),
                                                 std::get<base::Error>(valRes).message));
        }
        auto targetValidator = base::getResponse<schemf::ValidationResult>(valRes).getValidator();

        const auto name = buildCtx->context().opName;

        if (buildCtx->allowMissingDependencies())
        {
            return makeTransformNoOp(buildCtx,
                                     fmt::format("{} -> Skipped KVDB resolution (allowMissingDependencies)", name));
        }

        // Get KVDB handler
        const auto& nsReader = buildCtx->getStoreNSReader();

        std::shared_ptr<IKVDBHandler> kvdbHandler;
        try
        {
            kvdbHandler = kvdbManager->getKVDBHandler(nsReader, dbName);
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("Engine KVDB builder: failed to load KVDB '{}': {}", dbName, e.what()));
        }

        // Trace messages
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
        const auto failureTrace5 = fmt::format("{} -> Array of values from DB is not homogeneous", name);
        const auto failureTrace6 =
            fmt::format("{} -> Final array failed validation for '{}': ", name, targetField.dotPath());

        // Return Op
        return [=,
                runState = buildCtx->runState(),
                targetField = targetField.jsonPath(),
                kvdbHandler = std::move(kvdbHandler)](base::Event event) -> TransformResult
        {
            // Resolve array of keys
            std::vector<json::Json> keys;
            if (keyArray->isReference())
            {
                const auto& keyArrayRef = *std::static_pointer_cast<Reference>(keyArray);
                if (!event->exists(keyArrayRef.jsonPath()))
                {
                    RETURN_FAILURE(runState, event, failureTrace1)
                }

                const auto value = event->getArray(keyArrayRef.jsonPath());
                if (!value)
                {
                    RETURN_FAILURE(runState, event, failureTrace2)
                }

                for (const auto& key : value.value())
                {
                    if (!key.isString())
                    {
                        RETURN_FAILURE(runState, event, failureTrace2)
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
            json::Json::Type type {};
            std::vector<std::reference_wrapper<const json::Json>> values;
            values.reserve(keys.size());

            for (const auto& jKey : keys)
            {
                try
                {
                    const json::Json& jValue = kvdbHandler->get(jKey.getString().value());

                    if (first)
                    {
                        type = jValue.type();
                        first = false;
                    }
                    else if (jValue.type() != type)
                    {
                        RETURN_FAILURE(runState, event, failureTrace5)
                    }

                    values.emplace_back(std::cref(jValue));
                }
                catch (const std::out_of_range& e)
                {
                    RETURN_FAILURE(runState, event, failureTrace3 + e.what())
                }
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
            for (const auto& value : values)
            {
                targetArray.appendJson(value.get());
            }

            // Validate target array
            if (targetValidator != nullptr)
            {
                auto res = targetValidator(targetArray);
                if (base::isError(res))
                {
                    RETURN_FAILURE(runState, event, failureTrace6 + res.value().message)
                }
            }

            event->set(targetField, targetArray);

            RETURN_SUCCESS(runState, event, successTrace);
        };
    };
}

namespace
{
auto getFnSearchMap(const json::Json& jMap)
{
    std::vector<std::optional<json::Json>> map(std::numeric_limits<uint64_t>::digits);

    if (!jMap.isObject())
    {
        throw std::runtime_error(fmt::format("Expected map 'object' as value from DB but got '{}'", jMap.typeName()));
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

        if (!isTypeSet)
        {
            mapValueType = value.type();
            isTypeSet = true;
        }
        else if (mapValueType != value.type())
        {
            throw std::runtime_error("Found heterogeneous values on the map value from DB");
        }

        map[index] = std::move(value);
    }

    // Move the lookup table into the closure instead of copying it.
    return [map = std::move(map)](uint64_t pos) -> std::optional<json::Json>
    {
        if (pos < map.size())
        {
            return map[pos];
        }
        return std::nullopt;
    };
}
} // namespace

TransformOp OpBuilderHelperKVDBDecodeBitmask(const Reference& targetField,
                                             const std::vector<OpArg>& opArgs,
                                             const std::shared_ptr<const IBuildCtx>& buildCtx,
                                             std::shared_ptr<IKVDBManager> kvdbManager)
{
    // Verify parameters size and types
    utils::assertSize(opArgs, 3);
    utils::assertValue(opArgs, 0, 1);
    utils::assertRef(opArgs, 2);

    // Check allowed fields
    const auto assetType = base::Name(buildCtx->context().assetName).parts().front();
    if (!buildCtx->allowedFields().check(assetType, targetField.dotPath()))
    {
        throw std::runtime_error(fmt::format("Field '{}' is not allowed in '{}'", targetField.dotPath(), assetType));
    }

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

    // Validate KVDB availability in integration/policy context
    validateKvdbAvailability(buildCtx, dbName);

    // Verify the schema fields
    if (buildCtx->validator().hasField(targetField.dotPath()))
    {
        auto jType = buildCtx->validator().getJsonType(targetField.dotPath());
        if (jType != json::Json::Type::String)
        {
            throw std::runtime_error(
                fmt::format("Expected target field '{}' to contain string", targetField.dotPath()));
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

    const auto name = buildCtx->context().opName;

    // In validation mode, we skip KVDB access entirely (no handler, no map pre-build).
    if (buildCtx->allowMissingDependencies())
    {
        return makeTransformNoOp(buildCtx,
                                 fmt::format("{} -> Skipped KVDB map build (allowMissingDependencies)", name));
    }
    // Build the lookup function from the KVDB map
    std::function<std::optional<json::Json>(uint64_t)> getValueFn;
    {
        const auto& nsReader = buildCtx->getStoreNSReader();

        std::shared_ptr<IKVDBHandler> kvdbHandler;
        try
        {
            kvdbHandler = kvdbManager->getKVDBHandler(nsReader, dbName);
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("Engine KVDB builder: failed to load KVDB '{}': {}", dbName, e.what()));
        }

        try
        {
            const json::Json& jMap = kvdbHandler->get(keyMap);
            getValueFn = getFnSearchMap(jMap);
        }
        catch (const std::out_of_range& e)
        {
            throw std::runtime_error(fmt::format("Could not get map from KVDB: {}", e.what()));
        }
        catch (const std::runtime_error& e)
        {
            throw std::runtime_error(fmt::format("Malformed map value for key '{}' in DB: {}", keyMap, e.what()));
        }
    }

    // Tracing
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace1 = fmt::format("{} -> Reference '{}' not found", name, maskRef.dotPath());
    const auto failureTrace2 = fmt::format("{} -> Reference '{}' is not a string", name, maskRef.dotPath());
    const auto failureTrace3 =
        fmt::format("{} -> Reference '{}' is not a valid hexadecimal number", name, maskRef.dotPath());
    const auto failureTrace4 =
        fmt::format("{} -> Reference '{}' values is out of range 0-0xFFFFFFFFFFFFFFFF", name, maskRef.dotPath());

    // Function that retrieves the mask from the event
    auto getMaskFn = [maskRef = maskRef.jsonPath(), failureTrace1, failureTrace2, failureTrace3, failureTrace4](
                         const base::Event& event) -> base::RespOrError<uint64_t>
    {
        if (!event->exists(maskRef))
        {
            return base::Error {failureTrace1};
        }

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
        // Get mask in hex
        uint64_t mask {};
        {
            auto resultMask = getMaskFn(event);
            if (base::isError(resultMask))
            {
                RETURN_FAILURE(runState, event, base::getError(resultMask).message)
            }
            mask = base::getResponse(resultMask);
        }

        // Iterate over the bits of the mask
        bool isResultEmpty {true};
        for (uint64_t bitPos = 0; bitPos < std::numeric_limits<uint64_t>::digits; bitPos++)
        {
            auto flag = 0x1ULL << bitPos;
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
            RETURN_FAILURE(runState, event, failureTrace4)
        }

        RETURN_SUCCESS(runState, event, successTrace);
    };
}

TransformBuilder getOpBuilderHelperKVDBDecodeBitmask(std::shared_ptr<IKVDBManager> kvdbManager)
{
    return [kvdbManager](const Reference& targetField,
                         const std::vector<OpArg>& opArgs,
                         const std::shared_ptr<const IBuildCtx>& buildCtx)
    {
        return OpBuilderHelperKVDBDecodeBitmask(targetField, opArgs, buildCtx, kvdbManager);
    };
}

} // namespace builder::builders
