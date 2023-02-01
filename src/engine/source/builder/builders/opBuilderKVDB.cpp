#include "opBuilderKVDB.hpp"

#include <string>
#include <variant>

#include <fmt/format.h>

#include <json/json.hpp>
#include <kvdb/kvdbManager.hpp>
#include <utils/stringUtils.hpp>

#include "baseHelper.hpp"
#include "baseTypes.hpp"
#include "syntax.hpp"

namespace builder::internals::builders
{

using builder::internals::syntax::REFERENCE_ANCHOR;
using namespace helper::base;

base::Expression KVDBGet(const std::any& definition, bool merge, std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    // Extract parameters from any
    auto [targetField, name, raw_parameters] = extractDefinition(definition);
    // Identify references and build JSON pointer paths
    const auto parameters {processParameters(name, raw_parameters)};

    // Assert expected number of parameters
    checkParametersSize(name, parameters, 2);
    checkParameterType(name, parameters[0], Parameter::Type::VALUE);

    // Format name for the tracer
    name = formatHelperName(name, targetField, parameters);

    // Extract parameters
    const auto dbName = parameters[0].m_value;
    const auto key = parameters[1];

    auto result = kvdbManager->getHandler(dbName);
    if (std::holds_alternative<base::Error>(result))
    {
        throw std::runtime_error(fmt::format("Engine KVDB builder: {}.", std::get<base::Error>(result).message));
    }

    // Trace messages
    const std::string successTrace {fmt::format("[{}] -> Success", name)};
    const std::string failureTrace1 = fmt::format("[{}] -> Failure: reference '{}' not found", name, key.m_value);
    const std::string failureTrace2 =
        fmt::format("[{}] -> Failure: key '{}' could not be found on database '{}'", name, key.m_value, dbName);
    const std::string failureTrace3 = fmt::format("[{}] -> Failure: Target field '{}' not found", name, targetField);
    const std::string failureTrace4 = fmt::format("[{}] -> Failure: fields type mismatch when merging", name);
    const std::string failureTrace5 = fmt::format("[{}] -> Failure: malformed JSON for key '{}'", name, key.m_value);

    // Return Expression
    return base::Term<base::EngineOp>::create(
        name,
        [=, kvdb = std::get<kvdb_manager::KVDBHandle>(result), targetField = std::move(targetField)](base::Event event)
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

            // Get value from the DB
            auto result = kvdb->read(resolvedKey);
            if (std::holds_alternative<base::Error>(result))
            {
                return base::result::makeFailure(event, failureTrace2);
            }
            try
            {
                json::Json value {std::get<std::string>(result).c_str()};
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
Builder getOpBuilderKVDBGet(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](const std::any& definition)
    {
        return KVDBGet(definition, false, kvdbManager);
    };
}

// <field>: +kvdb_get_merge/<DB>/<ref_key>
Builder getOpBuilderKVDBGetMerge(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](const std::any& definition)
    {
        return KVDBGet(definition, true, kvdbManager);
    };
}

// TODO: documentation and tests of this method are missing
base::Expression
existanceCheck(const std::any& definition, bool checkExist, std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    auto [targetField, name, arguments] = extractDefinition(definition);
    const auto parameters = processParameters(name, arguments);
    checkParametersSize(name, parameters, 1);
    checkParameterType(name, parameters[0], Parameter::Type::VALUE);
    name = formatHelperName(targetField, name, parameters);

    const auto dbName = parameters[0].m_value;

    // Get DB
    // TODO: Fix once KVDB is refactored
    const auto result = kvdbManager->getHandler(dbName);
    if (std::holds_alternative<base::Error>(result))
    {
        throw std::runtime_error(fmt::format("Engine KVDB builder: {}.", std::get<base::Error>(result).message));
    }

    const std::string successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace {
        fmt::format("[{}] -> Failure: Target field '{}' does not exist or it is not a string", name, targetField)};

    return base::Term<base::EngineOp>::create(
        name,
        [=, kvdb = std::get<kvdb_manager::KVDBHandle>(result), targetField = std::move(targetField)](base::Event event)
        {
            bool found = false;
            try // TODO We are only using try for JSON::get. Is correct to
                // wrap everything?
            {
                const auto value = event->getString(targetField);
                if (value.has_value())
                {
                    if (kvdb->hasKey(value.value()))
                    {
                        found = true;
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
Builder getOpBuilderKVDBMatch(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](const std::any& definition)
    {
        return existanceCheck(definition, true, kvdbManager);
    };
}

// TODO: tests for this method are missing
// <field>: +kvdb_not_match/<DB>
Builder getOpBuilderKVDBNotMatch(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](const std::any& definition)
    {
        return existanceCheck(definition, false, kvdbManager);
    };
}

base::Expression KVDBSet(const std::any& definition, std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    auto [targetField, name, arguments] = extractDefinition(definition);
    const auto parameters = processParameters(name, arguments);

    checkParametersSize(name, parameters, 3);
    checkParameterType(name, parameters[0], Parameter::Type::VALUE);

    name = formatHelperName(targetField, name, parameters);

    auto dbName = parameters[0].m_value;
    const auto key = parameters[1];
    const auto value = parameters[2];

    auto result = kvdbManager->getHandler(dbName, true);
    if (std::holds_alternative<base::Error>(result))
    {
        throw std::runtime_error(fmt::format("Engine KVDB builder: {}.", std::get<base::Error>(result).message));
    }

    // Trace messages
    const std::string successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace {fmt::format("[{}] -> Failure: ", name)};
    const std::string failureTrace1 {fmt::format("[{}] -> Failure: reference '{}' not found", name, dbName)};
    const std::string failureTrace2 {fmt::format("[{}] -> Failure: reference '{}' not found", name, key.m_value)};
    const std::string failureTrace3 {fmt::format("[{}] -> Failure: reference '{}' not found", name, value.m_value)};
    const std::string failureTrace4 {fmt::format("[{}] -> ", name) + "Failure: Database '{}' could not be loaded: {}"};

    // Return Expression
    return base::Term<base::EngineOp>::create(
        name,
        [=,
         kvdb = std::get<kvdb_manager::KVDBHandle>(result),
         dbName = std::move(dbName),
         targetField = std::move(targetField)](base::Event event)
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

            // TODO: use a secure kvdb handler method to write the K-V instead of writing it through the kvdb manager
            std::optional<base::Error> err;
            if (isValueRef)
            {
                err = kvdbManager->writeKey(dbName, resolvedKey, resolvedJsonValue);
            }
            else
            {
                err = kvdbManager->writeKey(dbName, resolvedKey, resolvedStrValue);
            }
            if (err)
            {
                return base::result::makeFailure(
                    event,
                    failureTrace
                        + fmt::format("Failure: Key '{}' and value '{}' could not be written to database '{}': {}",
                                      resolvedKey,
                                      resolvedStrValue,
                                      dbName,
                                      err.value().message));
            }

            event->setBool(true, targetField);

            return base::result::makeSuccess(event, successTrace);
        });
}

// TODO: some tests for this method are missing
// <field>: +kvdb_set/<db>/<field>/<value>
Builder getOpBuilderKVDBSet(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](const std::any& definition)
    {
        return KVDBSet(definition, kvdbManager);
    };
}

base::Expression KVDBDelete(const std::any& definition, std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    auto [targetField, name, arguments] = extractDefinition(definition);
    const auto parameters = processParameters(name, arguments);
    checkParametersSize(name, parameters, 1);
    name = formatHelperName(targetField, name, parameters);

    const auto dbName = parameters[0];

    // Trace messages
    const std::string successTrace {fmt::format("[{}] -> Success", name)};

    const std::string failureTrace {fmt::format("[{}] -> Failure: ", name)};
    const std::string failureTrace1 {fmt::format("[{}] -> Failure: reference '{}' not found", name, dbName.m_value)};

    // Return Expression
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField)](base::Event event)
        {
            event->setBool(false, targetField);

            // Get DB name
            std::string resolvedDBName;
            if (Parameter::Type::REFERENCE == dbName.m_type)
            {
                const auto retval = event->getString(dbName.m_value);
                if (retval)
                {
                    resolvedDBName = retval.value();
                }
                else
                {
                    return base::result::makeFailure(event, failureTrace1);
                }
            }
            else
            {
                resolvedDBName = dbName.m_value;
            }

            const auto deleteResult = kvdbManager->deleteDB(resolvedDBName);
            if (deleteResult)
            {
                return base::result::makeFailure(event,
                                                 failureTrace
                                                     + fmt::format("Database '{}' could not be deleted: {}",
                                                                   resolvedDBName,
                                                                   deleteResult.value().message));
            }

            event->setBool(true, targetField);

            return base::result::makeSuccess(event, successTrace);
        });
}

// TODO: some tests for this method are missing
// <field>: +kvdb_delete/<db>
Builder getOpBuilderKVDBDelete(std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager)
{
    return [kvdbManager](const std::any& definition)
    {
        return KVDBDelete(definition, kvdbManager);
    };
}

} // namespace builder::internals::builders
