#include "opBuilderKVDB.hpp"

#include <string>

#include <fmt/format.h>
#include <json/json.hpp>
#include <kvdb/kvdbManager.hpp>

#include "baseHelper.hpp"
#include "baseTypes.hpp"
#include "syntax.hpp"
#include <utils/stringUtils.hpp>

namespace builder::internals::builders
{

using builder::internals::syntax::REFERENCE_ANCHOR;
using namespace helper::base;

base::Expression KVDBExtract(const std::any& definition,
                             bool merge,
                             std::shared_ptr<KVDBManager> kvdbManager)
{
    // Extract parameters from any
    auto [targetField, name, raw_parameters] =
        helper::base::extractDefinition(definition);
    // Identify references and build JSON pointer paths
    auto parameters {helper::base::processParameters(raw_parameters)};
    // Assert expected number of parameters
    helper::base::checkParametersSize(parameters, 2);
    helper::base::checkParameterType(parameters[0], Parameter::Type::VALUE);
    // Format name for the tracer
    name = helper::base::formatHelperFilterName(name, targetField, parameters);

    // Extract parameters
    const auto dbName = parameters[0].m_value;
    const auto key = parameters[1];

    // Get DB
    // TODO: Fix once KVDB is refactored
    auto kvdb = kvdbManager->getDB(dbName);
    if (!kvdb)
    {
        kvdbManager->addDb(dbName, false);
    }
    kvdb = kvdbManager->getDB(dbName);
    if (!kvdb)
    {
        const auto msg {fmt::format("[{}] DB isn't available for usage", dbName)};
        throw std::runtime_error(std::move(msg));
    }

    // Trace messages
    std::string successTrace = fmt::format("[{}] -> Success", name);
    std::string failureTrace1 =
        fmt::format("[{}] -> Failure: key [{}] not found", name, key.m_value);
    std::string failureTrace2 = fmt::format("[{}] -> Failure", name);
    std::string failureTrace3 = fmt::format("[{}] -> Failure: Target field [{}] not "
                                            "found",
                                            name,
                                            targetField);
    std::string failureTrace4 =
        fmt::format("[{}] -> Failure: Fields type mismatch when merging", name);
    std::string failureTrace5 = fmt::format("[{}] -> Failure: Malformed JSON for key "
                                            "[{}]",
                                            name,
                                            key.m_value);

    // Return Expression
    return base::Term<base::EngineOp>::create(
        name,
        [=, kvdb = std::move(kvdb), targetField = std::move(targetField)](
            base::Event event)
        {
            // Get DB key
            std::string resolvedKey;
            if (Parameter::Type::REFERENCE == key.m_type)
            {
                auto value = event->getString(key.m_value);
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
            std::string dbValue = kvdb->read(resolvedKey);
            if (dbValue.empty())
            {
                return base::result::makeFailure(event, failureTrace2);
            }
            // Create Json and add to event
            else
            {
                // TODO: Maybe add non throw version of this method
                try
                {
                    json::Json value {dbValue.c_str()};
                    if (merge)
                    {
                        // Failure cases on merge
                        if (!event->exists(targetField))
                        {
                            return base::result::makeFailure(event, failureTrace3);
                        }
                        else if (event->type(targetField) != value.type()
                                 || (!value.isObject() && !value.isArray()))
                        {
                            return base::result::makeFailure(event, failureTrace4);
                        }
                        event->merge(value, targetField);
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
            }

            return base::result::makeSuccess(event, successTrace);
        });
}

// <field>: +kvdb_extract/<DB>/<ref_key>
Builder getOpBuilderKVDBExtract(std::shared_ptr<KVDBManager> kvdbManager)
{
    return [kvdbManager](const std::any& definition)
    {
        return KVDBExtract(definition, false, kvdbManager);
    };
}

// <field>: +kvdb_extract_merge/<DB>/<ref_key>
Builder getOpBuilderKVDBExtractMerge(std::shared_ptr<KVDBManager> kvdbManager)
{
    return [kvdbManager](const std::any& definition)
    {
        return KVDBExtract(definition, true, kvdbManager);
    };
}

base::Expression existanceCheck(const std::any& definition,
                                bool checkExist,
                                std::shared_ptr<KVDBManager> kvdbManager)
{

    auto [targetField, name, arguments] = extractDefinition(definition);
    auto parameters = processParameters(arguments);
    checkParametersSize(parameters, 1);
    checkParameterType(parameters[0], Parameter::Type::VALUE);
    name = formatHelperFilterName(targetField, name, parameters);

    const auto dbName = parameters[0].m_value;

    // Get DB
    // TODO: Fix once KVDB is refactored
    auto kvdb = kvdbManager->getDB(dbName);
    if (!kvdb)
    {
        kvdbManager->addDb(dbName, false);
    }
    kvdb = kvdbManager->getDB(dbName);
    if (!kvdb)
    {
        const auto msg {fmt::format("[{}] DB isn't available for usage", dbName)};
        throw std::runtime_error(std::move(msg));
    }

    std::string successTrace = fmt::format("[{}] -> Success", name);
    std::string failureTrace = fmt::format("[{}] -> Failure", name);

    return base::Term<base::EngineOp>::create(
        name,
        [=, kvdb = std::move(kvdb), targetField = std::move(targetField)](
            base::Event event)
        {
            bool found = false;
            try // TODO We are only using try for JSON::get. Is correct to
                // wrap everything?
            {
                auto value = event->getString(targetField);
                if (value.has_value())
                {
                    if (kvdb->hasKey(value.value()))
                    {
                        found = true;
                    }
                }
            }
            catch (std::exception& ex)
            {
                return base::result::makeFailure(event, failureTrace);
            }

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

// <field>: +kvdb_match/<DB>
Builder getOpBuilderKVDBMatch(std::shared_ptr<KVDBManager> kvdbManager)
{
    return [kvdbManager](const std::any& definition)
    {
        return existanceCheck(definition, true, kvdbManager);
    };
}

// <field>: +kvdb_not_match/<DB>
Builder getOpBuilderKVDBNotMatch(std::shared_ptr<KVDBManager> kvdbManager)
{
    return [kvdbManager](const std::any& definition)
    {
        return existanceCheck(definition, false, kvdbManager);
    };
}
} // namespace builder::internals::builders
