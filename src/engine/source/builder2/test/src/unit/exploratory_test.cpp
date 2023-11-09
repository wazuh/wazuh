#include <gtest/gtest.h>

#include <functional>

#include <fmt/format.h>

#include <baseTypes.hpp>
#include <expression.hpp>
#include <json/json.hpp>

#include <schemf/ischema.hpp>

struct RuntimeState // Atomics?
{
    bool trace;
    bool sandbox;
    bool check;
};

struct BuildContext
{
    std::string assetName;
    std::string policyName;
    std::string stageName;
};

void validateSimple(const std::string& name, std::shared_ptr<schemf::ISchema> schema, json::Json::Type type) {}

void validateFromReference(const std::string& name,
                           std::shared_ptr<schemf::ISchema> schema,
                           const std::string& reference)
{
}

// Example of a builder
base::EngineOp builder(const std::string& targetField,
                       const std::string& name,
                       const std::vector<std::string>& rawParameters,
                       std::shared_ptr<schemf::ISchema> schema,
                       std::shared_ptr<RuntimeState> runState,
                       std::shared_ptr<BuildContext> buildCtx)
{
    // Example simple validation, i.e. this helper maps a number
    validateSimple(name, schema, json::Json::Type::Number);

    // Process parameters
    auto parameters = rawParameters;
    // Assert parameters are valid

    // Example validation depending on reference field
    validateFromReference(name, schema, parameters[0]);

    // Get runtime validator
    auto runtimeValidator = schema->getRuntimeValidator(targetField);

    // Do build things ...
    // We can now obtain the same handler for the entire asset using the buildCtx

    // The actual operation
    return [runtimeValidator, parameters, runState](const base::Event& event)
    {
        if (false) // Fake error condition
        {
            // RETURN_ERROR(state, event, codigo) <- Do a macro for this
            if (runState->trace)
            {
                return base::result::makeFailure(
                    event, fmt::format("Complex error message that does not impact when trace is not enabled"));
            }

            return base::result::makeFailure(event);
        }

        // When testing do not perform collateral effects
        // SANDBOX(state, code) <- Do a macro for this
        if (!runState->sandbox)
        {
            // Do something
        }

        // If runtime checking is enabled, validate the event
        // CHECK(state, value) <- Do a macro for this
        if (runState->check)
        {
            json::Json fakeValue;
            auto error = runtimeValidator(fakeValue);
            if (error)
            {
                if (runState->trace)
                {
                    return base::result::makeFailure(event, fmt::format("Complex error message"));
                }

                return base::result::makeFailure(event);
            }
        }

        if (runState->trace)
        {
            return base::result::makeSuccess(event, fmt::format("Complex success message"));
        }

        return base::result::makeSuccess(event);
    };
}



TEST(Test, test)
{
}
