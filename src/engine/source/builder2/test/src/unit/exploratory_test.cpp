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

#define RETURN_FAILURE(runState, event, traceMsg)                                                                      \
    if ((runState)->trace)                                                                                             \
    {                                                                                                                  \
        return base::result::makeFailure(event, traceMsg);                                                             \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        return base::result::makeFailure(event);                                                                       \
    }

#define RETURN_SUCCESS(runState, event, traceMsg)                                                                      \
    if ((runState)->trace)                                                                                             \
    {                                                                                                                  \
        return base::result::makeSuccess(event, traceMsg);                                                             \
    }                                                                                                                  \
    else                                                                                                               \
    {                                                                                                                  \
        return base::result::makeSuccess(event);                                                                       \
    }

#define SANDBOX(runState, code)                                                                                        \
    if (!(runState)->sandbox)                                                                                          \
    {                                                                                                                  \
        code;                                                                                                          \
    }

// Example of a builder
base::EngineOp map(const std::string& targetField,
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
    // auto runtimeValidator = schema->getRuntimeValidator(targetField);

    // Do build things ...
    // We can now obtain the same handler for the entire asset using the buildCtx

    // The actual operation
    return [parameters, runState](const base::Event& event)
    {
        if (false) // Fake error condition
        {
            RETURN_FAILURE(runState, event, "trace");
            // if (runState->trace)
            // {
            //     return base::result::makeFailure(
            //         event, fmt::format("Complex error message that does not impact when trace is not enabled"));
            // }

            // return base::result::makeFailure(event, "traza");
        }

        // When testing do not perform collateral effects
        SANDBOX(runState, auto code = "collateral effect code")
        // if (!runState->sandbox)
        // {
        //     // Do something
        // }

        // If runtime checking is enabled, validate the event
        // CHECK(state, value) <- Do a macro for this
        if (runState->check)
        {
            json::Json fakeValue;
            // auto error = runtimeValidator(fakeValue);
            // if (error)
            // {
            //     if (runState->trace)
            //     {
            //         return base::result::makeFailure(event, fmt::format("Complex error message"));
            //     }

            //     return base::result::makeFailure(event);
            // }
        }

        if (runState->trace)
        {
            return base::result::makeSuccess(event, fmt::format("Complex success message"));
        }

        return base::result::makeSuccess(event);
    };
}

// Passing functions from wrapper and commposition
// Cons
// Necesita que el builder llame a las funciones, tienen que estar en la definicion
// del builder. Añadir o quitar estas funciones implica cambiar todos los builders

//
namespace one
{
using Op = std::function<int(int)>;
using BuildTypeCheck = std::function<void(int)>;
using Builder = std::function<Op(std::string, BuildTypeCheck)>;

Op addOne(
    std::string target, BuildTypeCheck buildCheck = [](int) {})
{
    buildCheck(1);
    return [](int x)
    {
        return x + 1;
    };
}

Op buildCheckWrapper(Builder builder)
{
    BuildTypeCheck buildCheck = [](int x)
    {
        return;
    };

    return builder("target", buildCheck);
}

} // namespace one

namespace two
{
using Op = base::EngineOp;

struct Builder
{
private:
    base::EngineOp op;

public:
    virtual ~Builder() = default;
    virtual std::optional<json::Json::Type> buildType() const = 0;

};

} // namespace two
TEST(Test, test) {}
