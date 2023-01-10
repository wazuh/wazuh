#include "stageDestination.hpp"

#include <any>

#include <baseTypes.hpp>
#include <expression.hpp>
#include <json/json.hpp>


namespace builder::internals::builders
{
Builder getStageDestinationBuilder(std::shared_ptr<Registry> registry)
{
    return [registry](const std::any& definition)
    {
        json::Json jsonDefinition;

        // Check definition
        try {
            jsonDefinition = std::any_cast<json::Json>(definition);
        } catch (std::exception& e) {
            throw std::runtime_error(fmt::format(
                "Destination stage: Definition could not be converted to json: {}", e.what()));
        }

        if (!jsonDefinition.isString())
        {
            throw std::runtime_error(fmt::format("Destination stage: Invalid json definition type, expected 'string' "
                                                 "but got '{}'",
                                                 jsonDefinition.typeName()));
        }

        // Build
        auto destination = jsonDefinition.getString().value();

        auto op =  base::Term<base::EngineOp>::create(
        "traceName",[=](base::Event event) -> base::result::Result<base::Event>
        {
            // Dummy implentation
            const auto hasTestRoute = event->getBool(json::Json::formatJsonPath("~test_route"));
            if (!hasTestRoute.has_value()  || hasTestRoute.value())
            {
                return base::result::makeFailure(
                    event,
                    "Destination stage: Could not get test route from event");
            }
            return base::result::makeSuccess(event, "exito! /~test_route");
        });
        return base::Chain::create("stage.destination", {op});
    };
}
} // namespace builder::internals::builders
