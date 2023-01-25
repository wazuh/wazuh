#include "routerAuxiliarFunctions.hpp"
#include <register.hpp>
#include <store/drivers/fileDriver.hpp>
#include <builders/baseHelper.hpp>

namespace aux
{

namespace
{

base::Expression coutOutputHelper_test(const std::any& definition)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    const auto parameters = helper::base::processParameters(name, rawParameters);

    name = helper::base::formatHelperName(name, targetField, parameters);
    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=, targetField = std::move(targetField), parameter = std::move(parameters)](
            base::Event event) -> base::result::Result<base::Event>
        {
            std::cout << "Dummy output: " << event->str() << std::endl;
            event->setString("dummyBypass", targetField);
            return base::result::makeSuccess(event, "Ok from dummy output");
        });
}
} // namespace

std::shared_ptr<builder::Builder> getFakeBuilder()
{

    auto store = std::make_shared<store::FileDriver>(STORE_PATH_TEST);

    auto registry = std::make_shared<builder::internals::Registry>();
    builder::internals::registerBuilders(registry, {0});

    registry->registerBuilder(coutOutputHelper_test, "helper.coutOutputHelper_test");

    auto builder = std::make_shared<builder::Builder>(store, registry);

    return builder;
};


base::Event createFakeMessage(std::optional<std::string> msgOpt)
{

    auto msgStr = msgOpt.value_or("1:127.0.0.1:Fake message");

    return base::parseEvent::parseOssecEvent(msgStr);
}

} // namespace aux
