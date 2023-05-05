#include "routerAuxiliarFunctions.hpp"
#include <builders/baseHelper.hpp>
#include <register.hpp>
#include <router/router.hpp>
#include <store/drivers/fileDriver.hpp>
#include <defs/idefinitions.hpp>
namespace aux
{

namespace
{

base::Expression coutOutputHelper_test(const std::string& targetField,
                                       const std::string& rawName,
                                       const std::vector<std::string>& rawParameters,
                                       std::shared_ptr<defs::IDefinitions> definitions)
{
    const auto parameters = helper::base::processParameters(rawName, rawParameters, definitions);

    const auto name = helper::base::formatHelperName(rawName, targetField, parameters);
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

    auto registry = std::make_shared<builder::internals::Registry<builder::internals::Builder>>();
    auto helperRegistry = std::make_shared<builder::internals::Registry<builder::internals::HelperBuilder>>();
    builder::internals::dependencies dependencies;
    dependencies.helperRegistry = helperRegistry;
    dependencies.logparDebugLvl = 0;
    builder::internals::registerHelperBuilders(helperRegistry);
    builder::internals::registerBuilders(registry, dependencies);

    helperRegistry->registerBuilder(coutOutputHelper_test, "coutOutputHelper_test");

    auto builder = std::make_shared<builder::Builder>(store, registry);

    return builder;
};

base::Event createFakeMessage(std::optional<std::string> msgOpt)
{

    auto msgStr = msgOpt.value_or("1:127.0.0.1:Fake message");

    return base::parseEvent::parseOssecEvent(msgStr);
}

std::shared_ptr<store::IStore> getFakeStore()
{
    auto store = std::make_shared<store::FileDriver>(STORE_PATH_TEST);
    // Clean internal store
    store->del(router::ROUTES_TABLE_NAME);
    return store;
}
} // namespace aux
