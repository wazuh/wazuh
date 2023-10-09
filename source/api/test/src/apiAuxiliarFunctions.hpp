#ifndef _API_AUXILIAR_FUNCTIONS_H
#define _API_AUXILIAR_FUNCTIONS_H

#include <netinet/in.h>
#include <string>
#include <random>
#include <vector>

#include <builder.hpp>
#include <builders/baseHelper.hpp>
#include <logging/logging.hpp>
#include <register.hpp>
#include <registry.hpp>
#include <schemf/emptySchema.hpp>
#include <store/mockStore.hpp>

void inline initLogging(void)
{
    static bool initialized = false;

    if (!initialized)
    {
        // Logging setup
        logging::LoggingConfig logConfig;
        logConfig.logLevel = "off";
        logConfig.filePath = "";
        logging::loggingInit(logConfig);
        initialized = true;
    }
}

std::string inline getRandomNumber(unsigned int length)
{
    const std::string digits = "0123456789";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<int> distribution(0, digits.size() - 1);

    std::string randomNumber;
    for (unsigned int i = 0; i < length; ++i)
    {
        randomNumber += digits[distribution(generator)];
    }

    return randomNumber;
}

std::string inline generateRandomStringWithPrefix(const unsigned int length, const std::string& prefix)
{
    std::string randomNumber = getRandomNumber(length);
    return prefix + randomNumber;
}

// TODO: Remove this when the builder mock is implemented
base::Expression inline coutOutputHelper(const std::string& targetField,
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

std::shared_ptr<builder::Builder> inline fakeBuilder(std::shared_ptr<store::mocks::MockStore> store)
{
    auto registry = std::make_shared<builder::internals::Registry<builder::internals::Builder>>();
    auto helperRegistry = std::make_shared<builder::internals::Registry<builder::internals::HelperBuilder>>();
    builder::internals::dependencies dependencies;
    dependencies.helperRegistry = helperRegistry;
    dependencies.logparDebugLvl = 0;
    dependencies.schema = schemf::mocks::EmptySchema::create();
    builder::internals::registerHelperBuilders(helperRegistry, dependencies);
    builder::internals::registerBuilders(registry, dependencies);

    helperRegistry->registerBuilder(coutOutputHelper, "coutOutputHelper_test");

    auto builder = std::make_shared<builder::Builder>(store, registry);

    return builder;
};

#endif // _API_AUXILIAR_FUNCTIONS_H
