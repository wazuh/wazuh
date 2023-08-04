#ifndef _ROUTER_AUX_FUNCTIONS_H
#define _ROUTER_AUX_FUNCTIONS_H

#include <vector>

#include <builders/baseHelper.hpp>
#include <defs/idefinitions.hpp>
#include <parseEvent.hpp>
#include <queue/concurrentQueue.hpp>
#include <schemf/emptySchema.hpp>
#include <store/mockStore.hpp>

#include "utils/stringUtils.hpp"
#include <builder.hpp>
#include <register.hpp>
#include <registry.hpp>

#include "fakeAssets.hpp"
#include <mocks/fakeMetric.hpp>

using namespace store::mocks;

inline base::Expression coutOutputHelper_test(const std::string& targetField,
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

class MockDeps
{
protected:
    std::shared_ptr<MockStore> m_store;
    std::shared_ptr<builder::Builder> m_builder;
    std::shared_ptr<builder::internals::Registry<builder::internals::Builder>> m_registry;
    std::shared_ptr<builder::internals::Registry<builder::internals::HelperBuilder>> m_helperRegistry;

    void init()
    {
        m_store = std::make_shared<MockStore>();
        m_registry = std::make_shared<builder::internals::Registry<builder::internals::Builder>>();
        m_helperRegistry = std::make_shared<builder::internals::Registry<builder::internals::HelperBuilder>>();

        builder::internals::dependencies dependencies;
        dependencies.helperRegistry = m_helperRegistry;
        dependencies.logparDebugLvl = 0;
        dependencies.schema = schemf::mocks::EmptySchema::create();
        builder::internals::registerHelperBuilders(m_helperRegistry);
        builder::internals::registerBuilders(m_registry, dependencies);

        m_helperRegistry->registerBuilder(coutOutputHelper_test, "coutOutputHelper_test");

        m_builder = std::make_shared<builder::Builder>(m_store, m_registry);
    }

    void expectBuild(const std::string& name, int times = 1)
    {
        if (aux::assets.find(name) == aux::assets.end())
        {
            FAIL() << "Asset " << name << " not found";
        }

        EXPECT_CALL(*m_store, get(base::Name(name)))
            .Times(times)
            .WillRepeatedly(::testing::Return(getSuccess(json::Json(aux::assets[name]))));
    }

    void expectBuildPolicy(const std::string& name, int times = 1)
    {
        if (aux::policies.find(name) == aux::policies.end())
        {
            FAIL() << "Policy " << name << " not found";
        }
        auto assets = aux::policies[name];
        for (const auto& asset : assets)
        {
            expectBuild(asset, times);
        }
    }

    void expectBuildTable(const std::string& name)
    {
        if (aux::tables.find(name) == aux::tables.end())
        {
            FAIL() << "Table " << name << " not found";
        }
        const auto& [filters, policies] = aux::tables[name];
        for (const auto& filter : filters)
        {
            expectBuild(filter);
        }
        for (const auto& policy : policies)
        {
            expectBuildPolicy(policy);
        }
    }
};

namespace aux
{
const std::vector<std::string> sampleEventsStr {
    R"(2:10.0.0.1:Test Event - deco_1 )", R"(4:10.0.0.1:Test Event - deco_2 )", R"(8:10.0.0.1:Test Event - deco_3 )"};

inline base::Event createFakeMessage(std::optional<std::string> msgOpt = std::nullopt)
{
    auto msgStr = msgOpt.value_or("1:127.0.0.1:Fake message");

    return base::parseEvent::parseWazuhEvent(msgStr);
}

struct testQueue
{
    std::shared_ptr<base::queue::ConcurrentQueue<base::Event>> m_eventQueue;

    std::shared_ptr<base::queue::ConcurrentQueue<base::Event>> getQueue()
    {
        if (m_eventQueue == nullptr)
        {
            m_eventQueue = std::make_shared<base::queue::ConcurrentQueue<base::Event>>(
                100, std::make_shared<FakeMetricScope>(), std::make_shared<FakeMetricScope>());
        }
        return m_eventQueue;
    }

    void pushEvent(const base::Event& event)
    {
        auto e = event;
        getQueue()->push(std::move(e));
    }
};

} // namespace aux

#endif // _ROUTER_AUX_FUNCTIONS_H
