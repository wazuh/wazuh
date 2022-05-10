#include "testUtils.hpp"

#include "_builder/connectable.hpp"
#include "_builder/rxcppBackend/rxcppFactory.hpp"

TEST(RxcppFactory, test)
{
    // Fabricated connectable graph
    // Fallible chain of chains
    //         FallibleChain
    //          /   \
    //      chain1  chain2
    //      /          \
    // op1 op2 op3  op4 op5 op6

    auto fallibleConn = builder::internals::ConnectableGroup::create(
        builder::internals::ConnectableGroup::FALLIBLE_CHAIN);
    fallibleConn->m_connectables.push_back(
        builder::internals::ConnectableGroup::create(
            builder::internals::ConnectableGroup::GroupType::CHAIN,
            {builder::internals::ConnectableOperation<Operation>::create(
                 [](Event<Json> event) -> Result<Event<Json>>
                 {
                     GTEST_COUT << "op1: Success" << std::endl;
                     return makeSuccess(std::move(event));
                 }),
             builder::internals::ConnectableOperation<Operation>::create(
                 [](Event<Json> event) -> Result<Event<Json>>
                 {
                     GTEST_COUT << "op2: Success" << std::endl;
                     return makeSuccess(std::move(event));
                 }),
             builder::internals::ConnectableOperation<Operation>::create(
                 [](Event<Json> event) -> Result<Event<Json>>
                 {
                     GTEST_COUT << "op3: Failure" << std::endl;
                     return makeFailure(std::move(event), "Error");
                 })}));
    fallibleConn->m_connectables.push_back(
        builder::internals::ConnectableGroup::create(
            builder::internals::ConnectableGroup::GroupType::CHAIN,
            {builder::internals::ConnectableOperation<Operation>::create(
                 [](Event<Json> event) -> Result<Event<Json>>
                 {
                     GTEST_COUT << "op4: Success" << std::endl;
                     return makeSuccess(std::move(event));
                 }),
             builder::internals::ConnectableOperation<Operation>::create(
                 [](Event<Json> event) -> Result<Event<Json>>
                 {
                     GTEST_COUT << "op5: Failure" << std::endl;
                     return makeFailure(std::move(event), "Error");
                 }),
             builder::internals::ConnectableOperation<Operation>::create(
                 [](Event<Json> event) -> Result<Event<Json>>
                 {
                     GTEST_COUT << "op6: Success" << std::endl;
                     return makeSuccess(std::move(event));
                 })}));

    auto input = rxcpp::observable<>::create<
                     builder::internals::rxcppBackend::RxcppEvent>(
                     [](auto s)
                     {
                         s.on_next(std::make_shared<Result<Event<Json>>>(
                             makeSuccess(Event {Json {}})));
                         s.on_next(std::make_shared<Result<Event<Json>>>(
                             makeSuccess(Event {Json {}})));
                         s.on_next(std::make_shared<Result<Event<Json>>>(
                             makeSuccess(Event {Json {}})));
                         s.on_completed();
                     })
                     .publish();

    auto output =
        builder::internals::rxcppBackend::rxcppFactory(input, fallibleConn);
    output.subscribe([](builder::internals::rxcppBackend::RxcppEvent result)
                     { GTEST_COUT << "Output got" << std::endl; });

    input.connect();
}
