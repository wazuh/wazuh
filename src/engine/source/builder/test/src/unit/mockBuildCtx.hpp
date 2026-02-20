#ifndef _BUILDER_TEST_UNIT_MOCK_BUILDCTX_HPP
#define _BUILDER_TEST_UNIT_MOCK_BUILDCTX_HPP

#include <gmock/gmock.h>

#include "builders/ibuildCtx.hpp"

namespace builder::builders::mocks
{

class MockBuildCtx : public IBuildCtx
{
public:
    using KvdbMap = std::unordered_map<std::string, bool>;

    MOCK_METHOD(std::shared_ptr<IBuildCtx>, clone, (), (const));
    MOCK_METHOD((const defs::IDefinitions&), definitions, (), (const));
    MOCK_METHOD(void, setDefinitions, (const std::shared_ptr<defs::IDefinitions>& definitions), ());
    MOCK_METHOD((const RegistryType&), registry, (), (const));
    MOCK_METHOD(void, setRegistry, (const std::shared_ptr<const RegistryType>& registry), ());
    MOCK_METHOD((const schemf::IValidator&), validator, (), (const));
    MOCK_METHOD(void, setValidator, (const std::shared_ptr<const schemf::IValidator>& validator), ());
    MOCK_METHOD((std::shared_ptr<const schemf::IValidator>), validatorPtr, (), (const));
    MOCK_METHOD((const Context&), context, (), (const));
    MOCK_METHOD((Context&), context, (), ());
    MOCK_METHOD((std::shared_ptr<const RunState>), runState, (), (const));
    MOCK_METHOD((const builder::IAllowedFields&), allowedFields, (), (const));
    MOCK_METHOD(void, setAllowedFields, (const std::shared_ptr<const builder::IAllowedFields>& allowedFields), ());
    MOCK_METHOD((std::shared_ptr<const builder::IAllowedFields>), allowedFieldsPtr, (), (const));
    MOCK_METHOD((std::shared_ptr<cm::store::ICMStoreNSReader>), storeNSReaderPtr, (), (const));
    MOCK_METHOD((const cm::store::ICMStoreNSReader&), getStoreNSReader, (), (const));
    MOCK_METHOD(void, setStoreNSReader, (const std::shared_ptr<cm::store::ICMStoreNSReader> nsReader), ());
    MOCK_METHOD(bool, allowMissingDependencies, (), (const));
    MOCK_METHOD(void, setAllowMissingDependencies, (bool allow), ());
    MOCK_METHOD((std::pair<bool, bool>), isKvdbAvailable, (const std::string& kvdbName), (const));
    MOCK_METHOD(bool, getIndexDiscardedEvents, (), (const));
};

} // namespace builder::builders::mocks

#endif // _BUILDER_TEST_UNIT_MOCK_BUILDCTX_HPP
