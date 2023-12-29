#ifndef _BUILDER_TEST_UNIT_MOCK_BUILDCTX_HPP
#define _BUILDER_TEST_UNIT_MOCK_BUILDCTX_HPP

#include <gmock/gmock.h>

#include "builders/ibuildCtx.hpp"

namespace builder::builders::mocks
{

class MockBuildCtx : public IBuildCtx
{
    MOCK_METHOD(std::shared_ptr<IBuildCtx>, clone, (), (const));
    MOCK_METHOD((const defs::IDefinitions&), definitions, (), (const));
    MOCK_METHOD(void, setDefinitions, (const std::shared_ptr<defs::IDefinitions>& definitions), ());
    MOCK_METHOD((const RegistryType&), registry, (), (const));
    MOCK_METHOD(void, setRegistry, (const std::shared_ptr<const RegistryType>& registry), ());
    MOCK_METHOD((const schemval::IValidator&), validator, (), (const));
    MOCK_METHOD(void, setValidator, (const std::shared_ptr<const schemval::IValidator>& validator), ());
    MOCK_METHOD((const schemf::ISchema&), schema, (), (const));
    MOCK_METHOD((std::shared_ptr<const schemf::ISchema>), schemaPtr, (), (const));
    MOCK_METHOD(void, setSchema, (const std::shared_ptr<const schemf::ISchema>& schema), ());
    MOCK_METHOD((const Context&), context, (), (const));
    MOCK_METHOD((Context&), context, (), ());
    MOCK_METHOD((std::shared_ptr<const RunState>), runState, (), (const));
};

} // namespace builder::builders::mocks

#endif // _BUILDER_TEST_UNIT_MOCK_BUILDCTX_HPP
