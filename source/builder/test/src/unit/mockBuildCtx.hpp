#ifndef _BUILDER_TEST_UNIT_MOCK_BUILDCTX_HPP
#define _BUILDER_TEST_UNIT_MOCK_BUILDCTX_HPP

#include <gmock/gmock.h>

#include "builders/ibuildCtx.hpp"

namespace builder::builders::mocks
{

class MockBuildCtx : public IBuildCtx
{
public:
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
};

} // namespace builder::builders::mocks

#endif // _BUILDER_TEST_UNIT_MOCK_BUILDCTX_HPP
