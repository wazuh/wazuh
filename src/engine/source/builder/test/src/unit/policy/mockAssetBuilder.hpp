#ifndef _BUILDER_TEST_UNIT_POLICY_MOCKASSETBUILDER_HPP
#define _BUILDER_TEST_UNIT_POLICY_MOCKASSETBUILDER_HPP

#include <gmock/gmock.h>

#include "policy/iassetBuilder.hpp"

namespace builder::policy::mocks
{

class MockAssetBuilder : public IAssetBuilder
{
public:
    MOCK_METHOD(Asset, CallableOp, (const json::Json& document), (const));
    MOCK_METHOD(builder::builders::Context&, getContext, (), (const));

    virtual Asset operator()(const json::Json& document) const override { return CallableOp(document); }
};

} // namespace builder::policy::mocks

#endif // _BUILDER_TEST_UNIT_POLICY_MOCKASSETBUILDER_HPP
