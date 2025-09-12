#ifndef _BUILDER_TEST_UNIT_POLICY_MOCKASSETBUILDER_HPP
#define _BUILDER_TEST_UNIT_POLICY_MOCKASSETBUILDER_HPP

#include <gmock/gmock.h>

#include "policy/iassetBuilder.hpp"

namespace builder::policy::mocks
{

class MockAssetBuilder : public IAssetBuilder
{
public:
    MOCK_METHOD(Asset, CallableOp, (const store::Doc& document), (const));

    virtual Asset operator()(const store::Doc& document) const override { return CallableOp(document); }
};

} // namespace builder::policy::mocks

#endif // _BUILDER_TEST_UNIT_POLICY_MOCKASSETBUILDER_HPP
