#ifndef _ROUTER2_MOCK_BUILDER_HPP
#define _ROUTER2_MOCK_BUILDER_HPP

#include <gmock/gmock.h>

#include "ibuilder.hpp"

namespace router
{
class MockBuilder : public router::IBuilder
{
public:
    MOCK_METHOD((base::RespOrError<std::shared_ptr<builder::IPolicy>>), buildPolicy, (const base::Name&), (const, override));
    MOCK_METHOD((base::RespOrError<base::Expression>), buildAsset, (const base::Name&), (const, override));
};
}

#endif // _ROUTER2_MOCK_BUILDER_HPP
