#ifndef _SCHEMVAL_MOCKVALIDATOR_HPP
#define _SCHEMVAL_MOCKVALIDATOR_HPP

#include <gmock/gmock.h>

#include <schemval/ivalidator.hpp>

namespace schemval::mocks
{

class MockValidator : public IValidator
{
public:
    MOCK_METHOD(const hlp::ParserBuilder&, getParser, (schemf::Type), (const, override));
    MOCK_METHOD(json::Json::Type, getJsonType, (schemf::Type), (const, override));
};

} // namespace schemval::mocks

#endif // _SCHEMVAL_MOCKVALIDATOR_HPP
