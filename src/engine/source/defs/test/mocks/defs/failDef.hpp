#include <defs/idefinitions.hpp>

namespace defs::mocks
{
class FailDef : public IDefinitions
{
public:
    FailDef() = default;
    ~FailDef() = default;

    json::Json get(std::string_view name) const override { throw std::runtime_error("FailDef::get() called"); }
    bool contains(std::string_view name) const override { return false; }
    std::string replace(std::string_view input) const override { return std::string(input); }
};
} // namespace defs::mocks
