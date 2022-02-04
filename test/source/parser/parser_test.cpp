#include "tao/pegtl.hpp"
#include "gtest/gtest.h"

/**
 *
 * A LogQL expression is a sequence of fields and anchors. Each field is enclosed in <>.
 *
 * A field is an alphanumeric identifier which optionally can be followed by a sequence of /identifier.
 *
 * An anchor is anything outside the enclosing <>.
 *
 * A LogQL expression describes a parser which must be built to parse a string into fields.
 *
 */
namespace logql {
using namespace tao::pegtl;

struct field : seq<one<'<'>, seq<alnum>, one<'>'>> {};
struct anchor : seq<sor<ascii::not_one<'<'>, ascii::not_one<'>'>>> {};
struct grammar : seq<sor<field, anchor>> {};

template< typename Rule >
struct action
   : tao::pegtl::nothing< Rule > {};

template<>
struct action<grammar>
{
    template <typename ActionInput>
    static void apply(const ActionInput& in, std::vector<std::string>& out)
    {
        out.push_back(in,string());
    }
};

} // namespace logql

// returns true if the input string is a valid logql expression, and false otherwise
bool logql_matcher(std::string in) {
    auto fields = new std::vector<std::string>();
    if (tao::pegtl::parse<logql::grammar, logql::action>(in, fields)) {
        return true;
    }
    return false;
}

TEST(Parser, LogQL) {

    ASSERT_TRUE(logql_matcher("<field1> anchor1 <field2>"));
}
