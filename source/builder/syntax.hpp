#ifndef _SYNTAX_H
#define _SYNTAX_H

/**
 * @brief Defines syntax elements.
 *
 * This namespace contains all anchors and syntax elements that identify
 * different objects.
 */
namespace builder::internals::syntax
{

constexpr auto REFERENCE_ANCHOR {'$'};
constexpr auto FUNCTION_HELPER_ARG_ANCHOR {','};
constexpr auto FUNCTION_HELPER_DEFAULT_ESCAPE {'\\'};
constexpr auto JSON_PATH_SEPARATOR {'.'};
constexpr auto CUSTOM_FIELD_ANCHOR {'~'};
constexpr auto VARIABLE_ANCHOR {'_'};
constexpr auto FIELD_EXTENDED = "_@#";
constexpr auto HELPER_NAME_EXTENDED = "_";
constexpr auto PARENTHESIS_OPEN = '(';
constexpr auto PARENTHESIS_CLOSE = ')';

} // namespace builder::internals::syntax

#endif // _SYNTAX_H
