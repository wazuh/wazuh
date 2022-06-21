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

constexpr char REFERENCE_ANCHOR {'$'};
constexpr char FUNCTION_HELPER_ANCHOR {'+'};
constexpr char FUNCTION_HELPER_ARG_ANCHOR {'/'};

} // namespace builder::internals::syntax

#endif // _SYNTAX_H
