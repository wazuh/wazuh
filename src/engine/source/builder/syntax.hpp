#ifndef _SYNTAX_H
#define _SYNTAX_H

#include <string>

/**
 * @brief Defines syntax elements.
 *
 * This namespace contains all anchors and syntax elements that identify
 * different objects.
 */
namespace builder::internals::syntax
{

const int REFERENCE_ANCHOR('$');
const int FUNCTION_HELPER_ANCHOR('+');

} // namespace builder::internals::syntax

#endif // _SYNTAX_H
