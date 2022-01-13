#ifndef _SYNTAX_H
#define _SYNTAX_H

#include <string>

/**
 * @brief Defines syntax elements.
 *
 * This namespace contains all anchors and syntax elements that identify
 * different objects.
 */
namespace builder::internals::syntax {

const std::string REFERENCE_ANCHOR("$");
const std::string HELPER_ANCHOR("+");
const std::string HELPER_ARG_ANCHOR("/");

} // namespace builder::internals::syntax

#endif // _SYNTAX_H
