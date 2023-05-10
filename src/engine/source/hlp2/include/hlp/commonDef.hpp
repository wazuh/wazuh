#ifndef HLP_COMMON_DEF_HPP
#define HLP_COMMON_DEF_HPP

#include <deque>
#include <functional>
#include <list>
#include <string>

#include <json/json.hpp>

namespace hlp
{

/*****************************************************************************************
 * Common definitions for the HLP parser and specific parsers
 *****************************************************************************************/
using jFnList = std::deque<std::function<void(json::Json&)>>; ///< List of functions, as result of parsing to apply to
                                                              ///< the Json object
using Stop = std::deque<std::string>;                          ///< List of strings to stop parsing
using Options = std::vector<std::string>;                     ///< List of arguments to configure the parser

// Parser builder parameters

/**
 * @brief Parser builder parameters
 *
 * Specifies the parameters to build a specific parser of logpar
 */
struct ParserSpec
{
    std::string m_name; ///< Name of the parser
    std::string m_path; ///< Path destination field of the Json object
    Stop m_endTokens;   ///< List of strings to stop parsing
    Options m_args;     ///< List of arguments to configure the parser
    bool m_capture;     ///< Indicates if the parser captures the result of parsing

    ParserSpec() = default;
};

} // namespace hlp

#endif // HLP_COMMON_DEF_HPP
