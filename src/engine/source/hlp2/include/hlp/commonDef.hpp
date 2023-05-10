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



/**
 * @brief Parser builder parameters
 *
 * Specifies the parameters to build a specific parser of logpar
 */
class ParserSpec
{
private:
    std::string m_name; ///< Name of the parser
    std::string m_path; ///< Path destination field of the Json object
    Stop m_endTokens;   ///< List of strings to stop parsing
    Options m_args;     ///< List of arguments to configure the parser
    bool m_capture;     ///< Indicates if the parser captures the result of parsing

public:
    ParserSpec() : m_name(""), m_path(""), m_endTokens(), m_args(), m_capture(false) {}

    /**
     * @brief Construct a new Parser Spec object
     *
     * @param name Name of the parser
     * @param tarjetField Path destination field of the Json object
     * @param endTokens List of strings to stop parsing
     * @param args List of arguments to configure the parser
     * @param capture Indicates if the parser captures the result of parsing
     */
    ParserSpec(const std::string& name,
               const std::string& tarjetField,
               const Stop& endTokens,
               const Options& args,
               bool capture = true)
        : m_name(name)
        , m_path(tarjetField)
        , m_endTokens(endTokens)
        , m_args(args)
        , m_capture(capture)
    {
    }

    // Getters
    const std::string& name() const { return m_name; }
    const std::string& targetField() const { return m_path; }
    const Stop& endTokens() const { return m_endTokens; }
    const Options& args() const { return m_args; }
    bool capture() const { return m_capture; }

    // Setters
    ParserSpec& name(const std::string& name)
    {
        m_name = name;
        return *this;
    }
    ParserSpec& path(const std::string& path)
    {
        m_path = path;
        return *this;
    }
    ParserSpec& endTokens(const Stop& endTokens)
    {
        m_endTokens = endTokens;
        return *this;
    }
    ParserSpec& args(const Options& args)
    {
        m_args = args;
        return *this;
    }
    ParserSpec& capture(bool capture)
    {
        m_capture = capture;
        return *this;
    }
};

} // namespace hlp

#endif // HLP_COMMON_DEF_HPP
