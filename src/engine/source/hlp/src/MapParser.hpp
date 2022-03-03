#ifndef _MAP_PARSER_H
#define _MAP_PARSER_H

#include <string>
#include <vector>
#include "hlpDetails.hpp"
#include <hlp/hlp.hpp>

ParserFn MapParser(std::string field_name, char endToken, std::string const& captureOpts);

#endif