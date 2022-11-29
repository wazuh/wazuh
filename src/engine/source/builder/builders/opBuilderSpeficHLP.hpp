/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OP_BUILDER_SPECIFIC_HLP_H
#define _OP_BUILDER_SPECIFIC_HLP_H

#include <any>

#include <baseTypes.hpp>

#include "expression.hpp"


//*************************************************
//*         HLP Specific parser Helpers           *
//*************************************************

namespace builder::internals::builders
{

/**
 * @brief Helper function of boolean parser from HLP
 *
 * @param definition Definition of the operation
 * @return base::Expression Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
base::Expression opBuilderSpecificHLPBoolParse(const std::any& definition);

/**
 * @brief Helper function of byte parser from HLP
 *
 * @param definition Definition of the operation
 * @return base::Expression Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
base::Expression opBuilderSpecificHLPByteParse(const std::any& definition);

/**
 * @brief Helper function of long parser from HLP
 *
 * @param definition Definition of the operation
 * @return base::Expression Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
base::Expression opBuilderSpecificHLPLongParse(const std::any& definition);

/**
 * @brief Helper function of float parser from HLP
 *
 * @param definition Definition of the operation
 * @return base::Expression Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
base::Expression opBuilderSpecificHLPFloatParse(const std::any& definition);

/**
 * @brief Helper function of double parser from HLP
 *
 * @param definition Definition of the operation
 * @return base::Expression Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
base::Expression opBuilderSpecificHLPDoubleParse(const std::any& definition);


/**
 * @brief Helper function of base64 parser from HLP
 *
 * @param definition Definition of the operation
 * @return base::Expression Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
base::Expression opBuilderSpecificHLPBase64Parse(const std::any& definition);

/**
 * @brief Helper function of date parser from HLP
 *
 * @param definition Definition of the operation
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPDateParse(const std::any& definition);

/**
 * @brief Helper function of ip parser from HLP
 *
 * @param definition Definition of the operation
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPIPParse(const std::any& definition);

/**
 * @brief Helper function of uri parser from HLP
 *
 * @param definition Definition of the operation
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPURIParse(const std::any& definition);

/**
 * @brief Helper function of user agent parser from HLP
 *
 * @param definition Definition of the operation
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPUserAgentParse(const std::any& definition);

/**
 * @brief Helper function of FQDN parser from HLP
 *
 * @param definition Definition of the operation
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPFQDNParse(const std::any& definition);

/**
 * @brief Helper function of file path parser from HLP
 *
 * @param definition Definition of the operation
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPFilePathParse(const std::any& definition);

/**
 * @brief Helper function of json parser from HLP
 *
 * @param definition Definition of the operation
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPJSONParse(const std::any& definition);

/**
 * @brief Helper function of xml parser from HLP
 *
 * @param definition Definition of the operation
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPXMLParse(const std::any& definition);

/**
 * @brief Helper function of csv parser from HLP
 *
 * @param definition Definition of the operation
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPCSVParse(const std::any& definition);

/**
 * @brief Helper function of key value parser from HLP
 *
 * @param definition Definition of the operation
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPKeyValueParse(const std::any& definition);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_SPECIFIC_HLP_H
